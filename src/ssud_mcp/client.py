"""Client-side transfers through SSUD's authenticated HTTP API, never local SMB paths."""

import ipaddress
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

CHUNK = 4 * 1024 * 1024


class AgentError(Exception):
    """Safe operational errors suitable for returning to an agent."""

    def __init__(self, message, *, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class AgentClient:
    def __init__(
        self,
        url,
        username,
        password,
        share,
        mother,
        local_root,
        *,
        http=None,
        pairing=False,
        allow_http=False,
    ):
        parsed = urlsplit(url)
        try:
            loopback = (
                parsed.hostname == "localhost"
                or ipaddress.ip_address(parsed.hostname or "").is_loopback
            )
        except ValueError:
            loopback = False
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or (parsed.scheme == "http" and not loopback and not (pairing and allow_http))
        ):
            raise AgentError("Use an HTTPS server URL, or HTTP on loopback, without a path.")
        if not pairing and (not username or not password or not share):
            raise AgentError("Samba username, password and share are required.")
        self.mother = self.remote_path(mother)
        self.url = url.rstrip("/")
        self.pairing = pairing
        self.pending = None
        self.paused_uploads = {}
        self.username = username
        self._password = password
        self.share = share
        self.local_root = Path(local_root).resolve(strict=True)
        if not self.local_root.is_dir():
            raise AgentError("Local transfer root must be an existing directory.")
        self.http = http or httpx.Client(
            base_url=url.rstrip("/"), timeout=60, follow_redirects=False, trust_env=False
        )
        self.http.headers.update({"X-SSUD-Request": "1", "Accept-Encoding": "identity"})
        self.expires = 0
        self.lock = threading.RLock()

    @classmethod
    def from_environment(cls):
        password = os.environ.pop("SSUD_AGENT_PASSWORD", "")
        url = os.getenv("SSUD_AGENT_URL", "http://127.0.0.1:8780")
        auth = os.getenv("SSUD_AGENT_AUTH", "browser")
        if auth == "browser":
            root = os.getenv("SSUD_AGENT_LOCAL_ROOT")
            if not root:
                raise AgentError("Set SSUD_AGENT_LOCAL_ROOT.")
            return cls(
                url,
                "",
                "",
                "",
                "",
                root,
                pairing=True,
                allow_http=os.getenv("SSUD_AGENT_ALLOW_HTTP", "").lower() == "true",
            )
        if auth != "password":
            raise AgentError("Set SSUD_AGENT_AUTH to browser or password.")
        required = (
            "SSUD_AGENT_USER",
            "SSUD_AGENT_SHARE",
            "SSUD_AGENT_HOME",
            "SSUD_AGENT_LOCAL_ROOT",
        )
        if any(name not in os.environ for name in required):
            raise AgentError("Set SSUD_AGENT_USER, SHARE, HOME and LOCAL_ROOT (all SSUD_AGENT_).")
        return cls(
            url,
            os.environ["SSUD_AGENT_USER"],
            password,
            os.environ["SSUD_AGENT_SHARE"],
            os.environ["SSUD_AGENT_HOME"],
            os.environ["SSUD_AGENT_LOCAL_ROOT"],
        )

    @staticmethod
    def remote_path(value):
        if (
            not isinstance(value, str)
            or value.startswith("/")
            or any(part in (".", "..") for part in value.split("/"))
            or any(char in value for char in "\\:\x00")
        ):
            raise AgentError("Remote paths must be relative to the configured Home folder.")
        return "/".join(part for part in value.split("/") if part)

    def local_path(self, value):
        path = Path(value)
        path = path if path.is_absolute() else self.local_root / path
        resolved = path.resolve()
        if not resolved.is_relative_to(self.local_root) or resolved == self.local_root:
            raise AgentError("Local file must be inside the configured transfer root.")
        return resolved

    def checked(self, response):
        if not 200 <= response.status_code < 300:
            if response.status_code == 401:
                self.expires = 0
            # Never relay response bodies, cookies, credentials or request URLs to the model.
            reference = response.headers.get("X-Request-ID", "")
            details = (
                f" Request ID: {reference}." if re.fullmatch(r"[a-f0-9]{24}", reference) else ""
            )
            raise AgentError(
                f"SSUD HTTP {response.status_code}; operation was not confirmed.{details}",
                status_code=response.status_code,
            )
        return response

    def request(self, method, path, **kwargs):
        try:
            result = self.checked(self.http.request(method, path, **kwargs)).json()
        except httpx.HTTPError:
            raise AgentError("SSUD connection failed; operation was not confirmed.") from None
        except ValueError:
            raise AgentError("Invalid SSUD response; operation was not confirmed.") from None
        if not isinstance(result, dict):
            raise AgentError("Invalid SSUD response; operation was not confirmed.")
        return result

    def connect(self):
        if self.expires > time.time():
            return
        if self.pairing:
            result = self.browser_login()
            if not result.get("connected"):
                raise AgentError("Run connect_files and approve the connection in your browser.")
            return
        self.http.headers.pop("X-SSUD-Share-Encoded", None)
        self.http.headers.pop("X-SSUD-Mother-Encoded", None)
        session = self.request(
            "POST", "/api/login", json={"username": self.username, "password": self._password}
        )
        try:
            self.request("PUT", "/api/share", json={"share": self.share})
            self.request("PUT", "/api/mother", json={"path": self.mother})
        except AgentError:
            try:
                self.request("POST", "/api/logout")
            except AgentError:
                pass
            raise
        self.http.headers.update(
            {
                "X-SSUD-Share-Encoded": quote(self.share, safe=""),
                "X-SSUD-Mother-Encoded": quote(self.mother, safe=""),
            }
        )
        self.expires = session["expires"]

    def browser_login(self):
        if not self.pairing:
            raise AgentError("Set SSUD_AGENT_AUTH=browser to use browser approval.")
        with self.lock:
            if self.expires > time.time():
                try:
                    self.request("GET", "/api/session", timeout=5)
                except AgentError as error:
                    if error.status_code != 401:
                        raise
                else:
                    return {"connected": True}
            self.http.headers.pop("Authorization", None)
            if self.pending:
                body, deadline = self.pending
                if deadline <= time.monotonic():
                    self.pending = None
                else:
                    try:
                        result = self.request("POST", "/api/agent/exchange", json=body, timeout=5)
                    except AgentError as error:
                        if error.status_code != 404:
                            raise
                        self.pending = None
                    else:
                        if not result.get("pending"):
                            self.http.headers["Authorization"] = "Bearer " + result["token"]
                            self.expires = result["expires"]
                            self.pending = None
                            self.paused_uploads.clear()
                            return {"connected": True}
            if self.pending is None:
                body = {"code": secrets.token_hex(8).upper(), "secret": secrets.token_urlsafe(32)}
                self.request("POST", "/api/agent/pair", json=body, timeout=5)
                self.pending = (body, time.monotonic() + 285)
            code = self.pending[0]["code"]
            return {
                "connected": False,
                "approval_url": f"{self.url}/agent/connect#{code}",
                "connection_code": code,
            }

    def browse(self, path="", offset=0, sort="name", listing=""):
        with self.lock:
            self.connect()
            return self.request(
                "GET",
                "/api/browse",
                params={
                    "path": self.remote_path(path),
                    "offset": offset,
                    "sort": sort,
                    "listing": listing,
                },
            )

    def create_folder(self, name, directory=""):
        directory = self.remote_path(directory)
        with self.lock:
            self.connect()
            return self.request("POST", "/api/folders", json={"name": name, "directory": directory})

    def workspace_request(self, method, endpoint, **kwargs):
        with self.lock:
            self.connect()
            return self.request(method, endpoint, **kwargs)

    def workspace(self):
        return self.workspace_request("GET", "/api/session")

    def usage(self):
        with self.lock:
            return {
                **self.workspace_request("GET", "/api/usage"),
                "quota": self.workspace_request("GET", "/api/quota"),
            }

    def index_status(self):
        return self.workspace_request("GET", "/api/index")

    def refresh_index(self):
        return self.workspace_request("POST", "/api/index")

    def set_automatic(self, enabled):
        return self.workspace_request("PUT", "/api/index/automatic", json={"enabled": enabled})

    def set_language(self, language):
        config = self.workspace_request("PUT", "/api/preferences", json={"language": language})
        return {key: config[key] for key in ("language", "preference")}

    def change_item(self, method, path, is_dir, size, mtime, name=None):
        body = {"path": self.remote_path(path), "is_dir": is_dir, "size": size, "mtime": mtime}
        if name is not None:
            body["name"] = name
        return self.workspace_request(method, "/api/items", json=body)

    def disconnect(self):
        with self.lock:
            if self.paused_uploads:
                raise AgentError("Finish or cancel paused uploads before disconnecting.")
            if self.pairing and "Authorization" in self.http.headers:
                self.request("POST", "/api/agent/disconnect")
                self.http.headers.pop("Authorization", None)
            elif not self.pairing and self.expires:
                self.request("POST", "/api/logout")
            self.pending = None
            self.expires = 0
            return {"connected": False}

    def search(self, query="", kind="all", extensions="", offset=0, cursor="", sort="name"):
        with self.lock:
            self.connect()
            return self.request(
                "GET",
                "/api/search",
                params=dict(
                    q=query,
                    kind=kind,
                    extensions=extensions,
                    offset=offset,
                    cursor=cursor,
                    sort=sort,
                ),
            )

    def upload(self, local_path, directory="", name=None, max_chunks=None, upload_id=None):
        if max_chunks is not None and max_chunks < 1:
            raise AgentError("max_chunks must be at least 1.")
        source = self.local_path(local_path)
        directory = self.remote_path(directory)
        if not source.is_file():
            raise AgentError("Upload source must be a regular file.")
        with self.lock, source.open("rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise AgentError("Upload source must be a regular file.")
            stat_result = os.fstat(handle.fileno())
            size = stat_result.st_size
            fingerprint = (source, size, stat_result.st_mtime_ns, stat_result.st_ino)
            self.connect()
            if upload_id is None:
                item = self.request(
                    "POST",
                    "/api/uploads",
                    json={"directory": directory, "name": name or source.name, "size": size},
                )
            else:
                original = self.paused_uploads.get(upload_id)
                if fingerprint != original:
                    raise AgentError("The paused upload source changed or is unavailable.")
                items = self.request("GET", "/api/uploads")["items"]
                item = next((entry for entry in items if entry["id"] == upload_id), None)
                if item is None:
                    self.paused_uploads.pop(upload_id, None)
                    raise AgentError("The paused upload no longer exists in this session.")
            upload_id = item["id"]
            offset = item["offset"]
            handle.seek(offset)
            chunks = 0
            try:
                while offset < size:
                    if max_chunks is not None and chunks >= max_chunks:
                        self.paused_uploads[upload_id] = fingerprint
                        return {
                            "state": "paused",
                            "upload_id": upload_id,
                            "offset": offset,
                            "size": size,
                            "name": item["name"],
                            "directory": item["directory"],
                        }
                    data = handle.read(min(CHUNK, size - offset))
                    if not data:
                        raise AgentError("Upload source changed while reading.")
                    # Retrying the same offset is safe under the server's chunk protocol.
                    for attempt in range(3):
                        try:
                            response = self.http.put(
                                f"/api/uploads/{upload_id}", params={"offset": offset}, content=data
                            )
                            break
                        except httpx.TransportError:
                            if attempt == 2:
                                raise AgentError("Upload connection failed.") from None
                    progress = self.checked(response).json()["offset"]
                    if progress != offset + len(data):
                        raise AgentError("Unexpected upload offset.")
                    offset = progress
                    chunks += 1
                if handle.read(1) or os.fstat(handle.fileno()).st_size != size:
                    raise AgentError("Upload source changed while reading.")
                result = self.request("POST", f"/api/uploads/{upload_id}/complete")
            except BaseException:
                try:
                    self.request("DELETE", f"/api/uploads/{upload_id}")
                except AgentError:
                    pass
                self.paused_uploads.pop(upload_id, None)
                raise
            self.paused_uploads.pop(upload_id, None)
            return {**result, "name": item["name"], "bytes": size, "directory": item["directory"]}

    def resume_upload(self, upload_id, max_chunks=None):
        with self.lock:
            original = self.paused_uploads.get(upload_id)
            if original is None:
                raise AgentError("This MCP session has no paused upload with that ID.")
            return self.upload(str(original[0]), max_chunks=max_chunks, upload_id=upload_id)

    def list_uploads(self):
        return self.workspace_request("GET", "/api/uploads")

    def cancel_upload(self, upload_id):
        if len(upload_id) != 32 or any(c not in "0123456789abcdef" for c in upload_id):
            raise AgentError("Invalid upload ID.")
        with self.lock:
            result = self.workspace_request("DELETE", f"/api/uploads/{upload_id}")
            self.paused_uploads.pop(upload_id, None)
            return result

    def download(self, path, local_path):
        remote = self.remote_path(path)
        destination = self.local_path(local_path)
        if destination.exists():
            raise AgentError("Download destination already exists; choose a new name.")
        with self.lock:
            self.connect()
            temporary = None
            try:
                with self.http.stream("GET", "/api/download", params={"path": remote}) as response:
                    self.checked(response)
                    if response.status_code != 200 or response.headers.get("content-encoding"):
                        raise AgentError("Expected a complete, uncompressed download.")
                    expected = response.headers.get("content-length")
                    size = 0
                    with tempfile.NamedTemporaryFile(
                        dir=destination.parent, prefix=".ssud-download-", delete=False
                    ) as handle:
                        temporary = Path(handle.name)
                        for data in response.iter_bytes(CHUNK):
                            handle.write(data)
                            size += len(data)
                        handle.flush()
                        os.fsync(handle.fileno())
                    if expected is None or size != int(expected):
                        raise AgentError("Incomplete download; destination was not created.")
                    # Publish atomically without replacing an existing file, even in a race.
                    os.link(temporary, destination)
                return {"path": remote, "local_path": str(destination), "bytes": size}
            except httpx.HTTPError:
                raise AgentError("Download interrupted; destination was not created.") from None
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

    def close(self):
        with self.lock:
            try:
                if self.expires > time.time():
                    for upload_id in self.paused_uploads:
                        try:
                            self.request("DELETE", f"/api/uploads/{upload_id}", timeout=5)
                        except AgentError:
                            pass
                if "Authorization" in self.http.headers and self.pairing:
                    self.request("POST", "/api/agent/disconnect")
                elif self.expires:
                    self.request("POST", "/api/logout")
            except AgentError:
                pass
            finally:
                self.expires = 0
                self._password = ""
                self.http.close()
