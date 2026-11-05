"""GitHubSource: read-only GET against https://api.github.com, nothing else.

Policy, enforced in code: one allowlisted host and scheme, no redirects followed, a timeout,
a response size cap, strict JSON, strict base64, the returned blob sha recomputed from the
decoded bytes, one generic User-Agent. The transport is injected so tests use recorded
fixtures (FixtureTransport); urllib_transport is the real one, a thin urllib wrapper that
honours the usual proxy and certificate environment and follows no redirect.

A token is never read unless the caller names an environment variable in token_env. The
value is sent only as an Authorization header to the allowlisted host; it is never logged,
stored, or put in a document or record.
"""

from __future__ import annotations

import base64
import binascii
import glob
import hashlib
import json
import mimetypes
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping

from .. import __version__
from ..canonical import canonical_bytes, sha256_hex
from ..clock import Clock
from .base import SourceDocument, SourceError, SourceFormatError, SourceRefused, SourceTooLarge, SourceUnavailable

API_HOST = "api.github.com"
API_BASE = f"https://{API_HOST}"
API_VERSION = "2022-11-28"
USER_AGENT = f"research-lab/{__version__} (stdlib urllib; read-only)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
KEPT_HEADERS = ("content-type", "etag", "last-modified", "x-github-media-type", "x-github-api-version-selected", "x-ratelimit-limit")

Transport = Callable[[str, Mapping[str, str], float], tuple[int, Mapping[str, str], bytes]]

_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def urllib_transport(url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, Mapping[str, str], bytes]:
    """GET url with headers; return (status, headers, body). Never follows a redirect: a 3xx
    comes back as its status for the adapter to refuse. Proxies and certificates come from
    the standard environment (HTTPS_PROXY, SSL_CERT_FILE); verification is never disabled."""
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status), {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        body = error.read() if error.fp is not None else b""
        return int(error.code), {k.lower(): v for k, v in error.headers.items()}, body
    except urllib.error.URLError as error:
        raise SourceUnavailable(f"transport failure: {error.reason}") from error
    except OSError as error:  # timeouts and socket errors
        raise SourceUnavailable(f"transport failure: {type(error).__name__}: {error}") from error


class FixtureTransport:
    """Serves recorded responses from a directory of JSON fixtures (see tests/fixtures/github).
    Each file holds url, status, headers and body. A url without a fixture is unavailable."""

    def __init__(self, directory: str) -> None:
        self.directory = directory
        self.calls: list[str] = []
        self._by_url: dict[str, tuple[int, dict[str, str], bytes]] = {}
        for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
            if os.path.basename(path) == "MANIFEST.json":
                continue
            with open(path, encoding="utf-8") as handle:
                fixture = json.load(handle)
            self._by_url[fixture["url"]] = (
                int(fixture["status"]),
                {str(k).lower(): str(v) for k, v in fixture.get("headers", {}).items()},
                fixture["body"].encode("utf-8"),
            )

    def __call__(self, url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, Mapping[str, str], bytes]:
        self.calls.append(url)
        if url not in self._by_url:
            raise SourceUnavailable(f"no recorded fixture for {url}")
        return self._by_url[url]


def git_blob_sha(content: bytes) -> str:
    """Git's blob object id: sha1 over "blob <len>\\0<content>". Used only to confirm that the
    decoded bytes are the blob GitHub named; integrity of the lab's records is SHA-256."""
    header = b"blob %d\x00" % len(content)
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


class GitHubSource:
    adapter_id = "github_rest"
    adapter_version = "1"

    def __init__(
        self,
        transport: Transport,
        clock: Clock,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        token_env: str | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock
        self._timeout = float(timeout)
        self._max_bytes = int(max_bytes)
        self._token_env = token_env

    # transport policy

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION, "User-Agent": USER_AGENT}
        if self._token_env:
            token = os.environ.get(self._token_env)
            if token:
                headers["Authorization"] = "Bearer " + token
        return headers

    def _get(self, path: str, query: Mapping[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        if not path.startswith("/"):
            raise SourceRefused("API paths are absolute")
        url = API_BASE + urllib.parse.quote(path, safe="/")
        if query:
            url += "?" + urllib.parse.urlencode(dict(query))
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname != API_HOST or parts.port not in (None, 443) or "@" in parts.netloc:
            raise SourceRefused(f"only https://{API_HOST} is allowed; refusing {url}")
        try:
            status, raw_headers, body = self._transport(url, self._headers(), self._timeout)
        except SourceError:
            raise
        except Exception as exc:  # the transport is injected; anything else is unavailability
            raise SourceUnavailable(f"transport failure: {type(exc).__name__}: {exc}") from exc
        headers = {str(k).lower(): str(v) for k, v in dict(raw_headers).items()}
        if len(body) > self._max_bytes:
            raise SourceTooLarge(f"response of {len(body)} bytes exceeds the cap of {self._max_bytes}")
        if 300 <= status < 400:
            raise SourceRefused(f"redirect {status} to {headers.get('location', '?')!r} refused: redirects are never followed")
        return status, headers, body

    @staticmethod
    def _json(status: int, headers: Mapping[str, str], body: bytes) -> tuple[dict[str, Any], str]:
        digest = sha256_hex(body)
        if status != 200:
            message = ""
            try:
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict) and isinstance(parsed.get("message"), str):
                    message = ": " + parsed["message"][:200]
            except (UnicodeDecodeError, ValueError):
                pass
            if status in (403, 429) and headers.get("x-ratelimit-remaining") == "0":
                raise SourceUnavailable(f"rate limited until epoch {headers.get('x-ratelimit-reset', '?')}{message}", status)
            if status == 404:
                raise SourceUnavailable(f"not found{message}", status)
            raise SourceUnavailable(f"GitHub API error{message}", status)
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise SourceFormatError(f"response is not JSON: {exc}", digest) from exc
        if not isinstance(data, dict):
            raise SourceFormatError(f"expected a JSON object, got {type(data).__name__}", digest)
        return data, digest

    @staticmethod
    def _field(data: Mapping[str, Any], name: str, kind: type, digest: str) -> Any:
        value = data.get(name)
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            raise SourceFormatError(f"field {name!r} missing or not {kind.__name__}", digest)
        return value

    @staticmethod
    def _retrieval(status: int, headers: Mapping[str, str], url_path: str) -> dict[str, Any]:
        out: dict[str, Any] = {"status": status, "api_version": API_VERSION, "path": url_path}
        for name in KEPT_HEADERS:
            if name in headers:
                out[name.replace("-", "_")] = headers[name]
        return out

    @staticmethod
    def _check_names(owner: str, repo: str) -> None:
        if not _NAME.match(owner) or not _NAME.match(repo) or owner in (".", "..") or repo in (".", ".."):
            raise SourceRefused(f"bad repository name {owner!r}/{repo!r}")

    @staticmethod
    def _check_path(path: str) -> None:
        if not path or path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")):
            raise SourceRefused(f"bad repository path {path!r}")

    # public fetches

    def fetch_metadata(self, owner: str, repo: str) -> SourceDocument:
        self._check_names(owner, repo)
        path = f"/repos/{owner}/{repo}"
        status, headers, body = self._get(path)
        data, digest = self._json(status, headers, body)
        full_name = self._field(data, "full_name", str, digest)
        default_branch = self._field(data, "default_branch", str, digest)
        pushed_at = self._field(data, "pushed_at", str, digest)
        content = canonical_bytes({"full_name": full_name, "default_branch": default_branch, "pushed_at": pushed_at})
        return SourceDocument(
            locator=f"github:{owner}/{repo}",
            content=content,
            media_type="application/json",
            retrieved_at=self._clock.now(),
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            retrieval=self._retrieval(status, headers, path),
            response_digest=digest,
            content_digest=sha256_hex(content),
            pinned={"repository": full_name, "default_branch": default_branch, "pushed_at": pushed_at},
        )

    def resolve_ref(self, owner: str, repo: str, ref: str) -> str:
        """A 40-hex ref is already a commit. A branch or lightweight tag is resolved through
        git/ref; an annotated tag is refused (it points at a tag object, not a commit)."""
        self._check_names(owner, repo)
        if _SHA40.match(ref):
            return ref
        if not ref or "/" in ref or ref.startswith(".") or ".." in ref:
            raise SourceRefused(f"bad ref {ref!r}")
        for kind in ("heads", "tags"):
            path = f"/repos/{owner}/{repo}/git/ref/{kind}/{ref}"
            status, headers, body = self._get(path)
            if status == 404:
                continue
            data, digest = self._json(status, headers, body)
            obj = self._field(data, "object", dict, digest)
            sha = self._field(obj, "sha", str, digest)
            if self._field(obj, "type", str, digest) != "commit":
                raise SourceUnavailable(f"ref {ref!r} is an annotated tag; only commits, branches and lightweight tags are supported")
            if not _SHA40.match(sha):
                raise SourceFormatError("object sha is not 40 hex characters", digest)
            return sha
        raise SourceUnavailable(f"ref {ref!r} is not a branch or tag of {owner}/{repo}", 404)

    def fetch_file(self, owner: str, repo: str, path: str, ref: str | None = None) -> SourceDocument:
        self._check_names(owner, repo)
        self._check_path(path)
        requested_ref = ref
        if requested_ref is None:
            requested_ref = self.fetch_metadata(owner, repo).pinned["default_branch"]
        commit = self.resolve_ref(owner, repo, requested_ref)
        api_path = f"/repos/{owner}/{repo}/contents/{path}"
        status, headers, body = self._get(api_path, {"ref": commit})
        data, digest = self._json(status, headers, body)
        if self._field(data, "type", str, digest) != "file":
            raise SourceFormatError(f"{path!r} is not a file at {commit}", digest)
        if self._field(data, "encoding", str, digest) != "base64":
            raise SourceFormatError("unexpected content encoding", digest)
        blob_sha = self._field(data, "sha", str, digest)
        declared_size = self._field(data, "size", int, digest)
        if self._field(data, "path", str, digest) != path:
            raise SourceFormatError("response path differs from the requested path", digest)
        raw = self._field(data, "content", str, digest).replace("\n", "").replace("\r", "")
        try:
            content = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SourceFormatError(f"content is not valid base64: {exc}", digest) from exc
        if len(content) > self._max_bytes:
            raise SourceTooLarge(f"decoded content of {len(content)} bytes exceeds the cap of {self._max_bytes}")
        if len(content) != declared_size:
            raise SourceFormatError(f"decoded size {len(content)} differs from declared size {declared_size}", digest)
        if not _SHA40.match(blob_sha) or git_blob_sha(content) != blob_sha:
            raise SourceFormatError("decoded content does not hash to the blob sha GitHub returned", digest)
        return SourceDocument(
            locator=f"github:{owner}/{repo}:{path}@{requested_ref}",
            content=content,
            media_type=mimetypes.guess_type(path)[0] or "application/octet-stream",
            retrieved_at=self._clock.now(),
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            retrieval=self._retrieval(status, headers, api_path),
            response_digest=digest,
            content_digest=sha256_hex(content),
            pinned={"repository": f"{owner}/{repo}", "path": path, "ref": requested_ref, "commit_sha": commit, "blob_sha": blob_sha},
        )

    def fetch(self, locator: str) -> SourceDocument:
        """github:owner/repo (metadata) or github:owner/repo:path[@ref] (one file)."""
        if not locator.startswith("github:"):
            raise SourceRefused(f"not a github locator: {locator!r}")
        rest = locator[len("github:") :]
        repo_part, sep, file_part = rest.partition(":")
        owner, slash, repo = repo_part.partition("/")
        if not slash or not owner or not repo:
            raise SourceRefused(f"bad github locator: {locator!r}")
        if not sep:
            return self.fetch_metadata(owner, repo)
        path, at, ref = file_part.rpartition("@")
        if not at:
            path, ref = file_part, None
        return self.fetch_file(owner, repo, path, ref or None)
