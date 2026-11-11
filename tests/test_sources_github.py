"""GitHubSource against recorded fixtures and hand-built transports. No network."""

import base64
import hashlib
import json
import os

import pytest
from conftest import ROOT

from research_lab.canonical import sha256_hex
from research_lab.clock import StepClock
from research_lab.sources import FixtureTransport, GitHubSource, SourceFormatError, SourceRefused, SourceTooLarge, SourceUnavailable
from research_lab.sources import github as github_module
from research_lab.sources.github import API_HOST, USER_AGENT, git_blob_sha

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "github")
OWNER, REPO = "wking53214", "WATCHER_MCU"
COMMIT = "4ab218d0c4c31e78bc0b9359f6c09fa32c87babd"
BLOB = "1862cdec13f22793e20c82f95ef43ddb86d40385"
README_SHA256 = "59a4d834f4b65040668ce44a4063eabbfa0e58451af337d552bde68f14f7d6b3"


@pytest.fixture
def transport():
    return FixtureTransport(FIXTURES)


@pytest.fixture
def src(transport):
    return GitHubSource(transport, StepClock())


class Canned:
    """A transport that returns one canned response, recording what it was asked."""

    def __init__(self, status=200, headers=None, body=b"{}", raise_exc=None):
        self.status, self.headers, self.body, self.raise_exc = status, headers or {}, body, raise_exc
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers), timeout))
        if self.raise_exc:
            raise self.raise_exc
        return self.status, self.headers, self.body


def contents_body(raw: bytes, **overrides):
    data = {
        "type": "file", "encoding": "base64", "size": len(raw), "name": "f.txt", "path": "f.txt",
        "sha": git_blob_sha(raw), "content": base64.b64encode(raw).decode("ascii") + "\n",
    }
    data.update(overrides)
    return json.dumps(data).encode("utf-8")


# fixtures


def test_fixture_manifest_matches_the_files_and_holds_no_secrets():
    with open(os.path.join(FIXTURES, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    listed = manifest["files"]
    on_disk = {name for name in os.listdir(FIXTURES) if name.endswith(".json") and name != "MANIFEST.json"}
    assert set(listed) == on_disk and len(on_disk) == 4
    for name, digest in listed.items():
        with open(os.path.join(FIXTURES, name), "rb") as handle:
            data = handle.read()
        assert hashlib.sha256(data).hexdigest() == digest, name
        fixture = json.loads(data)
        assert fixture["url"].startswith("https://api.github.com/") and fixture["captured_at"] == manifest["captured_at"]
        assert hashlib.sha256(fixture["body"].encode("utf-8")).hexdigest() == fixture["body_sha256"]
        lowered = {k.lower() for k in fixture["headers"]}
        assert not lowered & {"authorization", "set-cookie", "x-github-request-id"}
        assert "ghp_" not in data.decode("utf-8") and "Bearer" not in data.decode("utf-8")
    assert "unauthenticated" in manifest["source"]


def test_metadata_from_fixture(src, transport):
    doc = src.fetch_metadata(OWNER, REPO)
    assert doc.locator == f"github:{OWNER}/{REPO}" and doc.media_type == "application/json"
    assert doc.pinned["default_branch"] == "main" and doc.pinned["repository"] == f"{OWNER}/{REPO}"
    assert doc.pinned["pushed_at"].endswith("Z")
    assert json.loads(doc.content) == {"default_branch": "main", "full_name": f"{OWNER}/{REPO}", "pushed_at": doc.pinned["pushed_at"]}
    assert doc.retrieval["status"] == 200 and doc.retrieval["content_type"].startswith("application/json")
    assert transport.calls == [f"https://api.github.com/repos/{OWNER}/{REPO}"]


def test_readme_from_fixture_is_pinned_and_verified(src, transport):
    doc = src.fetch_file(OWNER, REPO, "README.md", ref="main")
    assert doc.pinned == {"repository": f"{OWNER}/{REPO}", "path": "README.md", "ref": "main", "commit_sha": COMMIT, "blob_sha": BLOB}
    assert doc.content_digest == README_SHA256 and doc.size == 42937
    assert git_blob_sha(doc.content) == BLOB
    assert doc.locator == f"github:{OWNER}/{REPO}:README.md@main" and doc.media_type == "text/markdown"
    assert doc.content.startswith(b"# ")
    assert transport.calls == [
        f"https://api.github.com/repos/{OWNER}/{REPO}/git/ref/heads/main",
        f"https://api.github.com/repos/{OWNER}/{REPO}/contents/README.md?ref={COMMIT}",
    ]
    assert doc.response_digest == sha256_hex(transport(transport.calls[1], {}, 1)[2])


def test_default_ref_resolves_the_default_branch_first(src, transport):
    doc = src.fetch_file(OWNER, REPO, "README.md")
    assert doc.pinned["ref"] == "main" and transport.calls[0] == f"https://api.github.com/repos/{OWNER}/{REPO}"


def test_locator_parsing(src):
    assert src.fetch(f"github:{OWNER}/{REPO}").pinned["default_branch"] == "main"
    assert src.fetch(f"github:{OWNER}/{REPO}:README.md@main").pinned["commit_sha"] == COMMIT
    assert src.fetch(f"github:{OWNER}/{REPO}:README.md").pinned["ref"] == "main"
    for bad in ("https://evil.com/x", "github:evil", "github:a@evil.com/repo", "github:/repo", f"github:{OWNER}/{REPO}:../x@main"):
        with pytest.raises(SourceRefused):
            src.fetch(bad)


def test_commit_sha_ref_is_used_without_resolution(src, transport):
    src.fetch_file(OWNER, REPO, "README.md", ref=COMMIT)
    assert transport.calls == [f"https://api.github.com/repos/{OWNER}/{REPO}/contents/README.md?ref={COMMIT}"]


def test_genuine_404_maps_to_unavailable(src):
    with pytest.raises(SourceUnavailable, match="not found") as info:
        src.fetch_file(OWNER, REPO, "this-path-does-not-exist.md", ref=COMMIT)
    assert info.value.status == 404


def test_unknown_url_has_no_fixture(src):
    with pytest.raises(SourceUnavailable, match="no recorded fixture"):
        src.fetch_file(OWNER, REPO, "other.md", ref=COMMIT)


# transport policy


def test_only_the_allowlisted_host_is_ever_requested_and_the_check_is_independent_of_the_constant(src, transport, monkeypatch):
    src.fetch_file(OWNER, REPO, "README.md")
    assert all(url.startswith(f"https://{API_HOST}/") for url in transport.calls)
    monkeypatch.setattr(github_module, "API_BASE", "https://evil.example")
    with pytest.raises(SourceRefused, match="only https://api.github.com is allowed"):
        GitHubSource(transport, StepClock()).fetch_metadata(OWNER, REPO)
    monkeypatch.setattr(github_module, "API_BASE", "http://api.github.com")
    with pytest.raises(SourceRefused, match="only https"):
        GitHubSource(transport, StepClock()).fetch_metadata(OWNER, REPO)
    monkeypatch.setattr(github_module, "API_BASE", "https://user@api.github.com")
    with pytest.raises(SourceRefused):
        GitHubSource(transport, StepClock()).fetch_metadata(OWNER, REPO)


def test_redirects_are_refused():
    canned = Canned(status=302, headers={"location": "https://evil.example/x"})
    with pytest.raises(SourceRefused, match="redirect 302 .* refused"):
        GitHubSource(canned, StepClock()).fetch_metadata(OWNER, REPO)


def test_user_agent_is_generic_and_headers_are_set():
    canned = Canned(body=json.dumps({"full_name": "a/b", "default_branch": "main", "pushed_at": "x"}).encode())
    GitHubSource(canned, StepClock(), timeout=3.5).fetch_metadata("a", "b")
    url, headers, timeout = canned.calls[0]
    assert headers["User-Agent"] == USER_AGENT and "@" not in USER_AGENT and "research-lab" in USER_AGENT
    assert headers["Accept"] == "application/vnd.github+json" and headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert "Authorization" not in headers and timeout == 3.5


def test_token_env_is_only_read_when_named_and_never_stored(monkeypatch):
    monkeypatch.setenv("RL_TEST_TOKEN", "secret-value")
    body = json.dumps({"full_name": "a/b", "default_branch": "main", "pushed_at": "x"}).encode()
    without = Canned(body=body)
    GitHubSource(without, StepClock()).fetch_metadata("a", "b")
    assert "Authorization" not in without.calls[0][1]
    with_token = Canned(body=body)
    doc = GitHubSource(with_token, StepClock(), token_env="RL_TEST_TOKEN").fetch_metadata("a", "b")
    assert with_token.calls[0][1]["Authorization"] == "Bearer secret-value"
    assert "secret-value" not in json.dumps(doc.record_body()) and "secret-value" not in doc.content.decode()


def test_http_errors_and_rate_limits_map_to_unavailable_with_status():
    rate = Canned(status=403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700000000"}, body=b'{"message":"API rate limit exceeded"}')
    with pytest.raises(SourceUnavailable, match="rate limited until epoch 1700000000: API rate limit exceeded") as info:
        GitHubSource(rate, StepClock()).fetch_metadata("a", "b")
    assert info.value.status == 403
    with pytest.raises(SourceUnavailable, match="GitHub API error") as info:
        GitHubSource(Canned(status=500, body=b"oops"), StepClock()).fetch_metadata("a", "b")
    assert info.value.status == 500
    with pytest.raises(SourceUnavailable, match="transport failure: RuntimeError: boom"):
        GitHubSource(Canned(raise_exc=RuntimeError("boom")), StepClock()).fetch_metadata("a", "b")
    with pytest.raises(SourceUnavailable, match="not found") as info:
        GitHubSource(Canned(status=404, body=b'{"message":"Not Found"}'), StepClock()).fetch_file("a", "b", "x", ref=COMMIT)
    assert info.value.status == 404


def test_response_size_cap():
    big = Canned(body=b"{" + b" " * 200 + b"}")
    with pytest.raises(SourceTooLarge):
        GitHubSource(big, StepClock(), max_bytes=100).fetch_metadata("a", "b")
    content = b"y" * 300
    with pytest.raises(SourceTooLarge):
        GitHubSource(Canned(body=contents_body(content)), StepClock(), max_bytes=250).fetch_file("a", "b", "f.txt", ref=COMMIT)


@pytest.mark.parametrize(
    "body, match",
    [
        (b"not json", "not JSON"),
        (b"[1, 2]", "expected a JSON object"),
        (json.dumps({"full_name": "a/b", "pushed_at": "x"}).encode(), "'default_branch' missing"),
        (json.dumps({"full_name": "a/b", "default_branch": 5, "pushed_at": "x"}).encode(), "'default_branch' missing or not str"),
    ],
)
def test_malformed_or_changed_metadata_json_raises_format_error_with_digest(body, match):
    with pytest.raises(SourceFormatError, match=match) as info:
        GitHubSource(Canned(body=body), StepClock()).fetch_metadata("a", "b")
    assert info.value.response_digest == sha256_hex(body)


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"type": "dir"}, "not a file"),
        ({"encoding": "none"}, "unexpected content encoding"),
        ({"size": "12"}, "'size' missing or not int"),
        ({"path": "other.txt"}, "differs from the requested path"),
        ({"content": "!!!not base64!!!"}, "not valid base64"),
        ({"content": base64.b64encode(b"different bytes").decode()}, "decoded size"),
        ({"sha": "0" * 40}, "does not hash to the blob sha"),
        ({"sha": "zz"}, "does not hash to the blob sha"),
    ],
)
def test_corrupt_or_changed_contents_json_is_refused(overrides, match):
    body = contents_body(b"hello world\n", **overrides)
    with pytest.raises(SourceFormatError, match=match) as info:
        GitHubSource(Canned(body=body), StepClock()).fetch_file("a", "b", "f.txt", ref=COMMIT)
    assert info.value.response_digest == sha256_hex(body)


def test_base64_with_wrong_length_declared_is_refused():
    content = b"hello\n"
    body = contents_body(content, content=base64.b64encode(content + b"x").decode(), size=len(content))
    with pytest.raises(SourceFormatError, match="decoded size 7 differs from declared size 6"):
        GitHubSource(Canned(body=body), StepClock()).fetch_file("a", "b", "f.txt", ref=COMMIT)


def test_ref_resolution_falls_back_to_tags_and_refuses_annotated_tags():
    class Router:
        def __init__(self, tag_type):
            self.tag_type = tag_type
            self.calls = []

        def __call__(self, url, headers, timeout):
            self.calls.append(url)
            if "/git/ref/heads/" in url:
                return 404, {}, b'{"message":"Not Found"}'
            if "/git/ref/tags/" in url:
                return 200, {}, json.dumps({"ref": "refs/tags/v1", "object": {"sha": COMMIT, "type": self.tag_type}}).encode()
            return 200, {}, contents_body(b"tagged\n")

    light = Router("commit")
    assert GitHubSource(light, StepClock()).resolve_ref("a", "b", "v1") == COMMIT
    assert len(light.calls) == 2
    with pytest.raises(SourceUnavailable, match="annotated tag"):
        GitHubSource(Router("tag"), StepClock()).resolve_ref("a", "b", "v1")
    missing = Canned(status=404, body=b'{"message":"Not Found"}')
    with pytest.raises(SourceUnavailable, match="not a branch or tag") as info:
        GitHubSource(missing, StepClock()).resolve_ref("a", "b", "nope")
    assert info.value.status == 404
    with pytest.raises(SourceRefused, match="bad ref"):
        GitHubSource(missing, StepClock()).resolve_ref("a", "b", "refs/../heads")
    with pytest.raises(SourceRefused, match="bad repository"):
        GitHubSource(missing, StepClock()).resolve_ref("a", "../b", "main")
    with pytest.raises(SourceRefused, match="bad repository path"):
        GitHubSource(missing, StepClock()).fetch_file("a", "b", "/etc/passwd", ref=COMMIT)
