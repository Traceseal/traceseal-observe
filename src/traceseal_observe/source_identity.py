"""Bounded public-source observations and registry-neutral identity derivation.

The adapters deliberately retain no remote bytes. They stream four fixed small
files through local SHA-256 and emit only canonical hashes and sizes. Production
origins are fixed; constructor injection exists for isolated tests and witnesses.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, unquote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    HTTPHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from traceseal_observe import canonical_dumps

HUGGINGFACE_ORIGIN = "https://huggingface.co"
MODELSCOPE_ORIGIN = "https://modelscope.cn"
SOURCE_OBSERVATION_VERSION = "1.0"
IDENTITY_VERSION = "1.0"
ARTIFACT_TYPE = "model"
COMPARISON_PROFILE = "transformer-essential-small-files-v1"
EVIDENCE_STRENGTH = "selected_files_content_observed"
EQUIVALENCE_LEVEL = "selected_files_equivalent"
SELECTED_FILES = (
    "LICENSE",
    "config.json",
    "generation_config.json",
    "tokenizer_config.json",
)
MAX_METADATA_BYTES = 1 << 20
MAX_SELECTED_FILE_BYTES = 64 << 10
MAX_SOURCE_FILES = 10_000
DEFAULT_TIMEOUT_SECONDS = 10.0

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_HASH_RE = re.compile(r"^git-sha1:[0-9a-f]{40}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_SEGMENT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class SourceObservationError(ValueError):
    """A public source could not produce a safe, canonical observation."""

    def __init__(self, message: str, code: str = "source_observation_invalid"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DerivedSourceObservation:
    metadata_hash: str
    observation_root: str
    provider: str
    revision_hash: str
    source_identity_hash: str


@dataclass(frozen=True)
class DerivedCanonicalIdentity:
    canonical_id: str
    equivalence_level: str
    evidence_root: str
    identity_hash: str
    profile_hash: str
    selected_files: int
    source_observation_hashes: tuple[str, ...]


@dataclass(frozen=True)
class PinnedSourceFile:
    """One bounded repository file fetched at an immutable provider revision."""

    content: bytes
    content_hash: str
    provider: str
    revision: dict[str, str]
    size: int
    source_identity_hash: str


def _fail(message: str, code: str = "source_observation_invalid") -> None:
    raise SourceObservationError(message, code)


def _hash_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _hash_text(value: str) -> str:
    return _hash_bytes(value.encode("utf-8"))


def _hash_record(value: Any) -> str:
    return _hash_bytes(canonical_dumps(value))


def _require_object(
    value: Any, required: set[str], optional: set[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("evidence object shape is invalid")
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        _fail("evidence object shape is invalid")
    return value


def _require_hash(value: Any) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        _fail("evidence hash is invalid")
    return value


def _valid_repository_id(value: str, *, namespaced: bool = False) -> bool:
    if not isinstance(value, str) or any(char in value for char in "?#\\"):
        return False
    parts = value.split("/")
    if len(parts) < (2 if namespaced else 1) or len(parts) > 2:
        return False
    return all(_REPOSITORY_SEGMENT_RE.fullmatch(part) is not None for part in parts)


def _valid_logical_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1024:
        return False
    if value.startswith("/") or "\\" in value or "\x00" in value:
        return False
    if unquote(value) != value:  # encoded separators/traversal fail closed
        return False
    parts = value.split("/")
    if any(
        part in ("", ".", "..") or _PATH_SEGMENT_RE.fullmatch(part) is None
        for part in parts
    ):
        return False
    return posixpath.normpath(value) == value


def _safe_encoding(value: str) -> bool:
    return not value or value.strip().lower() == "identity"


class _OriginRedirectHandler(HTTPRedirectHandler):
    def __init__(self, scheme: str, netloc: str, allow_same_origin: bool):
        super().__init__()
        self.scheme = scheme
        self.netloc = netloc
        self.allow_same_origin = allow_same_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        target = urlsplit(newurl)
        redirect_count = len(getattr(req, "redirect_dict", {}))
        if (
            not self.allow_same_origin
            or target.username is not None
            or target.password is not None
            or target.scheme.lower() != self.scheme
            or target.netloc.lower() != self.netloc
            or redirect_count >= 2
        ):
            raise HTTPError(req.full_url, code, "redirect refused", headers, fp)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            raise HTTPError(req.full_url, code, "redirect refused", headers, fp)
        for header in ("Authorization", "Cookie", "Proxy-Authorization"):
            redirected.remove_header(header)
        redirected.add_header("Accept-Encoding", "identity")
        return redirected


class _SourceTransport:
    def __init__(self, base_url: str, *, timeout: float, allow_redirect: bool):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or timeout <= 0
            or timeout > DEFAULT_TIMEOUT_SECONDS
        ):
            _fail("source configuration is invalid", "source_configuration_invalid")
        self.scheme = parsed.scheme.lower()
        self.netloc = parsed.netloc.lower()
        self.base_url = f"{self.scheme}://{self.netloc}"
        self.timeout = timeout
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPHandler(),
            HTTPSHandler(),
            _OriginRedirectHandler(self.scheme, self.netloc, allow_redirect),
        )

    def url(self, *segments: str, query: dict[str, str] | None = None) -> str:
        path = "/".join(quote(segment, safe="") for segment in segments)
        target = f"{self.base_url}/{path}"
        if query:
            target += "?" + urlencode(query)
        return target

    def open(self, url: str, accept: str):  # noqa: ANN201 - urllib response protocol
        request = Request(
            url,
            method="GET",
            headers={"Accept": accept, "Accept-Encoding": "identity"},
        )
        for header in ("Authorization", "Cookie", "Proxy-Authorization"):
            request.remove_header(header)
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            raise SourceObservationError(
                "source observation unavailable", "source_unavailable"
            ) from exc
        final = urlsplit(response.geturl())
        if final.scheme.lower() != self.scheme or final.netloc.lower() != self.netloc:
            response.close()
            _fail("source observation unavailable", "source_unavailable")
        return response

    def json(self, url: str) -> Any:
        response = self.open(url, "application/json")
        try:
            if response.status != 200 or not _safe_encoding(
                response.headers.get("Content-Encoding", "")
            ):
                _fail("source observation unavailable", "source_unavailable")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > MAX_METADATA_BYTES:
                _fail("source response is too large", "response_too_large")
            payload = response.read(MAX_METADATA_BYTES + 1)
        except SourceObservationError:
            raise
        except (OSError, ValueError) as exc:
            raise SourceObservationError(
                "source observation unavailable", "source_unavailable"
            ) from exc
        finally:
            response.close()
        if len(payload) > MAX_METADATA_BYTES:
            _fail("source response is too large", "response_too_large")
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceObservationError(
                "source response is malformed", "source_response_malformed"
            ) from exc

    def file_hashes(self, url: str, expected_size: int) -> tuple[str, str]:
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or expected_size > MAX_SELECTED_FILE_BYTES
        ):
            _fail("selected file is too large", "selected_file_too_large")
        response = self.open(url, "application/octet-stream")
        sha256_hasher = hashlib.sha256()
        git_hasher = hashlib.sha1(b"blob %d\0" % expected_size)
        total = 0
        try:
            if response.status != 200 or not _safe_encoding(
                response.headers.get("Content-Encoding", "")
            ):
                _fail("source observation unavailable", "source_unavailable")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) != expected_size:
                _fail("selected file size differs", "selected_file_mismatch")
            while True:
                chunk = response.read(min(16 << 10, MAX_SELECTED_FILE_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SELECTED_FILE_BYTES:
                    _fail("selected file is too large", "selected_file_too_large")
                sha256_hasher.update(chunk)
                git_hasher.update(chunk)
        except SourceObservationError:
            raise
        except (OSError, ValueError) as exc:
            raise SourceObservationError(
                "source observation unavailable", "source_unavailable"
            ) from exc
        finally:
            response.close()
        if total != expected_size:
            _fail("selected file size differs", "selected_file_mismatch")
        return sha256_hasher.hexdigest(), git_hasher.hexdigest()

    def file_bytes(
        self, url: str, *, expected_size: int | None = None
    ) -> tuple[bytes, str, str]:
        if expected_size is not None and (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 1
            or expected_size > MAX_SELECTED_FILE_BYTES
        ):
            _fail("pinned file is too large", "selected_file_too_large")
        response = self.open(url, "application/octet-stream")
        try:
            if response.status != 200 or not _safe_encoding(
                response.headers.get("Content-Encoding", "")
            ):
                _fail("source observation unavailable", "source_unavailable")
            declared = response.headers.get("Content-Length")
            declared_size = int(declared) if declared is not None else None
            if declared_size is not None and (
                declared_size < 1
                or (expected_size is not None and declared_size != expected_size)
            ):
                _fail("pinned file size differs", "source_response_malformed")
            if declared_size is not None and declared_size > MAX_SELECTED_FILE_BYTES:
                _fail("pinned file is too large", "selected_file_too_large")
            payload = response.read(MAX_SELECTED_FILE_BYTES + 1)
        except SourceObservationError:
            raise
        except (OSError, ValueError) as exc:
            raise SourceObservationError(
                "source observation unavailable", "source_unavailable"
            ) from exc
        finally:
            response.close()
        if len(payload) > MAX_SELECTED_FILE_BYTES:
            _fail("pinned file is too large", "selected_file_too_large")
        if (
            not payload
            or (declared_size is not None and len(payload) != declared_size)
            or (expected_size is not None and len(payload) != expected_size)
        ):
            _fail("pinned file size differs", "source_response_malformed")
        git_oid = hashlib.sha1(b"blob %d\0" % len(payload) + payload).hexdigest()
        return payload, hashlib.sha256(payload).hexdigest(), git_oid


class HuggingFaceSourceAdapter:
    """Fresh, non-caching observation of the fixed public Hugging Face origin."""

    def __init__(
        self,
        *,
        base_url: str = HUGGINGFACE_ORIGIN,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self._transport = _SourceTransport(
            base_url, timeout=timeout, allow_redirect=True
        )

    def observe_revision(self, repository_id: str) -> str:
        if not _valid_repository_id(repository_id):
            _fail("source identity is invalid", "source_identity_invalid")
        parts = repository_id.split("/")
        metadata = self._transport.json(
            self._transport.url("api", "models", *parts)
        )
        if not isinstance(metadata, dict):
            _fail("source response is malformed", "source_response_malformed")
        revision = metadata.get("sha")
        if metadata.get("id") != repository_id or not isinstance(
            revision, str
        ) or _COMMIT_RE.fullmatch(revision) is None:
            _fail("source response is malformed", "source_response_malformed")
        return revision

    def fetch_pinned_file(self, repository_id: str, logical_path: str) -> PinnedSourceFile:
        if not _valid_repository_id(repository_id) or not _valid_logical_path(logical_path):
            _fail("source identity or path is invalid", "source_identity_invalid")
        revision = self.observe_revision(repository_id)
        payload, digest, _ = self._transport.file_bytes(
            self._transport.url(
                *repository_id.split("/"), "resolve", revision, logical_path
            )
        )
        return PinnedSourceFile(
            content=payload,
            content_hash="sha256:" + digest,
            provider="huggingface",
            revision={
                "kind": "git_commit_sha1",
                "reference_hash": _hash_text("main"),
                "value_hash": _hash_text(revision),
            },
            size=len(payload),
            source_identity_hash=_hash_text(repository_id),
        )

    def observe(self, repository_id: str) -> dict[str, Any]:
        revision = self.observe_revision(repository_id)
        parts = repository_id.split("/")
        tree = self._transport.json(
            self._transport.url(
                "api",
                "models",
                *parts,
                "tree",
                revision,
                query={"expand": "true", "recursive": "true"},
            )
        )
        if not isinstance(tree, list) or not tree or len(tree) > MAX_SOURCE_FILES:
            _fail("source response is malformed", "source_response_malformed")
        files: dict[str, dict[str, Any]] = {}
        for raw in tree:
            if not isinstance(raw, dict):
                _fail("source response is malformed", "source_response_malformed")
            path, kind, size, oid = (
                raw.get("path"),
                raw.get("type"),
                raw.get("size"),
                raw.get("oid"),
            )
            if (
                not _valid_logical_path(path)
                or kind != "file"
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or path in files
            ):
                _fail("source file manifest is invalid", "source_response_malformed")
            lfs = raw.get("lfs")
            if lfs is None:
                if not isinstance(oid, str) or _COMMIT_RE.fullmatch(oid) is None:
                    _fail("provider hash is invalid", "source_response_malformed")
                provider_hash = {
                    "algorithm": "git_sha1",
                    "origin": "provider_supplied",
                    "value": "git-sha1:" + oid,
                }
            else:
                if (
                    not isinstance(lfs, dict)
                    or lfs.get("size") != size
                    or not isinstance(lfs.get("oid"), str)
                    or _SHA256_RE.fullmatch(lfs["oid"]) is None
                ):
                    _fail("provider hash is invalid", "source_response_malformed")
                provider_hash = {
                    "algorithm": "sha256",
                    "origin": "provider_supplied",
                    "value": "sha256:" + lfs["oid"],
                }
            files[path] = {"size": size, "provider_hash": provider_hash}

        selected = []
        for path in SELECTED_FILES:
            metadata = files.get(path)
            if metadata is None:
                _fail("selected file is missing", "selected_file_missing")
            content_sha256, git_oid = self._transport.file_hashes(
                self._transport.url(*parts, "resolve", revision, path),
                metadata["size"],
            )
            provider_hash = metadata["provider_hash"]
            expected = (
                "git-sha1:" + git_oid
                if provider_hash["algorithm"] == "git_sha1"
                else "sha256:" + content_sha256
            )
            if provider_hash["value"] != expected:
                _fail("provider and local hashes differ", "selected_file_mismatch")
            selected.append(
                {
                    "content_hash": {
                        "algorithm": "sha256",
                        "origin": "locally_computed",
                        "value": "sha256:" + content_sha256,
                    },
                    "path_hash": _hash_text(path),
                    "provider_hash": provider_hash,
                    "size": metadata["size"],
                }
            )
        return _build_source_observation(
            "huggingface",
            repository_id,
            {
                "kind": "git_commit_sha1",
                "reference_hash": _hash_text("main"),
                "value_hash": _hash_text(revision),
            },
            selected,
        )


class ModelScopeSourceAdapter:
    """Fresh, non-caching observation of the fixed public ModelScope origin."""

    def __init__(
        self,
        *,
        base_url: str = MODELSCOPE_ORIGIN,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self._transport = _SourceTransport(
            base_url, timeout=timeout, allow_redirect=False
        )

    def fetch_pinned_file(self, repository_id: str, logical_path: str) -> PinnedSourceFile:
        if not _valid_repository_id(repository_id, namespaced=True) or not _valid_logical_path(
            logical_path
        ):
            _fail("source identity or path is invalid", "source_identity_invalid")
        parts = repository_id.split("/")
        metadata = self._transport.json(
            self._transport.url("api", "v1", "models", *parts)
        )
        if not isinstance(metadata, dict) or metadata.get("Code") != 200:
            _fail("source response is malformed", "source_response_malformed")
        data = metadata.get("Data")
        if (
            not isinstance(data, dict)
            or data.get("Path", "") + "/" + data.get("Name", "") != repository_id
            or data.get("Revision") != "master"
            or data.get("IsAccessible") != 1
            or data.get("IsPublished") != 1
        ):
            _fail("source response is malformed", "source_response_malformed")
        listing = self._transport.json(
            self._transport.url(
                "api",
                "v1",
                "models",
                *parts,
                "repo",
                "files",
                query={"Recursive": "true", "Revision": "master"},
            )
        )
        listing_data = listing.get("Data") if isinstance(listing, dict) else None
        raw_files = listing_data.get("Files") if isinstance(listing_data, dict) else None
        if (
            not isinstance(listing, dict)
            or listing.get("Code") != 200
            or not isinstance(raw_files, list)
            or not raw_files
            or len(raw_files) > MAX_SOURCE_FILES
        ):
            _fail("source response is malformed", "source_response_malformed")
        selected: dict[str, Any] | None = None
        seen: set[str] = set()
        for raw in raw_files:
            if not isinstance(raw, dict):
                _fail("source response is malformed", "source_response_malformed")
            path, kind, size, digest, revision = (
                raw.get("Path"),
                raw.get("Type"),
                raw.get("Size"),
                raw.get("Sha256"),
                raw.get("Revision"),
            )
            if (
                not _valid_logical_path(path)
                or path in seen
                or kind != "blob"
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or not isinstance(digest, str)
                or _SHA256_RE.fullmatch(digest) is None
                or not isinstance(revision, str)
                or _COMMIT_RE.fullmatch(revision) is None
            ):
                _fail("source file manifest is invalid", "source_response_malformed")
            seen.add(path)
            if path == logical_path:
                selected = {
                    "size": size,
                    "digest": digest,
                    "revision": revision,
                }
        if selected is None:
            _fail("pinned file is missing", "source_unavailable")
        if selected["size"] > MAX_SELECTED_FILE_BYTES:
            _fail("pinned file is too large", "selected_file_too_large")
        payload, digest, _ = self._transport.file_bytes(
            self._transport.url(
                "api",
                "v1",
                "models",
                *parts,
                "repo",
                query={
                    "FilePath": logical_path,
                    "Revision": selected["revision"],
                },
            ),
            expected_size=selected["size"],
        )
        if digest != selected["digest"]:
            _fail("provider and local hashes differ", "selected_file_mismatch")
        return PinnedSourceFile(
            content=payload,
            content_hash="sha256:" + digest,
            provider="modelscope",
            revision={
                "kind": "file_commit_sha1",
                "reference_hash": _hash_text("master"),
                "value_hash": _hash_text(selected["revision"]),
            },
            size=len(payload),
            source_identity_hash=_hash_text(repository_id),
        )

    def observe(self, repository_id: str) -> dict[str, Any]:
        if not _valid_repository_id(repository_id, namespaced=True):
            _fail("source identity is invalid", "source_identity_invalid")
        parts = repository_id.split("/")
        metadata = self._transport.json(
            self._transport.url("api", "v1", "models", *parts)
        )
        if not isinstance(metadata, dict) or metadata.get("Code") != 200:
            _fail("source response is malformed", "source_response_malformed")
        data = metadata.get("Data")
        if (
            not isinstance(data, dict)
            or data.get("Path", "") + "/" + data.get("Name", "") != repository_id
            or data.get("Revision") != "master"
            or data.get("IsAccessible") != 1
            or data.get("IsPublished") != 1
        ):
            _fail("source response is malformed", "source_response_malformed")
        listing = self._transport.json(
            self._transport.url(
                "api",
                "v1",
                "models",
                *parts,
                "repo",
                "files",
                query={"Recursive": "true", "Revision": "master"},
            )
        )
        if not isinstance(listing, dict) or listing.get("Code") != 200:
            _fail("source response is malformed", "source_response_malformed")
        listing_data = listing.get("Data")
        raw_files = listing_data.get("Files") if isinstance(listing_data, dict) else None
        if (
            not isinstance(raw_files, list)
            or not raw_files
            or len(raw_files) > MAX_SOURCE_FILES
        ):
            _fail("source response is malformed", "source_response_malformed")
        files: dict[str, dict[str, Any]] = {}
        for raw in raw_files:
            if not isinstance(raw, dict):
                _fail("source response is malformed", "source_response_malformed")
            path, kind, size, digest, revision = (
                raw.get("Path"),
                raw.get("Type"),
                raw.get("Size"),
                raw.get("Sha256"),
                raw.get("Revision"),
            )
            if (
                not _valid_logical_path(path)
                or kind != "blob"
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or not isinstance(digest, str)
                or _SHA256_RE.fullmatch(digest) is None
                or not isinstance(revision, str)
                or _COMMIT_RE.fullmatch(revision) is None
                or path in files
            ):
                _fail("source file manifest is invalid", "source_response_malformed")
            files[path] = {
                "size": size,
                "revision": revision,
                "provider_hash": {
                    "algorithm": "sha256",
                    "origin": "provider_supplied",
                    "value": "sha256:" + digest,
                },
            }

        selected = []
        revision_records = []
        for path in SELECTED_FILES:
            file = files.get(path)
            if file is None:
                _fail("selected file is missing", "selected_file_missing")
            content_sha256, _ = self._transport.file_hashes(
                self._transport.url(
                    "api",
                    "v1",
                    "models",
                    *parts,
                    "repo",
                    query={"FilePath": path, "Revision": "master"},
                ),
                file["size"],
            )
            if file["provider_hash"]["value"] != "sha256:" + content_sha256:
                _fail("provider and local hashes differ", "selected_file_mismatch")
            path_hash = _hash_text(path)
            selected.append(
                {
                    "content_hash": {
                        "algorithm": "sha256",
                        "origin": "locally_computed",
                        "value": "sha256:" + content_sha256,
                    },
                    "path_hash": path_hash,
                    "provider_hash": file["provider_hash"],
                    "size": file["size"],
                }
            )
            revision_records.append(
                {"commit_hash": _hash_text(file["revision"]), "path_hash": path_hash}
            )
        revision_records.sort(key=lambda item: item["path_hash"])
        return _build_source_observation(
            "modelscope",
            repository_id,
            {
                "kind": "selected_file_commit_set",
                "reference_hash": _hash_text("master"),
                "value_hash": _hash_record(revision_records),
            },
            selected,
        )


def _build_source_observation(
    provider: str,
    repository_id: str,
    revision: dict[str, Any],
    files: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered = sorted(files, key=lambda item: item["path_hash"])
    observation = {
        "artifact_type": ARTIFACT_TYPE,
        "evidence_strength": EVIDENCE_STRENGTH,
        "files": ordered,
        "metadata_hash": "",
        "observation_root": "",
        "observation_version": SOURCE_OBSERVATION_VERSION,
        "provider": provider,
        "revision": revision,
        "source_identity_hash": _hash_text(repository_id),
    }
    _complete_source_observation(observation)
    return observation


def _valid_source_hash(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"algorithm", "origin", "value"}:
        return False
    if value["origin"] not in {"provider_supplied", "locally_computed"}:
        return False
    if value["algorithm"] == "sha256":
        return isinstance(value["value"], str) and _HASH_RE.fullmatch(value["value"]) is not None
    if value["algorithm"] == "git_sha1":
        return isinstance(value["value"], str) and _GIT_HASH_RE.fullmatch(value["value"]) is not None
    return False


def _complete_source_observation(observation: dict[str, Any]) -> None:
    top = _require_object(
        observation,
        {
            "artifact_type",
            "evidence_strength",
            "files",
            "metadata_hash",
            "observation_root",
            "observation_version",
            "provider",
            "revision",
            "source_identity_hash",
        },
    )
    if (
        top["artifact_type"] != ARTIFACT_TYPE
        or top["evidence_strength"] != EVIDENCE_STRENGTH
        or top["observation_version"] != SOURCE_OBSERVATION_VERSION
        or top["provider"] not in {"huggingface", "modelscope"}
    ):
        _fail("source observation discriminator is invalid")
    _require_hash(top["source_identity_hash"])
    revision = _require_object(
        top["revision"], {"kind", "reference_hash", "value_hash"}
    )
    expected_kind = (
        "git_commit_sha1"
        if top["provider"] == "huggingface"
        else "selected_file_commit_set"
    )
    if revision["kind"] != expected_kind:
        _fail("source revision kind is invalid")
    _require_hash(revision["reference_hash"])
    _require_hash(revision["value_hash"])
    files = top["files"]
    if not isinstance(files, list) or len(files) != len(SELECTED_FILES):
        _fail("selected file evidence is invalid")
    expected_paths = {_hash_text(path) for path in SELECTED_FILES}
    previous = ""
    metadata_files = []
    for raw in files:
        file = _require_object(
            raw, {"content_hash", "path_hash", "provider_hash", "size"}
        )
        path_hash = _require_hash(file["path_hash"])
        if path_hash not in expected_paths or (previous and path_hash <= previous):
            _fail("selected file evidence is invalid")
        expected_paths.remove(path_hash)
        previous = path_hash
        if (
            isinstance(file["size"], bool)
            or not isinstance(file["size"], int)
            or file["size"] < 0
            or file["size"] > MAX_SELECTED_FILE_BYTES
            or not _valid_source_hash(file["content_hash"])
            or file["content_hash"]["algorithm"] != "sha256"
            or file["content_hash"]["origin"] != "locally_computed"
            or not _valid_source_hash(file["provider_hash"])
            or file["provider_hash"]["origin"] != "provider_supplied"
        ):
            _fail("selected file evidence is invalid")
        metadata_files.append(
            {
                "path_hash": path_hash,
                "provider_hash": file["provider_hash"],
                "size": file["size"],
            }
        )
    if expected_paths:
        _fail("selected file evidence is invalid")
    metadata_record = {
        "files": metadata_files,
        "provider": top["provider"],
        "revision": revision,
        "source_identity_hash": top["source_identity_hash"],
    }
    top["metadata_hash"] = _hash_record(metadata_record)
    root_record = {
        "artifact_type": top["artifact_type"],
        "evidence_strength": top["evidence_strength"],
        "files": files,
        "metadata_hash": top["metadata_hash"],
        "observation_version": top["observation_version"],
        "provider": top["provider"],
        "revision": revision,
        "source_identity_hash": top["source_identity_hash"],
    }
    top["observation_root"] = _hash_record(root_record)


def derive_source_observation(value: Any) -> DerivedSourceObservation:
    if not isinstance(value, dict):
        _fail("source observation is invalid")
    original = json.loads(canonical_dumps(value))
    candidate = json.loads(canonical_dumps(value))
    candidate["metadata_hash"] = ""
    candidate["observation_root"] = ""
    _complete_source_observation(candidate)
    if candidate != original:
        _fail("source observation hash chain differs")
    revision_hash = _hash_record(candidate["revision"])
    return DerivedSourceObservation(
        metadata_hash=candidate["metadata_hash"],
        observation_root=candidate["observation_root"],
        provider=candidate["provider"],
        revision_hash=revision_hash,
        source_identity_hash=candidate["source_identity_hash"],
    )


def canonical_observation_bytes(value: dict[str, Any]) -> bytes:
    derive_source_observation(value)
    return canonical_dumps(value)


def _profile_hash() -> str:
    return _hash_record(
        {
            "path_hashes": sorted(_hash_text(path) for path in SELECTED_FILES),
            "profile_version": COMPARISON_PROFILE,
        }
    )


def build_canonical_identity(observations: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(observations, list) or len(observations) != 2:
        _fail("canonical identity requires exactly two sources")
    by_provider: dict[str, dict[str, Any]] = {}
    for observation in observations:
        derived = derive_source_observation(observation)
        if derived.provider in by_provider:
            _fail("duplicate identity source")
        by_provider[derived.provider] = observation
    if set(by_provider) != {"huggingface", "modelscope"}:
        _fail("canonical identity sources are invalid")
    hf, ms = by_provider["huggingface"], by_provider["modelscope"]
    identity_files = []
    for hf_file, ms_file in zip(hf["files"], ms["files"]):
        if (
            hf_file["path_hash"] != ms_file["path_hash"]
            or hf_file["size"] != ms_file["size"]
            or hf_file["content_hash"]["value"]
            != ms_file["content_hash"]["value"]
        ):
            _fail("selected file content differs", "selected_file_mismatch")
        identity_files.append(
            {
                "content_digest": hf_file["content_hash"]["value"],
                "path_hash": hf_file["path_hash"],
                "size": hf_file["size"],
            }
        )
    profile_hash = _profile_hash()
    canonical_id = _hash_record(
        {
            "artifact_type": ARTIFACT_TYPE,
            "files": identity_files,
            "profile_hash": profile_hash,
        }
    )
    sources = []
    for provider in sorted(by_provider):
        observation = by_provider[provider]
        derived = derive_source_observation(observation)
        sources.append(
            {
                "observation_root": derived.observation_root,
                "provider": provider,
                "revision_hash": derived.revision_hash,
                "source_identity_hash": derived.source_identity_hash,
            }
        )
    evidence_root = _hash_record(
        {
            "canonical_id": canonical_id,
            "identity_version": IDENTITY_VERSION,
            "level": EQUIVALENCE_LEVEL,
            "profile_hash": profile_hash,
            "sources": sources,
        }
    )
    return {
        "artifact_type": ARTIFACT_TYPE,
        "canonical_id": canonical_id,
        "equivalence": {
            "evidence_root": evidence_root,
            "level": EQUIVALENCE_LEVEL,
            "profile_hash": profile_hash,
            "selected_files": len(identity_files),
        },
        "identity_version": IDENTITY_VERSION,
        "sources": sources,
    }


def derive_canonical_identity(
    identity: Any, observations: list[dict[str, Any]]
) -> DerivedCanonicalIdentity:
    if not isinstance(identity, dict):
        _fail("canonical identity is invalid")
    expected = build_canonical_identity(observations)
    if canonical_dumps(identity) != canonical_dumps(expected):
        _fail("canonical identity differs from source evidence")
    source_hashes = tuple(
        _hash_bytes(canonical_observation_bytes(observation))
        for observation in sorted(observations, key=lambda item: item["provider"])
    )
    return DerivedCanonicalIdentity(
        canonical_id=expected["canonical_id"],
        equivalence_level=expected["equivalence"]["level"],
        evidence_root=expected["equivalence"]["evidence_root"],
        identity_hash=_hash_bytes(canonical_dumps(expected)),
        profile_hash=expected["equivalence"]["profile_hash"],
        selected_files=expected["equivalence"]["selected_files"],
        source_observation_hashes=source_hashes,
    )


def canonical_identity_bytes(
    identity: dict[str, Any], observations: list[dict[str, Any]]
) -> bytes:
    derive_canonical_identity(identity, observations)
    return canonical_dumps(identity)
