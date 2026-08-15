"""Validation, endpoint policy, redaction, and artifact confinement."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
RESOURCE_GROUP_RE = re.compile(r"^[\w.()\-]{1,90}$", re.ASCII)
RESOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9._()\-]{1,128}$")
STORAGE_ACCOUNT_RE = re.compile(r"^[a-z0-9]{3,24}$")
CONTAINER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$")
VAULT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$")


class AzurePackError(Exception):
    """Safe, operator-facing pack error."""


@dataclass(frozen=True)
class Cloud:
    name: str
    authority: str
    arm: str
    graph: str
    blob_suffix: str
    vault_suffix: str

    @property
    def arm_scope(self) -> str:
        return f"{self.arm}/.default"

    @property
    def graph_scope(self) -> str:
        return f"{self.graph}/.default"

    @property
    def storage_scope(self) -> str:
        return "https://storage.azure.com/.default"

    @property
    def vault_scope(self) -> str:
        return f"https://{self.vault_suffix.lstrip('.')}/.default"


CLOUDS = {
    "public": Cloud(
        "public",
        "https://login.microsoftonline.com",
        "https://management.azure.com",
        "https://graph.microsoft.com",
        ".blob.core.windows.net",
        ".vault.azure.net",
    ),
    "usgov": Cloud(
        "usgov",
        "https://login.microsoftonline.us",
        "https://management.usgovcloudapi.net",
        "https://graph.microsoft.us",
        ".blob.core.usgovcloudapi.net",
        ".vault.usgovcloudapi.net",
    ),
    "usdod": Cloud(
        "usdod",
        "https://login.microsoftonline.us",
        "https://management.usgovcloudapi.net",
        "https://dod-graph.microsoft.us",
        ".blob.core.usgovcloudapi.net",
        ".vault.usgovcloudapi.net",
    ),
    "china": Cloud(
        "china",
        "https://login.chinacloudapi.cn",
        "https://management.chinacloudapi.cn",
        "https://microsoftgraph.chinacloudapi.cn",
        ".blob.core.chinacloudapi.cn",
        ".vault.azure.cn",
    ),
}


@dataclass(frozen=True)
class Profile:
    cloud: Cloud
    auth_mode: str
    subscription_id: str | None
    tenant_id: str | None
    client_id: str | None
    client_secret: str | None
    managed_identity_client_id: str | None
    workload_token_file: str | None

    @classmethod
    def parse(cls, value: str | dict[str, Any]) -> Profile:
        try:
            raw = json.loads(value) if isinstance(value, str) else dict(value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AzurePackError("profile must be a JSON object") from exc
        allowed = {
            "cloud",
            "auth_mode",
            "subscription_id",
            "tenant_id",
            "client_id",
            "client_secret",
            "managed_identity_client_id",
            "workload_token_file",
        }
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise AzurePackError(f"unknown profile fields: {', '.join(unknown)}")
        cloud_name = raw.get("cloud", "public")
        if cloud_name not in CLOUDS:
            raise AzurePackError("cloud must be one of: public, usgov, usdod, china")
        mode = raw.get("auth_mode", "default")
        if mode not in {
            "default",
            "managed_identity",
            "workload_identity",
            "service_principal",
        }:
            raise AzurePackError("unsupported auth_mode")
        for field in (
            "subscription_id",
            "tenant_id",
            "client_id",
            "managed_identity_client_id",
        ):
            if raw.get(field) and not UUID_RE.fullmatch(str(raw[field])):
                raise AzurePackError(f"{field} must be a UUID")
        required = {
            "workload_identity": ("tenant_id", "client_id", "workload_token_file"),
            "service_principal": ("tenant_id", "client_id", "client_secret"),
        }.get(mode, ())
        missing = [field for field in required if not raw.get(field)]
        if missing:
            raise AzurePackError(f"{mode} requires: {', '.join(missing)}")
        if mode != "service_principal" and raw.get("client_secret"):
            raise AzurePackError(
                "client_secret is accepted only for service_principal auth"
            )
        token_file = raw.get("workload_token_file")
        if token_file and (
            not os.path.isabs(token_file) or not os.path.isfile(token_file)
        ):
            raise AzurePackError(
                "workload_token_file must be an existing absolute file"
            )
        return cls(
            cloud=CLOUDS[cloud_name],
            auth_mode=mode,
            subscription_id=raw.get("subscription_id"),
            tenant_id=raw.get("tenant_id"),
            client_id=raw.get("client_id"),
            client_secret=raw.get("client_secret"),
            managed_identity_client_id=raw.get("managed_identity_client_id"),
            workload_token_file=token_file,
        )

    def require_subscription(self) -> str:
        if not self.subscription_id:
            raise AzurePackError("subscription_id is required for this ARM operation")
        return self.subscription_id

    @property
    def secrets(self) -> tuple[str, ...]:
        return tuple(value for value in (self.client_secret,) if value)


def validate_resource_group(value: str) -> str:
    if not RESOURCE_GROUP_RE.fullmatch(value) or value.endswith("."):
        raise AzurePackError("invalid resource_group")
    return value


def validate_name(value: str, field: str = "name") -> str:
    if not RESOURCE_NAME_RE.fullmatch(value):
        raise AzurePackError(f"invalid {field}")
    return value


def validate_storage_account(value: str) -> str:
    if not STORAGE_ACCOUNT_RE.fullmatch(value):
        raise AzurePackError("invalid storage_account")
    return value


def validate_container(value: str) -> str:
    if not CONTAINER_RE.fullmatch(value) or "--" in value:
        raise AzurePackError("invalid container")
    return value


def validate_blob_name(value: str) -> str:
    if not value or len(value) > 1024 or any(ord(char) < 32 for char in value):
        raise AzurePackError("invalid blob_name")
    return value


def validate_vault(value: str) -> str:
    if not VAULT_NAME_RE.fullmatch(value) or "--" in value:
        raise AzurePackError("invalid vault_name")
    return value


def parse_object(
    value: str | dict[str, Any] | None, field: str = "body"
) -> dict[str, Any]:
    if value is None or value == "":
        return {}
    try:
        result = json.loads(value) if isinstance(value, str) else dict(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AzurePackError(f"{field} must be a JSON object") from exc
    if not isinstance(result, dict):
        raise AzurePackError(f"{field} must be a JSON object")
    return result


def require_confirmation(actual: str | None, verb: str, target: str) -> None:
    expected = f"{verb} {target}"
    if actual != expected:
        raise AzurePackError(f"confirmation must exactly equal: {expected}")


def artifact_path(relative: str, *, for_write: bool) -> Path:
    root_value = os.environ.get("ATTUNE_ARTIFACT_DIR")
    if not root_value or not os.path.isabs(root_value):
        raise AzurePackError(
            "ATTUNE_ARTIFACT_DIR must be set to an absolute path by the worker"
        )
    candidate_input = Path(relative)
    if candidate_input.is_absolute() or not relative or ".." in candidate_input.parts:
        raise AzurePackError("artifact_path must be a confined relative path")
    root = Path(root_value).resolve(strict=True)
    candidate = root.joinpath(candidate_input)
    parent = candidate.parent.resolve(strict=True)
    if parent != root and root not in parent.parents:
        raise AzurePackError("artifact_path escapes ATTUNE_ARTIFACT_DIR")
    if candidate.is_symlink():
        raise AzurePackError("artifact_path must not be a symlink")
    if not for_write:
        resolved = candidate.resolve(strict=True)
        if root not in resolved.parents or not resolved.is_file():
            raise AzurePackError("upload source must be a regular confined artifact")
        return resolved
    return candidate


def open_artifact_file(relative: str, mode: str):
    """Open an artifact without following symlinks in any path component."""
    if mode not in {"rb", "xb"}:
        raise ValueError("artifact mode must be rb or xb")
    root_value = os.environ.get("ATTUNE_ARTIFACT_DIR")
    if not root_value or not os.path.isabs(root_value):
        raise AzurePackError(
            "ATTUNE_ARTIFACT_DIR must be set to an absolute path by the worker"
        )
    relative_path = Path(relative)
    if relative_path.is_absolute() or not relative or ".." in relative_path.parts:
        raise AzurePackError("artifact_path must be a confined relative path")
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.open(Path(root_value).resolve(strict=True), directory_flags)
    try:
        for component in relative_path.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        flags = os.O_RDONLY if mode == "rb" else os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(relative_path.name, flags, 0o600, dir_fd=directory_fd)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            os.close(fd)
            raise AzurePackError("artifact_path must identify a regular file")
        return os.fdopen(fd, mode)
    except (FileNotFoundError, FileExistsError, NotADirectoryError, OSError) as exc:
        if isinstance(exc, AzurePackError):
            raise
        raise AzurePackError(
            f"artifact open rejected: {exc.__class__.__name__}"
        ) from None
    finally:
        os.close(directory_fd)


def validate_service_url(url: str, base: str) -> str:
    parsed = urlparse(url)
    expected = urlparse(base)
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected.hostname
        or parsed.port is not None
    ):
        raise AzurePackError(
            "service returned a continuation URL outside the cloud allowlist"
        )
    if not parsed.path.startswith("/v1.0/"):
        raise AzurePackError("service returned a continuation URL outside Graph v1.0")
    if parsed.username or parsed.password or parsed.fragment:
        raise AzurePackError("invalid continuation URL")
    return url


_SENSITIVE_KEY = re.compile(
    r"(secret|password|token|authorization|access.?key|sas)", re.IGNORECASE
)
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:sig|token|code|client_secret|password)=)[^&\s]+"
)
_CONNECTION_SECRET = re.compile(r"(?i)(AccountKey=)[^;\s]+")


def redact(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        output = {
            key: "[REDACTED]"
            if _SENSITIVE_KEY.search(str(key))
            else redact(item, secrets)
            for key, item in value.items()
        }
        if str(value.get("type", "")).lower() in {"securestring", "secureobject"}:
            output["value"] = "[REDACTED]"
        return output
    if isinstance(value, (list, tuple)):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        output = _BEARER.sub("Bearer [REDACTED]", value)
        output = _QUERY_SECRET.sub(r"\1[REDACTED]", output)
        output = _CONNECTION_SECRET.sub(r"\1[REDACTED]", output)
        for secret in secrets:
            if secret:
                output = output.replace(secret, "[REDACTED]")
        return output
    return value


def collect_secret_values(
    value: Any, sensitive_parent: bool = False
) -> tuple[str, ...]:
    """Find secret leaves in action parameters, including JSON-string bodies."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.extend(
                collect_secret_values(
                    item, sensitive_parent or bool(_SENSITIVE_KEY.search(str(key)))
                )
            )
    elif isinstance(value, (list, tuple)):
        for item in value:
            found.extend(collect_secret_values(item, sensitive_parent))
    elif isinstance(value, str):
        if sensitive_parent and value:
            found.append(value)
        stripped = value.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                found.extend(collect_secret_values(json.loads(value), sensitive_parent))
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
    return tuple(dict.fromkeys(found))


def remove_artifact_file(relative: str) -> bool:
    """Best-effort removal confined by directory file descriptors."""
    root_value = os.environ.get("ATTUNE_ARTIFACT_DIR")
    relative_path = Path(relative)
    if (
        not root_value
        or not os.path.isabs(root_value)
        or relative_path.is_absolute()
        or not relative
        or ".." in relative_path.parts
    ):
        return False
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(Path(root_value).resolve(strict=True), flags)
        try:
            for component in relative_path.parts[:-1]:
                next_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            os.unlink(relative_path.name, dir_fd=directory_fd)
            return True
        finally:
            os.close(directory_fd)
    except OSError:
        return False
