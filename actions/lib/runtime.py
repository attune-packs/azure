"""Hardened Azure SDK and Microsoft Graph action runtime."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from datetime import date, datetime
from typing import Any, ClassVar

from .security import (
    AzurePackError,
    Profile,
    collect_secret_values,
    open_artifact_file,
    parse_object,
    redact,
    remove_artifact_file,
    require_confirmation,
    validate_blob_name,
    validate_container,
    validate_name,
    validate_resource_group,
    validate_service_url,
    validate_storage_account,
    validate_vault,
)

READ_RETRY_STATUSES = {429, 500, 502, 503, 504}
GRAPH_USER_FIELDS = (
    "id,displayName,userPrincipalName,mail,accountEnabled,jobTitle,department"
)
GRAPH_GROUP_FIELDS = "id,displayName,description,mailNickname,mailEnabled,securityEnabled,isAssignableToRole"


def serialize(value: Any) -> Any:
    """Convert Azure models to JSON-compatible values without introspecting secrets."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serialize(item) for item in value]
    if hasattr(value, "as_dict"):
        return serialize(value.as_dict())
    return str(value)


def collect_pages(
    values: Iterable[Any], max_items: int, max_pages: int
) -> tuple[list[Any], bool]:
    if not 1 <= max_items <= 1000 or not 1 <= max_pages <= 100:
        raise AzurePackError("max_items must be 1..1000 and max_pages must be 1..100")
    items: list[Any] = []
    truncated = False
    pages = values.by_page() if hasattr(values, "by_page") else (values,)
    for page_number, page in enumerate(pages, 1):
        if page_number > max_pages:
            truncated = True
            break
        for item in page:
            if len(items) >= max_items:
                truncated = True
                break
            items.append(serialize(item))
        if truncated:
            break
    return items, truncated


class Runtime:
    def __init__(
        self,
        profile_value: str | dict[str, Any],
        *,
        session: Any = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.profile = Profile.parse(profile_value)
        self._credential_instance: Any = None
        self._session = session
        self._sleep = sleeper

    @property
    def credential(self) -> Any:
        if self._credential_instance is None:
            from azure.identity import (
                ClientSecretCredential,
                DefaultAzureCredential,
                ManagedIdentityCredential,
                WorkloadIdentityCredential,
            )

            common = {"authority": self.profile.cloud.authority}
            if self.profile.auth_mode == "default":
                self._credential_instance = DefaultAzureCredential(
                    **common,
                    managed_identity_client_id=self.profile.managed_identity_client_id,
                    exclude_interactive_browser_credential=True,
                )
            elif self.profile.auth_mode == "managed_identity":
                self._credential_instance = ManagedIdentityCredential(
                    client_id=self.profile.managed_identity_client_id
                )
            elif self.profile.auth_mode == "workload_identity":
                self._credential_instance = WorkloadIdentityCredential(
                    **common,
                    tenant_id=self.profile.tenant_id,
                    client_id=self.profile.client_id,
                    token_file_path=self.profile.workload_token_file,
                )
            else:
                self._credential_instance = ClientSecretCredential(
                    **common,
                    tenant_id=self.profile.tenant_id,
                    client_id=self.profile.client_id,
                    client_secret=self.profile.client_secret,
                )
        return self._credential_instance

    def close(self) -> None:
        if self._credential_instance is not None and hasattr(
            self._credential_instance, "close"
        ):
            self._credential_instance.close()
        if self._session is not None and hasattr(self._session, "close"):
            self._session.close()

    def _sdk_options(self, mutation: bool) -> dict[str, Any]:
        from azure.core.pipeline.policies import RetryPolicy
        from azure.core.pipeline.transport import RequestsTransport

        # Mutation retries are disabled. Reads use Azure Core's bounded retry policy.
        retry = RetryPolicy(
            retry_total=0 if mutation else 3,
            retry_connect=0 if mutation else 3,
            retry_read=0 if mutation else 3,
            retry_status=0 if mutation else 3,
            retry_backoff_factor=0.8,
        )
        return {
            "base_url": self.profile.cloud.arm,
            "credential_scopes": [self.profile.cloud.arm_scope],
            "retry_policy": retry,
            "transport": RequestsTransport(connection_timeout=10, read_timeout=30),
            "polling_interval": 2,
        }

    def _resource_client(self, mutation: bool = False) -> Any:
        from azure.mgmt.resource.resources import ResourceManagementClient

        return ResourceManagementClient(
            self.credential,
            self.profile.require_subscription(),
            **self._sdk_options(mutation),
        )

    def _deployment_client(self, mutation: bool = False) -> Any:
        from azure.mgmt.resource.deployments import DeploymentsMgmtClient

        return DeploymentsMgmtClient(
            self.credential,
            self.profile.require_subscription(),
            **self._sdk_options(mutation),
        )

    def _compute_client(self, mutation: bool = False) -> Any:
        from azure.mgmt.compute import ComputeManagementClient

        return ComputeManagementClient(
            self.credential,
            self.profile.require_subscription(),
            **self._sdk_options(mutation),
        )

    def _network_client(self, mutation: bool = False) -> Any:
        from azure.mgmt.network import NetworkManagementClient

        return NetworkManagementClient(
            self.credential,
            self.profile.require_subscription(),
            **self._sdk_options(mutation),
        )

    def _storage_management_client(self, mutation: bool = False) -> Any:
        from azure.mgmt.storage import StorageManagementClient

        return StorageManagementClient(
            self.credential,
            self.profile.require_subscription(),
            **self._sdk_options(mutation),
        )

    @staticmethod
    def _success(operation: str, **values: Any) -> dict[str, Any]:
        return {"ok": True, "operation": operation, **serialize(values)}

    def _finish(self, operation: str, poller: Any, timeout: int) -> dict[str, Any]:
        if not 10 <= timeout <= 3600:
            raise AzurePackError("poll_timeout must be 10..3600 seconds")
        result = poller.result(timeout=timeout)
        status = poller.status() if hasattr(poller, "status") else "Succeeded"
        if str(status).lower() not in {"succeeded", "success", "completed"}:
            raise AzurePackError(f"{operation} did not succeed (status={status})")
        return self._success(operation, status=status, resource=serialize(result))

    def execute(self, operation: str, **params: Any) -> dict[str, Any]:
        method_name = f"op_{operation}"
        method = getattr(self, method_name, None)
        if (
            method is None
            or not method_name.replace("op_", "").replace("_", "").isalnum()
        ):
            raise AzurePackError("unsupported operation")
        operation_secrets = self.profile.secrets + collect_secret_values(params)
        try:
            return redact(method(**params), operation_secrets)
        except AzurePackError:
            raise
        except Exception as exc:  # noqa: BLE001 - sanitize every SDK boundary failure.
            safe = redact(str(exc), operation_secrets)
            raise AzurePackError(f"{operation} failed: {safe[:500]}") from None

    # Subscriptions and resource groups

    def op_subscriptions_list(
        self, max_items: int = 200, max_pages: int = 20, **_: Any
    ) -> dict[str, Any]:
        from azure.mgmt.subscription import SubscriptionClient

        client = SubscriptionClient(self.credential, **self._sdk_options(False))
        items, truncated = collect_pages(
            client.subscriptions.list(), int(max_items), int(max_pages)
        )
        return self._success(
            "subscriptions_list", items=items, count=len(items), truncated=truncated
        )

    def op_resource_groups_list(
        self, max_items: int = 500, max_pages: int = 50, **_: Any
    ) -> dict[str, Any]:
        items, truncated = collect_pages(
            self._resource_client().resource_groups.list(),
            int(max_items),
            int(max_pages),
        )
        return self._success(
            "resource_groups_list", items=items, count=len(items), truncated=truncated
        )

    def op_resource_groups_get(self, resource_group: str, **_: Any) -> dict[str, Any]:
        group = self._resource_client().resource_groups.get(
            validate_resource_group(resource_group)
        )
        return self._success("resource_groups_get", resource=group)

    def op_resource_groups_create_or_update(
        self, resource_group: str, location: str, tags_json: str = "{}", **_: Any
    ) -> dict[str, Any]:
        validate_name(location, "location")
        body = {"location": location, "tags": parse_object(tags_json, "tags_json")}
        result = self._resource_client(True).resource_groups.create_or_update(
            validate_resource_group(resource_group), body
        )
        return self._success(
            "resource_groups_create_or_update", status="Succeeded", resource=result
        )

    def op_resource_groups_delete(
        self, resource_group: str, confirmation: str, poll_timeout: int = 900, **_: Any
    ) -> dict[str, Any]:
        group = validate_resource_group(resource_group)
        target = self._resource_id(group)
        require_confirmation(confirmation, "DELETE", target)
        poller = self._resource_client(True).resource_groups.begin_delete(group)
        return self._finish("resource_groups_delete", poller, int(poll_timeout))

    def _resource_id(self, group: str, provider_path: str = "") -> str:
        base = f"/subscriptions/{self.profile.require_subscription()}/resourceGroups/{group}"
        return f"{base}/{provider_path}" if provider_path else base

    # Compute virtual machines

    def op_vm_list(
        self,
        resource_group: str = "",
        max_items: int = 500,
        max_pages: int = 50,
        **_: Any,
    ) -> dict[str, Any]:
        service = self._compute_client().virtual_machines
        values = (
            service.list(validate_resource_group(resource_group))
            if resource_group
            else service.list_all()
        )
        items, truncated = collect_pages(values, int(max_items), int(max_pages))
        return self._success(
            "vm_list", items=items, count=len(items), truncated=truncated
        )

    def op_vm_get(self, resource_group: str, name: str, **_: Any) -> dict[str, Any]:
        result = self._compute_client().virtual_machines.get(
            validate_resource_group(resource_group),
            validate_name(name),
            expand="instanceView",
        )
        return self._success("vm_get", resource=result)

    def op_vm_create_or_update(
        self,
        resource_group: str,
        name: str,
        resource_json: str,
        if_match: str = "",
        poll_timeout: int = 1800,
        **_: Any,
    ) -> dict[str, Any]:
        from azure.core import MatchConditions

        kwargs = {}
        if if_match:
            kwargs.update(etag=if_match, match_condition=MatchConditions.IfNotModified)
        poller = self._compute_client(True).virtual_machines.begin_create_or_update(
            validate_resource_group(resource_group),
            validate_name(name),
            parse_object(resource_json, "resource_json"),
            **kwargs,
        )
        return self._finish("vm_create_or_update", poller, int(poll_timeout))

    def _vm_power(
        self,
        operation: str,
        method: str,
        resource_group: str,
        name: str,
        poll_timeout: int,
    ) -> dict[str, Any]:
        service = self._compute_client(True).virtual_machines
        poller = getattr(service, method)(
            validate_resource_group(resource_group), validate_name(name)
        )
        return self._finish(operation, poller, int(poll_timeout))

    def op_vm_start(
        self, resource_group: str, name: str, poll_timeout: int = 900, **_: Any
    ) -> dict[str, Any]:
        return self._vm_power(
            "vm_start", "begin_start", resource_group, name, poll_timeout
        )

    def op_vm_stop(
        self, resource_group: str, name: str, poll_timeout: int = 900, **_: Any
    ) -> dict[str, Any]:
        return self._vm_power(
            "vm_stop", "begin_power_off", resource_group, name, poll_timeout
        )

    def op_vm_deallocate(
        self, resource_group: str, name: str, poll_timeout: int = 900, **_: Any
    ) -> dict[str, Any]:
        return self._vm_power(
            "vm_deallocate", "begin_deallocate", resource_group, name, poll_timeout
        )

    def op_vm_restart(
        self, resource_group: str, name: str, poll_timeout: int = 900, **_: Any
    ) -> dict[str, Any]:
        return self._vm_power(
            "vm_restart", "begin_restart", resource_group, name, poll_timeout
        )

    def op_vm_delete(
        self,
        resource_group: str,
        name: str,
        confirmation: str,
        poll_timeout: int = 1800,
        **_: Any,
    ) -> dict[str, Any]:
        group, vm_name = validate_resource_group(resource_group), validate_name(name)
        target = self._resource_id(
            group, f"providers/Microsoft.Compute/virtualMachines/{vm_name}"
        )
        require_confirmation(confirmation, "DELETE", target)
        poller = self._compute_client(True).virtual_machines.begin_delete(
            group, vm_name
        )
        return self._finish("vm_delete", poller, int(poll_timeout))

    # Network resources

    _NETWORK: ClassVar[dict[str, tuple[str, str]]] = {
        "vnet": ("virtual_networks", "Microsoft.Network/virtualNetworks"),
        "nic": ("network_interfaces", "Microsoft.Network/networkInterfaces"),
        "public_ip": ("public_ip_addresses", "Microsoft.Network/publicIPAddresses"),
        "nsg": ("network_security_groups", "Microsoft.Network/networkSecurityGroups"),
    }

    def _network_list(
        self, kind: str, resource_group: str, max_items: int, max_pages: int
    ) -> dict[str, Any]:
        service_name, _ = self._NETWORK[kind]
        service = getattr(self._network_client(), service_name)
        values = (
            service.list(validate_resource_group(resource_group))
            if resource_group
            else service.list_all()
        )
        items, truncated = collect_pages(values, int(max_items), int(max_pages))
        return self._success(
            f"{kind}_list", items=items, count=len(items), truncated=truncated
        )

    def _network_get(self, kind: str, resource_group: str, name: str) -> dict[str, Any]:
        service_name, _ = self._NETWORK[kind]
        result = getattr(self._network_client(), service_name).get(
            validate_resource_group(resource_group), validate_name(name)
        )
        return self._success(f"{kind}_get", resource=result)

    def _network_put(
        self,
        kind: str,
        resource_group: str,
        name: str,
        resource_json: str,
        poll_timeout: int,
    ) -> dict[str, Any]:
        service_name, _ = self._NETWORK[kind]
        poller = getattr(
            self._network_client(True), service_name
        ).begin_create_or_update(
            validate_resource_group(resource_group),
            validate_name(name),
            parse_object(resource_json, "resource_json"),
        )
        return self._finish(f"{kind}_create_or_update", poller, int(poll_timeout))

    def _network_delete(
        self,
        kind: str,
        resource_group: str,
        name: str,
        confirmation: str,
        poll_timeout: int,
    ) -> dict[str, Any]:
        service_name, provider = self._NETWORK[kind]
        group, resource_name = (
            validate_resource_group(resource_group),
            validate_name(name),
        )
        target = self._resource_id(group, f"providers/{provider}/{resource_name}")
        require_confirmation(confirmation, "DELETE", target)
        poller = getattr(self._network_client(True), service_name).begin_delete(
            group, resource_name
        )
        return self._finish(f"{kind}_delete", poller, int(poll_timeout))

    def op_vnet_list(
        self,
        resource_group: str = "",
        max_items: int = 500,
        max_pages: int = 50,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_list("vnet", resource_group, max_items, max_pages)

    def op_vnet_get(self, resource_group: str, name: str, **_: Any) -> dict[str, Any]:
        return self._network_get("vnet", resource_group, name)

    def op_vnet_create_or_update(
        self,
        resource_group: str,
        name: str,
        resource_json: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_put(
            "vnet", resource_group, name, resource_json, poll_timeout
        )

    def op_vnet_delete(
        self,
        resource_group: str,
        name: str,
        confirmation: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_delete(
            "vnet", resource_group, name, confirmation, poll_timeout
        )

    def op_subnet_list(
        self,
        resource_group: str,
        vnet_name: str,
        max_items: int = 500,
        max_pages: int = 50,
        **_: Any,
    ) -> dict[str, Any]:
        values = self._network_client().subnets.list(
            validate_resource_group(resource_group),
            validate_name(vnet_name, "vnet_name"),
        )
        items, truncated = collect_pages(values, int(max_items), int(max_pages))
        return self._success(
            "subnet_list", items=items, count=len(items), truncated=truncated
        )

    def op_subnet_get(
        self, resource_group: str, vnet_name: str, name: str, **_: Any
    ) -> dict[str, Any]:
        result = self._network_client().subnets.get(
            validate_resource_group(resource_group),
            validate_name(vnet_name, "vnet_name"),
            validate_name(name),
        )
        return self._success("subnet_get", resource=result)

    def op_subnet_create_or_update(
        self,
        resource_group: str,
        vnet_name: str,
        name: str,
        resource_json: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        poller = self._network_client(True).subnets.begin_create_or_update(
            validate_resource_group(resource_group),
            validate_name(vnet_name, "vnet_name"),
            validate_name(name),
            parse_object(resource_json, "resource_json"),
        )
        return self._finish("subnet_create_or_update", poller, int(poll_timeout))

    def op_subnet_delete(
        self,
        resource_group: str,
        vnet_name: str,
        name: str,
        confirmation: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        group, vnet, subnet = (
            validate_resource_group(resource_group),
            validate_name(vnet_name, "vnet_name"),
            validate_name(name),
        )
        target = self._resource_id(
            group,
            f"providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}",
        )
        require_confirmation(confirmation, "DELETE", target)
        return self._finish(
            "subnet_delete",
            self._network_client(True).subnets.begin_delete(group, vnet, subnet),
            int(poll_timeout),
        )

    def op_nic_list(
        self,
        resource_group: str = "",
        max_items: int = 500,
        max_pages: int = 50,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_list("nic", resource_group, max_items, max_pages)

    def op_nic_get(self, resource_group: str, name: str, **_: Any) -> dict[str, Any]:
        return self._network_get("nic", resource_group, name)

    def op_nic_create_or_update(
        self,
        resource_group: str,
        name: str,
        resource_json: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_put(
            "nic", resource_group, name, resource_json, poll_timeout
        )

    def op_nic_delete(
        self,
        resource_group: str,
        name: str,
        confirmation: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_delete(
            "nic", resource_group, name, confirmation, poll_timeout
        )

    def op_public_ip_list(
        self,
        resource_group: str = "",
        max_items: int = 500,
        max_pages: int = 50,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_list("public_ip", resource_group, max_items, max_pages)

    def op_public_ip_get(
        self, resource_group: str, name: str, **_: Any
    ) -> dict[str, Any]:
        return self._network_get("public_ip", resource_group, name)

    def op_public_ip_create_or_update(
        self,
        resource_group: str,
        name: str,
        resource_json: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_put(
            "public_ip", resource_group, name, resource_json, poll_timeout
        )

    def op_public_ip_delete(
        self,
        resource_group: str,
        name: str,
        confirmation: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_delete(
            "public_ip", resource_group, name, confirmation, poll_timeout
        )

    def op_nsg_list(
        self,
        resource_group: str = "",
        max_items: int = 500,
        max_pages: int = 50,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_list("nsg", resource_group, max_items, max_pages)

    def op_nsg_get(self, resource_group: str, name: str, **_: Any) -> dict[str, Any]:
        return self._network_get("nsg", resource_group, name)

    def op_nsg_create_or_update(
        self,
        resource_group: str,
        name: str,
        resource_json: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_put(
            "nsg", resource_group, name, resource_json, poll_timeout
        )

    def op_nsg_delete(
        self,
        resource_group: str,
        name: str,
        confirmation: str,
        poll_timeout: int = 1200,
        **_: Any,
    ) -> dict[str, Any]:
        return self._network_delete(
            "nsg", resource_group, name, confirmation, poll_timeout
        )

    # Storage management and artifact-confined blobs

    def op_storage_accounts_list(
        self,
        resource_group: str = "",
        max_items: int = 500,
        max_pages: int = 50,
        **_: Any,
    ) -> dict[str, Any]:
        service = self._storage_management_client().storage_accounts
        values = (
            service.list_by_resource_group(validate_resource_group(resource_group))
            if resource_group
            else service.list()
        )
        items, truncated = collect_pages(values, int(max_items), int(max_pages))
        return self._success(
            "storage_accounts_list", items=items, count=len(items), truncated=truncated
        )

    def op_storage_accounts_get(
        self, resource_group: str, name: str, **_: Any
    ) -> dict[str, Any]:
        result = self._storage_management_client().storage_accounts.get_properties(
            validate_resource_group(resource_group), validate_storage_account(name)
        )
        return self._success("storage_accounts_get", resource=result)

    def op_storage_accounts_create_or_update(
        self,
        resource_group: str,
        name: str,
        resource_json: str,
        poll_timeout: int = 1800,
        **_: Any,
    ) -> dict[str, Any]:
        poller = self._storage_management_client(True).storage_accounts.begin_create(
            validate_resource_group(resource_group),
            validate_storage_account(name),
            parse_object(resource_json, "resource_json"),
        )
        return self._finish(
            "storage_accounts_create_or_update", poller, int(poll_timeout)
        )

    def op_storage_accounts_delete(
        self, resource_group: str, name: str, confirmation: str, **_: Any
    ) -> dict[str, Any]:
        group, account = (
            validate_resource_group(resource_group),
            validate_storage_account(name),
        )
        target = self._resource_id(
            group, f"providers/Microsoft.Storage/storageAccounts/{account}"
        )
        require_confirmation(confirmation, "DELETE", target)
        self._storage_management_client(True).storage_accounts.delete(group, account)
        return self._success(
            "storage_accounts_delete", status="Succeeded", resource_id=target
        )

    def _blob_service(self, account: str, mutation: bool) -> Any:
        from azure.core.pipeline.policies import RetryPolicy
        from azure.storage.blob import BlobServiceClient

        account_name = validate_storage_account(account)
        return BlobServiceClient(
            account_url=f"https://{account_name}{self.profile.cloud.blob_suffix}",
            credential=self.credential,
            audience=self.profile.cloud.storage_scope.removesuffix("/.default"),
            retry_policy=RetryPolicy(retry_total=0 if mutation else 3),
            connection_timeout=10,
            read_timeout=30,
        )

    def op_blob_list(
        self,
        storage_account: str,
        container: str,
        prefix: str = "",
        max_items: int = 500,
        max_pages: int = 50,
        **_: Any,
    ) -> dict[str, Any]:
        validate_container(container)
        values = (
            self._blob_service(storage_account, False)
            .get_container_client(container)
            .list_blobs(name_starts_with=prefix)
        )
        items, truncated = collect_pages(values, int(max_items), int(max_pages))
        return self._success(
            "blob_list", items=items, count=len(items), truncated=truncated
        )

    def op_blob_upload(
        self,
        storage_account: str,
        container: str,
        blob_name: str,
        artifact_path: str,
        overwrite: bool = False,
        if_match: str = "",
        confirmation: str = "",
        **_: Any,
    ) -> dict[str, Any]:
        from azure.core import MatchConditions

        account = validate_storage_account(storage_account)
        container_name = validate_container(container)
        object_name = validate_blob_name(blob_name)
        if overwrite:
            if not if_match:
                raise AzurePackError("if_match ETag is required when overwrite is true")
            require_confirmation(
                confirmation,
                "OVERWRITE",
                f"blob://{account}/{container_name}/{object_name}",
            )
        client = self._blob_service(storage_account, True).get_blob_client(
            container=container_name, blob=object_name
        )
        kwargs: dict[str, Any] = {
            "overwrite": bool(overwrite),
            "max_concurrency": 2,
            "timeout": 60,
        }
        if if_match:
            kwargs.update(etag=if_match, match_condition=MatchConditions.IfNotModified)
        with open_artifact_file(artifact_path, "rb") as stream:
            result = client.upload_blob(stream, **kwargs)
        return self._success(
            "blob_upload",
            status="Succeeded",
            artifact_path=artifact_path,
            blob_name=blob_name,
            etag=getattr(result, "etag", None),
        )

    def op_blob_download(
        self,
        storage_account: str,
        container: str,
        blob_name: str,
        artifact_path: str,
        if_match: str = "",
        **_: Any,
    ) -> dict[str, Any]:
        from azure.core import MatchConditions

        client = self._blob_service(storage_account, False).get_blob_client(
            container=validate_container(container), blob=validate_blob_name(blob_name)
        )
        kwargs: dict[str, Any] = {"max_concurrency": 2, "timeout": 60}
        if if_match:
            kwargs.update(etag=if_match, match_condition=MatchConditions.IfNotModified)
        downloader = client.download_blob(**kwargs)
        try:
            with open_artifact_file(artifact_path, "xb") as stream:
                downloader.readinto(stream)
                size = stream.tell()
        except Exception:
            remove_artifact_file(artifact_path)
            raise
        return self._success(
            "blob_download",
            status="Succeeded",
            artifact_path=artifact_path,
            blob_name=blob_name,
            bytes=size,
        )

    # ARM deployments

    def op_deployment_validate(
        self,
        resource_group: str,
        name: str,
        deployment_json: str,
        poll_timeout: int = 900,
        **_: Any,
    ) -> dict[str, Any]:
        poller = self._deployment_client(True).deployments.begin_validate(
            validate_resource_group(resource_group),
            validate_name(name),
            parse_object(deployment_json, "deployment_json"),
        )
        return self._finish("deployment_validate", poller, int(poll_timeout))

    def op_deployment_create_or_update(
        self,
        resource_group: str,
        name: str,
        deployment_json: str,
        confirmation: str,
        poll_timeout: int = 3600,
        **_: Any,
    ) -> dict[str, Any]:
        group, deployment = validate_resource_group(resource_group), validate_name(name)
        target = self._resource_id(
            group, f"providers/Microsoft.Resources/deployments/{deployment}"
        )
        require_confirmation(confirmation, "DEPLOY", target)
        poller = self._deployment_client(True).deployments.begin_create_or_update(
            group,
            deployment,
            parse_object(deployment_json, "deployment_json"),
        )
        return self._finish("deployment_create_or_update", poller, int(poll_timeout))

    def op_deployment_status(
        self, resource_group: str, name: str, **_: Any
    ) -> dict[str, Any]:
        result = self._deployment_client().deployments.get(
            validate_resource_group(resource_group), validate_name(name)
        )
        return self._success("deployment_status", resource=result)

    def op_deployment_delete(
        self,
        resource_group: str,
        name: str,
        confirmation: str,
        poll_timeout: int = 1800,
        **_: Any,
    ) -> dict[str, Any]:
        group, deployment = validate_resource_group(resource_group), validate_name(name)
        target = self._resource_id(
            group, f"providers/Microsoft.Resources/deployments/{deployment}"
        )
        require_confirmation(confirmation, "DELETE", target)
        return self._finish(
            "deployment_delete",
            self._deployment_client(True).deployments.begin_delete(group, deployment),
            int(poll_timeout),
        )

    # Key Vault secrets: values are accepted only for set and never returned.

    def _secret_client(self, vault_name: str, mutation: bool) -> Any:
        from azure.core.pipeline.policies import RetryPolicy
        from azure.keyvault.secrets import SecretClient

        vault = validate_vault(vault_name)
        return SecretClient(
            vault_url=f"https://{vault}{self.profile.cloud.vault_suffix}",
            credential=self.credential,
            verify_challenge_resource=True,
            retry_policy=RetryPolicy(retry_total=0 if mutation else 3),
            connection_timeout=10,
            read_timeout=30,
        )

    def op_keyvault_secret_set(
        self,
        vault_name: str,
        name: str,
        secret_value: str,
        content_type: str = "",
        tags_json: str = "{}",
        **_: Any,
    ) -> dict[str, Any]:
        result = self._secret_client(vault_name, True).set_secret(
            validate_name(name),
            secret_value,
            content_type=content_type or None,
            tags=parse_object(tags_json, "tags_json"),
        )
        properties = result.properties
        return self._success(
            "keyvault_secret_set",
            status="Succeeded",
            id=str(properties.id),
            name=properties.name,
            version=properties.version,
            enabled=properties.enabled,
        )

    def op_keyvault_secret_delete(
        self,
        vault_name: str,
        name: str,
        confirmation: str,
        poll_timeout: int = 900,
        **_: Any,
    ) -> dict[str, Any]:
        vault, secret = validate_vault(vault_name), validate_name(name)
        target = f"https://{vault}{self.profile.cloud.vault_suffix}/secrets/{secret}"
        require_confirmation(confirmation, "DELETE", target)
        poller = self._secret_client(vault, True).begin_delete_secret(secret)
        result = poller.result(timeout=int(poll_timeout))
        return self._success(
            "keyvault_secret_delete",
            status="Succeeded",
            id=str(result.id),
            name=result.name,
        )

    def op_keyvault_secret_list_metadata(
        self, vault_name: str, max_items: int = 500, max_pages: int = 50, **_: Any
    ) -> dict[str, Any]:
        values = self._secret_client(vault_name, False).list_properties_of_secrets()
        items, truncated = collect_pages(values, int(max_items), int(max_pages))
        return self._success(
            "keyvault_secret_list_metadata",
            items=items,
            count=len(items),
            truncated=truncated,
        )

    # Microsoft Graph v1.0

    def _graph_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def _graph_request(
        self,
        method: str,
        path_or_url: str,
        *,
        body: dict[str, Any] | None = None,
        retry_read: bool = True,
    ) -> Any:
        base = f"{self.profile.cloud.graph}/v1.0"
        url = (
            validate_service_url(path_or_url, self.profile.cloud.graph)
            if path_or_url.startswith("http")
            else f"{base}/{path_or_url.lstrip('/')}"
        )
        token = self.credential.get_token(self.profile.cloud.graph_scope).token
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        attempts = 3 if method == "GET" and retry_read else 1
        response = None
        for attempt in range(attempts):
            try:
                response = self._graph_session().request(
                    method,
                    url,
                    headers=headers,
                    json=body,
                    timeout=(10, 30),
                    verify=True,
                    allow_redirects=False,
                )
            except Exception as exc:  # noqa: BLE001 - hide transport details and credentials.
                raise AzurePackError(
                    f"Microsoft Graph transport failed: {exc.__class__.__name__}"
                ) from None
            if (
                response.status_code not in READ_RETRY_STATUSES
                or attempt + 1 == attempts
            ):
                break
            retry_after = response.headers.get("Retry-After", "1")
            try:
                delay = min(max(float(retry_after), 0.0), 30.0)
            except ValueError:
                delay = min(2**attempt, 30)
            self._sleep(delay)
        assert response is not None
        if not 200 <= response.status_code < 300:
            code, message = (
                f"HTTP_{response.status_code}",
                "Microsoft Graph request failed",
            )
            try:
                error = response.json().get("error", {})
                code = str(error.get("code", code))[:100]
                message = str(error.get("message", message))[:300]
            except (TypeError, ValueError, AttributeError):
                pass
            raise AzurePackError(
                f"Microsoft Graph {code}: {redact(message, self.profile.secrets)}"
            )
        if response.status_code == 204 or not getattr(response, "content", b""):
            return None
        return response.json()

    def _graph_pages(
        self, path: str, max_items: int, max_pages: int
    ) -> tuple[list[Any], bool]:
        if not 1 <= int(max_items) <= 1000 or not 1 <= int(max_pages) <= 100:
            raise AzurePackError(
                "max_items must be 1..1000 and max_pages must be 1..100"
            )
        items: list[Any] = []
        next_url: str | None = path
        page = 0
        truncated = False
        while next_url:
            page += 1
            if page > int(max_pages):
                truncated = True
                break
            payload = self._graph_request("GET", next_url)
            for item in payload.get("value", []):
                if len(items) >= int(max_items):
                    truncated = True
                    break
                items.append(item)
            if truncated:
                break
            next_url = payload.get("@odata.nextLink")
            if next_url:
                validate_service_url(next_url, self.profile.cloud.graph)
        return items, truncated

    @staticmethod
    def _object_id(value: str, field: str) -> str:
        from .security import UUID_RE

        if not UUID_RE.fullmatch(value):
            raise AzurePackError(f"{field} must be a UUID")
        return value

    def op_graph_users_list(
        self, max_items: int = 500, max_pages: int = 50, **_: Any
    ) -> dict[str, Any]:
        items, truncated = self._graph_pages(
            f"users?$select={GRAPH_USER_FIELDS}&$top=100",
            int(max_items),
            int(max_pages),
        )
        return self._success(
            "graph_users_list", items=items, count=len(items), truncated=truncated
        )

    def op_graph_users_get(self, user_id: str, **_: Any) -> dict[str, Any]:
        uid = self._object_id(user_id, "user_id")
        result = self._graph_request("GET", f"users/{uid}?$select={GRAPH_USER_FIELDS}")
        return self._success("graph_users_get", resource=result)

    def op_graph_users_create(
        self,
        user_principal_name: str,
        display_name: str,
        mail_nickname: str,
        initial_password: str,
        account_enabled: bool = False,
        **_: Any,
    ) -> dict[str, Any]:
        if (
            not user_principal_name
            or "@" not in user_principal_name
            or len(user_principal_name) > 113
        ):
            raise AzurePackError("invalid user_principal_name")
        body = {
            "accountEnabled": bool(account_enabled),
            "displayName": display_name,
            "mailNickname": validate_name(mail_nickname, "mail_nickname"),
            "userPrincipalName": user_principal_name,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": True,
                "password": initial_password,
            },
        }
        result = self._graph_request("POST", "users", body=body, retry_read=False)
        safe_result = {
            key: value for key, value in result.items() if key != "passwordProfile"
        }
        return self._success(
            "graph_users_create", status="Succeeded", resource=safe_result
        )

    def op_graph_users_update(
        self, user_id: str, changes_json: str, **_: Any
    ) -> dict[str, Any]:
        allowed = {
            "displayName",
            "jobTitle",
            "department",
            "officeLocation",
        }
        changes = parse_object(changes_json, "changes_json")
        if not changes or set(changes) - allowed:
            raise AzurePackError(
                f"changes_json fields must be a non-empty subset of: {', '.join(sorted(allowed))}"
            )
        uid = self._object_id(user_id, "user_id")
        self._graph_request("PATCH", f"users/{uid}", body=changes, retry_read=False)
        return self._success("graph_users_update", status="Succeeded", id=uid)

    def op_graph_users_delete(
        self, user_id: str, confirmation: str, **_: Any
    ) -> dict[str, Any]:
        uid = self._object_id(user_id, "user_id")
        require_confirmation(confirmation, "DELETE", f"graph:user:{uid}")
        self._graph_request("DELETE", f"users/{uid}", retry_read=False)
        return self._success("graph_users_delete", status="Succeeded", id=uid)

    def op_graph_groups_list(
        self, max_items: int = 500, max_pages: int = 50, **_: Any
    ) -> dict[str, Any]:
        items, truncated = self._graph_pages(
            f"groups?$select={GRAPH_GROUP_FIELDS}&$top=100",
            int(max_items),
            int(max_pages),
        )
        return self._success(
            "graph_groups_list", items=items, count=len(items), truncated=truncated
        )

    def op_graph_groups_get(self, group_id: str, **_: Any) -> dict[str, Any]:
        gid = self._object_id(group_id, "group_id")
        result = self._graph_request(
            "GET", f"groups/{gid}?$select={GRAPH_GROUP_FIELDS}"
        )
        return self._success("graph_groups_get", resource=result)

    def op_graph_groups_create(
        self, display_name: str, mail_nickname: str, description: str = "", **_: Any
    ) -> dict[str, Any]:
        body = {
            "displayName": display_name,
            "description": description or None,
            "mailEnabled": False,
            "mailNickname": validate_name(mail_nickname, "mail_nickname"),
            "securityEnabled": True,
            "isAssignableToRole": False,
        }
        result = self._graph_request("POST", "groups", body=body, retry_read=False)
        return self._success("graph_groups_create", status="Succeeded", resource=result)

    def op_graph_groups_update(
        self, group_id: str, changes_json: str, **_: Any
    ) -> dict[str, Any]:
        allowed = {"displayName", "description"}
        changes = parse_object(changes_json, "changes_json")
        if not changes or set(changes) - allowed:
            raise AzurePackError(
                "changes_json fields must be displayName and/or description"
            )
        gid = self._object_id(group_id, "group_id")
        self._graph_request("PATCH", f"groups/{gid}", body=changes, retry_read=False)
        return self._success("graph_groups_update", status="Succeeded", id=gid)

    def op_graph_groups_delete(
        self, group_id: str, confirmation: str, **_: Any
    ) -> dict[str, Any]:
        gid = self._object_id(group_id, "group_id")
        require_confirmation(confirmation, "DELETE", f"graph:group:{gid}")
        self._assert_group_not_role_assignable(gid)
        self._graph_request("DELETE", f"groups/{gid}", retry_read=False)
        return self._success("graph_groups_delete", status="Succeeded", id=gid)

    def _assert_group_not_role_assignable(self, group_id: str) -> None:
        group = self._graph_request(
            "GET", f"groups/{group_id}?$select=id,isAssignableToRole"
        )
        if group.get("isAssignableToRole") is not False:
            raise AzurePackError(
                "role-assignable groups are outside this pack's mutation boundary"
            )

    def op_graph_memberships_list(
        self, group_id: str, max_items: int = 500, max_pages: int = 50, **_: Any
    ) -> dict[str, Any]:
        gid = self._object_id(group_id, "group_id")
        items, truncated = self._graph_pages(
            f"groups/{gid}/members?$select=id,displayName&$top=100",
            int(max_items),
            int(max_pages),
        )
        return self._success(
            "graph_memberships_list", items=items, count=len(items), truncated=truncated
        )

    def op_graph_memberships_add(
        self,
        group_id: str,
        member_id: str,
        member_kind: str,
        confirmation: str,
        **_: Any,
    ) -> dict[str, Any]:
        gid, mid = (
            self._object_id(group_id, "group_id"),
            self._object_id(member_id, "member_id"),
        )
        if member_kind not in {"user", "group"}:
            raise AzurePackError("member_kind must be user or group")
        self._assert_group_not_role_assignable(gid)
        endpoint = "users" if member_kind == "user" else "groups"
        if member_kind == "group":
            self._assert_group_not_role_assignable(mid)
        else:
            self._graph_request("GET", f"{endpoint}/{mid}?$select=id")
        require_confirmation(
            confirmation, "ADD", f"graph:{member_kind}:{mid} TO graph:group:{gid}"
        )
        body = {"@odata.id": f"{self.profile.cloud.graph}/v1.0/directoryObjects/{mid}"}
        self._graph_request(
            "POST", f"groups/{gid}/members/$ref", body=body, retry_read=False
        )
        return self._success(
            "graph_memberships_add", status="Succeeded", group_id=gid, member_id=mid
        )

    def op_graph_memberships_remove(
        self, group_id: str, member_id: str, confirmation: str, **_: Any
    ) -> dict[str, Any]:
        gid, mid = (
            self._object_id(group_id, "group_id"),
            self._object_id(member_id, "member_id"),
        )
        self._assert_group_not_role_assignable(gid)
        require_confirmation(
            confirmation, "REMOVE", f"graph:member:{mid} FROM graph:group:{gid}"
        )
        self._graph_request(
            "DELETE", f"groups/{gid}/members/{mid}/$ref", retry_read=False
        )
        return self._success(
            "graph_memberships_remove", status="Succeeded", group_id=gid, member_id=mid
        )
