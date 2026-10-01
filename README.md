# Microsoft Azure Attune Pack

Production-oriented Azure automation using current split Azure SDK packages,
`azure-identity`, Microsoft Graph REST `v1.0`, Key Vault, and Blob Storage.
The pack deliberately does not carry forward Azure AD Graph, `azurerm`, bundled
`azure-mgmt`, libcloud, certificate-file authentication, or stale upstream
action names.

## Authentication

Create one encrypted, pack-owned Attune Key named `azure_profile`, then bind its
JSON value to each action's secret `profile` parameter through your Attune
workflow or policy secret binding. Do not put profiles or client secrets in
pack files, workflow source, command history, logs, or artifacts.

Managed identity is the preferred production profile:

```sh
attune key create --local-ref azure_profile --name "Azure profile" --encrypt \
  --owner-type pack --owner-pack-ref azure \
  --value '{"cloud":"public","auth_mode":"managed_identity","subscription_id":"00000000-0000-0000-0000-000000000000","managed_identity_client_id":"11111111-1111-1111-1111-111111111111"}'
```

The CLI example contains no credential. If a static service-principal secret is
unavoidable, provision the encrypted key through an approved secrets channel
instead of placing `client_secret` on a command line.

Supported `auth_mode` values:

| Mode | Required profile fields | Notes |
| --- | --- | --- |
| `default` | optional `subscription_id` | `DefaultAzureCredential`; interactive browser disabled |
| `managed_identity` | optional `managed_identity_client_id`, operation-specific `subscription_id` | Preferred on Azure |
| `workload_identity` | `tenant_id`, `client_id`, absolute `workload_token_file` | Federated token file must already exist |
| `service_principal` | `tenant_id`, `client_id`, `client_secret` | Static secret fallback only |

Tenant, client, and subscription IDs are distinct UUID fields. A subscription
ID is required only for ARM operations; Microsoft Graph operations use the
tenant identity and never infer a subscription.

## Clouds And Audiences

Only fixed Azure cloud profiles are accepted. Callers cannot provide endpoint
URLs.

| Profile | ARM | Graph | Blob suffix | Key Vault suffix |
| --- | --- | --- | --- | --- |
| `public` | `management.azure.com` | `graph.microsoft.com` | `.blob.core.windows.net` | `.vault.azure.net` |
| `usgov` | `management.usgovcloudapi.net` | `graph.microsoft.us` | `.blob.core.usgovcloudapi.net` | `.vault.usgovcloudapi.net` |
| `usdod` | `management.usgovcloudapi.net` | `dod-graph.microsoft.us` | `.blob.core.usgovcloudapi.net` | `.vault.usgovcloudapi.net` |
| `china` | `management.chinacloudapi.cn` | `microsoftgraph.chinacloudapi.cn` | `.blob.core.chinacloudapi.cn` | `.vault.azure.cn` |

ARM, Graph, Storage, and Key Vault use distinct token audiences. TLS
verification is mandatory. Graph continuation URLs are revalidated against the
selected cloud and `/v1.0`; redirects are disabled.

## Action Surface

- Subscriptions: list.
- Resource groups: list, get, create/update, delete.
- Virtual machines: list, get with instance view, create/update, start, stop,
  deallocate, restart, delete. SDK long-running pollers are always awaited with
  a bounded `poll_timeout`.
- Network: virtual networks, subnets, network interfaces, public IP addresses,
  and network security groups with list/get/create-update/delete actions.
- Storage accounts: list/get/create/delete. Blobs: list metadata, upload, and
  download.
- ARM deployments: validate, create/update, status, and delete history.
- Key Vault: set secret, delete secret, and list metadata. Secret-value
  retrieval is intentionally omitted.
- Microsoft Graph: selected user/group reads, constrained user/group writes,
  and direct membership list/add/remove using current Graph `v1.0` endpoints.

All JSON object inputs are strings such as `resource_json`, `deployment_json`,
or `changes_json`, keeping top-level action contracts flat. Outputs always
contain `ok` and `operation`, plus structured `resource`, `items`, `status`,
`count`, or artifact metadata as appropriate.

## Safety Contracts

- Every delete and ARM deployment requires an exact target-specific
  `confirmation` shown by the action's validation error. Membership changes
  require exact `ADD ... TO ...` or `REMOVE ... FROM ...` confirmation. Blob
  replacement requires both an ETag and exact `OVERWRITE ...` confirmation.
- VM create/update and blob replacement accept supported ETags; HTTP 412
  conflicts are failures. Current Graph directory write documentation does not
  advertise conditional headers, so Graph writes are never retried and use
  confirmation where destructive. Graph reads retry at most twice after the
  first attempt and honor a clamped `Retry-After`.
- Azure SDK mutation clients have retries disabled. SDK reads have bounded
  retries. HTTP connection/read timeouts and LRO deadlines are bounded.
- Graph group mutation refuses role-assignable groups. User updates cannot
  change passwords, account state, roles, or authorization fields. Group
  updates are limited to name and description. Membership accepts only verified
  users or groups, never arbitrary directory object types.
- Blob account endpoints are constructed from validated names and cloud
  suffixes. Upload/download paths must be relative to the worker-provided
  `ATTUNE_ARTIFACT_DIR`; parent traversal and symlinks are rejected. Downloads
  use exclusive creation and never overwrite an artifact.
- Client secrets, password fields, bearer tokens, storage keys, SAS fields, and
  known secret values are redacted from structured results and exceptions.

Confirmation example for VM deletion:

```text
DELETE /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01
```

## Least Privilege

Grant only roles required by selected actions. Typical data-plane roles are
`Storage Blob Data Reader` or `Storage Blob Data Contributor`, and `Key Vault
Secrets Officer` for secret mutation. Use scoped ARM roles at subscription,
resource-group, or resource level as appropriate, noting that Azure LRO status
URLs can require resource-group permission.

For Microsoft Graph application permissions, separate read-only automation from
writers. Use the narrow combination needed, such as `User.Read.All`,
`User.ReadUpdate.All` for allowlisted profile updates, `User.ReadWrite.All` for
create/delete, `Group.Read.All`, `Group.ReadWrite.All`, or
`GroupMember.ReadWrite.All`. Do not grant directory-role management permissions
or broad `Directory.ReadWrite.All` merely to run this pack. Admin consent and
conditional-access policy remain tenant administrator responsibilities.

Microsoft Graph user/group `v1.0` writes currently lack documented ETag
preconditions. This is an upstream concurrency gap; this pack does not claim an
unsupported guarantee. Keep write identities narrowly scoped and use execution
audit records plus target-specific confirmations.

## Development

Tests use only the Python standard library and deterministic fakes. They do not
load Azure credentials or make network calls.

```sh
python -m unittest discover -s tests -v
python -m compileall -q actions tests
attune pack check /home/david/Codebase/attune-packs/azure
attune pack test /home/david/Codebase/attune-packs/azure
```

See `SOURCE_METADATA.json` and `NOTICE` for exact attributed source and
Microsoft documentation revisions. The upstream StackStorm pack is a
requirements source only; this is a clean implementation.
