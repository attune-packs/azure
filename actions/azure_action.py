"""Single audited entry point used by the pack's declarative action contracts."""

from lib.runtime import Runtime
from lib.security import AzurePackError
from st2common.runners.base_action import Action


class AzureAction(Action):
    def run(self, operation, profile=None, **kwargs):
        profile_value = profile
        if not profile_value:
            raise AzurePackError(
                "profile must be supplied from the pack-owned Attune Key azure_profile"
            )
        runtime = Runtime(profile_value)
        try:
            return runtime.execute(operation, **kwargs)
        finally:
            runtime.close()
