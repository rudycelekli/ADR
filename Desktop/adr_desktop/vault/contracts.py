"""Errors and codes that cross the boundary between Desktop and the vault."""


class NativeUnavailable(RuntimeError):
    pass


class NativeTimedOut(NativeUnavailable):
    pass


# Closed, content-free codes the vault and the native host report, with the message an agent sees for
# each. Any other error text is never reflected to an agent.
SAFE_ERRORS = {
    "known_malicious_artifact": (
        "ADR blocked a known malicious artifact. Open Malicious artifacts in ADR to review the match."
    ),
    "keychain_unavailable": (
        "ADR could not access the saved credential in macOS Keychain. "
        "Unlock Keychain and allow the ADR app to use the item, then try again."
    ),
    "credential_check_timeout": (
        "ADR's credential check timed out. Open Credential vault in ADR to check its storage status."
    ),
    "credential_check_unavailable": (
        "ADR could not check the saved credentials. Open the ADR menu-bar app and try again."
    ),
    "invalid_environment_credential": "ADR could not load a saved credential. Review its entry in the vault.",
    "invalid_credential_id": "ADR could not find the saved credential. Review its entry in the vault.",
    "local_vault_missing": (
        "This credential is not in ADR's local vault yet. Open Credential vault and move the old "
        "Keychain entry, or save the value again. No extra agent configuration is needed."
    ),
    "local_vault_corrupt": (
        "A saved local credential could not be verified. Review that entry in ADR; it was not replaced."
    ),
    "local_vault_key_missing": (
        "ADR's local vault key is missing. Restore the complete vault backup or re-enter the credentials."
    ),
    "local_vault_key_invalid": (
        "ADR's local vault key is invalid. Review the vault in ADR; no key was replaced."
    ),
    "local_vault_unsafe_path": "ADR could not safely open its vault files. Review the local profile in ADR.",
    "local_vault_permissions": "ADR's vault files need owner-only access. Review the local profile in ADR.",
    "local_vault_too_large": "A local vault record exceeded its supported size. Review that entry in ADR.",
    "local_vault_unavailable": "ADR's local credential store is unavailable. Open the ADR menu-bar app.",
    "local_vault_busy": "ADR's credential store is busy with another operation. Wait for it to finish.",
    "local_vault_exists": "This credential already has a local copy. Refresh the vault before trying again.",
    "local_vault_write_uncertain": (
        "ADR could not confirm the credential save. "
        "Refresh vault storage before retrying or deleting anything."
    ),
    "credential_removed_during_save": (
        "This credential was removed while its save was pending. It was not reactivated."
    ),
    "vault_migration_busy": (
        "A previous credential move is still finishing. Close any pending Keychain dialog before retrying."
    ),
    "vault_migration_expired": "The credential move expired. Refresh storage before explicitly trying again.",
    "vault_migration_cancelled": (
        "The credential move was cancelled. Refresh storage to see which copies completed."
    ),
    "vault_migration_invalidated": "This entry was removed while the credential move was pending.",
}
