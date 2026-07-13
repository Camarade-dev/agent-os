"""Admissible execution helpers with lazy legacy exports.

Keeping this package initializer import-free lets the isolated V0 controller
consume ``bounded_write`` without loading the legacy evidence/run-loop stack.
The established public exports remain available on first access.
"""

from __future__ import annotations

from importlib import import_module


_LOCAL_EXPORTS = {
    "BoundedWriteError",
    "BoundedWriteRequest",
    "BoundedWriteResult",
    "CompletedWriteInterruption",
    "PhysicalAttestationError",
    "PhysicalFileFacts",
    "WorkspaceAuthorityDescriptor",
    "attest_completed_write_against_original_authority",
    "attest_physical_file",
    "execute_bounded_write",
    "revalidate_workspace_authority",
    "validate_bounded_write_content",
}
_LEGACY_EXPORTS = {
    "ALLOWED_BOUNDED_OPERATIONS", "DIAG_FORBIDDEN_OPERATION_CATEGORY", "DIAG_NOT_ADMITTED",
    "DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION", "DIAG_NO_WORKSPACE_CONFIGURED",
    "DIAG_PATH_OUTSIDE_WORKSPACE", "DIAG_REFUSED_DECISION", "DIAG_UNSUPPORTED_OPERATION",
    "BoundedExecutionResult", "BoundedLocalExecutor", "assess_bounded_execution_eligibility",
    "execute_bounded_local_action", "extract_structured_operations", "validate_relative_path_inside_workspace",
    "validate_workspace_path",
}
_VERIFICATION_EXPORTS = {
    "ALLOWED_VERIFICATION_CHECKS", "ALLOWED_VERIFICATION_PROFILES", "BoundedVerificationError",
    "VerificationEvidence", "VerificationRequest", "VerificationResult", "default_requests_for_profile",
    "run_bounded_verification", "run_single_verification_check", "validate_verification_request",
}


def __getattr__(name: str):
    if name in _LOCAL_EXPORTS:
        return getattr(import_module("admissible.execution.bounded_write"), name)
    if name in _LEGACY_EXPORTS:
        return getattr(import_module("admissible.execution.bounded_local_executor"), name)
    if name in _VERIFICATION_EXPORTS:
        return getattr(import_module("admissible.execution.bounded_local_verification"), name)
    raise AttributeError(name)


__all__ = sorted(_LOCAL_EXPORTS | _LEGACY_EXPORTS | _VERIFICATION_EXPORTS)
