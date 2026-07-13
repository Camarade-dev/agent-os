# Admissible V0 trusted executor boundary

`V0ControllerEngine.tick()` does not accept a raw bounded-execution completion.
Only a configured `V0BoundedExecutorAdapter` may receive the persisted
in-flight execution command, immutable admitted batch, and guard-validated
workspace targets. Its immutable result envelope is consumed by
`consume_trusted_execution_result()`, which checks the persisted single-use
capability before creating V0's internal reducer event.

The capability is persisted with the execution command and binds the session,
issuance revision, command, batch, and invocation. Once the event is consumed,
the command is settled and the capability cannot be replayed. Physical target
identities are derived by `WorkspaceGuard`, retained in materialized evidence,
and checked against all earlier evidence in the same session.

This is deliberately an in-process trusted API boundary. It prevents accidental
or normal-path evidence fabrication. It is not a cryptographic defence against
arbitrary malicious Python code already running in the same process.
