# Codex 0.145.0 app-server schemas

These files are an exact subset of the JSON Schemas generated locally by the
content-pinned `codex-cli 0.145.0` binary with experimental APIs enabled.
Generation used an empty Codex home, no authentication mount, and no network;
it did not initialize a thread or invoke a provider.

`manifest.json` binds every packaged byte and also records the identity of the
complete generated v2 bundle from which this lifecycle subset was selected.
Runtime protocol authority verifies the packaged files against this manifest.
