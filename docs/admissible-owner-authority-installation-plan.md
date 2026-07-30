# Owner-authority installation readiness

**Status: NOT EXECUTED.** This plan is generated from the authoritative installer
and related modules. No host privilege was used by the implementation task, no
system service was installed or started, nothing under `/etc`, `/var` or `/run`
was created or modified, Docker Desktop integration was not enabled, and the
dedicated launcher account was not created.

Regenerate the exact plan at any time (unprivileged):

```
python3 -m admissible.capsule.owner_authority.installer plan \
    --authorized-launcher admissible-launcher
python3 -m admissible.capsule.owner_authority.installer plan \
    --authorized-launcher admissible-launcher --json
python3 -m admissible.capsule.owner_authority.host_readiness
```

## WSL / systemd / `/run` notes

This workspace is WSL2 with systemd. `/run` is typically tmpfs: a WSL or
distro restart clears runtime sockets and the broker unit must recreate them
on start. Stale-socket cleanup may unlink only an exact dead `0660`
root-owned socket whose group matches the authorized launcher gid from the
durable installation record, after validating the parent runtime directory
without following symlinks and re-checking device/inode identity immediately
before deletion. Unexpected sockets (including mode `0777`), symlinks,
non-sockets, live listeners and identity mismatches refuse closed and are
retained. Do not treat a missing
`/run/admissible-owner-authority-v1/broker.sock` after reboot as durable state
loss — authorization state lives under `/var/lib`.

## Exact host setup order

### 1. Enable Docker Desktop WSL integration

On Windows Docker Desktop: Settings → Resources → WSL Integration → enable the
Ubuntu distro used by this workspace. Then verify inside the distro:

```
docker info
ls -l /var/run/docker.sock
```

### 2. Verify Docker and controller identity

Record the socket/controller identity after Docker works. The full
Docker/security suite is host-setup blocked until this succeeds.

### 3. Build the deterministic application environment (wheel/zipapp) twice

```
python3 -m admissible.capsule.owner_authority.deployment_artifact \
  build --output /tmp/admissible-broker-a.pyz
python3 -m admissible.capsule.owner_authority.deployment_artifact \
  build --output /tmp/admissible-broker-b.pyz
sha256sum /tmp/admissible-broker-a.pyz /tmp/admissible-broker-b.pyz
cmp /tmp/admissible-broker-a.pyz /tmp/admissible-broker-b.pyz
cp /tmp/admissible-broker-a.pyz /tmp/admissible-broker.pyz
```

The immutable root-owned application environment is published later to:

`/opt/admissible-owner-authority-v1/broker.pyz`

The systemd unit must invoke that exact path. It must not use cwd,
`PYTHONPATH`, editable installs, or `/home/stris`.

### 4. Create the dedicated launcher identity

```
sudo groupadd --system admissible-launcher
sudo useradd --system --gid admissible-launcher --home-dir /nonexistent \
  --shell /usr/sbin/nologin --comment 'Admissible boundary launcher' \
  admissible-launcher
id admissible-launcher
groups admissible-launcher
! id -nG admissible-launcher | tr ' ' '\n' | grep -Ex 'sudo|docker|wheel|root'
```

The launcher must not be in `sudo` or `docker`. Do not use `stris` (or any
root-equivalent account) as the production launcher.

### 5. Validate launcher and host readiness (read-only)

```
python3 -m admissible.capsule.owner_authority.installer plan \
  --authorized-launcher admissible-launcher
python3 -c "from admissible.capsule.owner_authority import validate_launcher_username as v; print(v('admissible-launcher'))"
python3 -m admissible.capsule.owner_authority.host_readiness
```

### 6. Conflict checks before mutation

```
python3 -m admissible.capsule.owner_authority.installer preinstall-checks
```

### 7. Review the exact install plan from code

```
python3 -m admissible.capsule.owner_authority.installer plan \
  --authorized-launcher admissible-launcher
```

### 8. One transactional privileged install

```
sudo python3 -m admissible.capsule.owner_authority.installer install \
  --authorized-launcher admissible-launcher \
  --deployment-artifact /tmp/admissible-broker.pyz \
  --deployment-artifact-sha256 <audited-sha256>
```

The installer stages under a journaled transaction, refuses pre-existing
targets and symlinks, publishes only after directories, signing identity,
installation record, application environment and unit file are fsynced, and
rolls back staged objects on any failure before publication. A private key is
never left without a corresponding durable installation record.

### 9. daemon-reload, enable and start

```
sudo systemctl daemon-reload
sudo systemctl enable admissible-owner-authority-broker-v1.service
sudo systemctl start admissible-owner-authority-broker-v1.service
```

The unit uses `Type=notify`, `Restart=on-failure`, bounded `RestartSec=2`, and
`ExecStart=/usr/bin/python3 /opt/admissible-owner-authority-v1/broker.pyz`
with `ProtectHome=yes`.

### 10. Wait for mechanical readiness

```
sudo systemctl status admissible-owner-authority-broker-v1.service
python3 -m admissible.capsule.owner_authority.installer verify
python3 -m admissible.capsule.owner_authority.host_readiness
```

### 11. Provider-free installation audit

Only claim pytest when it is present on the host. Preferred invocation:

```
python3 -m pytest \
  tests/test_admissible_capsule_external_owner_authority.py \
  tests/test_admissible_capsule_owner_authority_install_repair.py \
  tests/test_admissible_capsule_owner_authority_privilege_witness.py
tests/run_capsule_suite_in_namespace.sh
```

Do not pass a broad `tests/test_admissible_capsule_*.py` glob to the namespace
wrapper; call it without path arguments so it selects the owner-authority
files itself.

### 12. Docker/security suite (after Docker works)

```
python3 -m pytest tests/test_admissible_capsule_os_boundary.py \
  tests/test_admissible_capsule_owner_bound_rehearsal.py \
  tests/test_admissible_capsule_owner_rooted_witness_trust.py
```

### 13. Auth-wrapper verification

```
python3 -m admissible.capsule.owner_authority.auth_wrapper render-runbook
python3 -m admissible.capsule.owner_authority.auth_wrapper validate-plan \
  --durable-auth-source <durable-chatgpt-auth.json> \
  --launcher admissible-launcher
```

### 14. canary-preflight-v2

Only after steps 1–13 succeed.

## Safe no-echo phrase provisioning

Stdin remains a terminal for fingerprint confirmation. The phrase arrives only
on FD 3 via a non-echoing reader outside the privileged process. Never use
`3<&0` or `3< <(cat)`.

```
exec 3< <(
  systemd-ask-password --echo=no "Owner authorization phrase:"
)
sudo python3 -m admissible.capsule.owner_authority.provisioner provision \
  --owner-payload <payload.json> \
  --phrase-fd 3
exec 3<&-
```

The same command is emitted by
`admissible.capsule.owner_authority.provisioner.phrase_fd_from_ask_password()`.

Preview first (unprivileged):

```
python3 -m admissible.capsule.owner_authority.provisioner summarize \
  --owner-payload <payload.json>
```

Missing, null or malformed required summary fields refuse before phrase
consumption.

## OpenSSL update continuity (key-preserving)

```
sudo python3 -m admissible.capsule.owner_authority.crypto_revision authorize \
  --executable-path /usr/bin/openssl \
  --confirm-sha256 <new-openssl-sha256> \
  --confirm-version <version-string> \
  --acknowledge-explicit-reattestation
```

Never rotates or exposes the signing private key. Automatic drift on the hot
signing path is refused; only this explicit re-attestation may advance the
append-only revision history. Historical receipts remain verifiable.

## Rollback of a failed / incomplete install

```
sudo python3 -m admissible.capsule.owner_authority.installer rollback-failed-install
```

Removes only objects belonging to an incomplete installation. Idempotent. Does
not destroy an established signing identity (use uninstall for that).

## Uninstall of a committed installation

```
sudo systemctl stop admissible-owner-authority-broker-v1.service
sudo systemctl disable admissible-owner-authority-broker-v1.service
sudo python3 -m admissible.capsule.owner_authority.installer uninstall \
  --preserve-signing-identity --acknowledge-destructive-pending-state
# or, destroying the signing identity (prior receipts become unverifiable):
sudo python3 -m admissible.capsule.owner_authority.installer uninstall \
  --destroy-signing-identity --acknowledge-destructive-pending-state
sudo systemctl daemon-reload
```

Uninstall inventories pending / phrase-verified / consumed / receipted
authorizations, refuses while authorization state exists unless the explicit
destructive acknowledgement is supplied, removes the unit, runtime state,
application environment and installation roots, and performs residue
verification. No physical-media secure-erasure claim is made.

Dedicated launcher account removal is a separate explicit owner action after
verify reports no remaining installation references:

```
sudo userdel admissible-launcher
sudo groupdel admissible-launcher
```

## Remaining host-setup blockers

- Docker Desktop WSL integration for this distro
- Creation of `admissible-launcher`
- Privileged production install under `/etc`, `/var`, `/run`, `/opt`
- Full Docker/security suite gate
- Durable ChatGPT auth source + privileged-open wrapper install

Until those are performed by the owner, host readiness correctly reports
`HOST_PREREQUISITES_MISSING` / canary
`CANARY_EXTERNAL_OWNER_ROOT_REQUIRES_HOST_SETUP`.
