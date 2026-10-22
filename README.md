# aws-cli-zsp for Windows

**Zero Standing Permissions for the AWS keys on your PC.** No readable key in `~/.aws`. Every session expires on its own. Windows Hello approves each one, and the prompt names the key, how long, and which command asked.

```
Unlock AWS key 'prod' for a 1-hour READ-ONLY session.
Requested by: aws s3 rm s3://prod-backups --recursive ← pwsh
```

If you didn't type that, press Cancel.

A Windows port and extension of Andrew Baker's macOS [aws-cli-zsp](https://andrewbaker.ninja/2026/10/20/aws-cli-zsp-zero-standing-permissions-for-aws-keys-on-your-mac/): the Secure Enclave becomes the TPM, Touch ID becomes Windows Hello. It adds a service mode that keeps your keys out of reach of malware running as you.

## How it works

1. Your long-lived access keys leave `~/.aws/credentials` and are sealed by a **Windows Hello key in the TPM**. A copy of the vault is useless on any other PC.
2. The AWS CLI, Terraform, boto3 and every SDK keep working through `credential_process`. They only ever receive a **short STS session**.
3. A new session needs **Windows Hello** (face, fingerprint or PIN). Locking the PC drops sessions. Every use is written to a hash-chained audit trail, the Windows Event Log and, optionally, an S3 bucket nobody can delete from.

## Two install modes

| | User mode | Service mode |
|---|---|---|
| Install | no admin | admin, once per PC |
| Vault | your profile | a Windows service under its own account |
| Long-lived key | Windows Hello | **split** between your Windows Hello and the service's TPM key: neither alone opens it |
| Sessions | TPM-sealed files | service memory only |
| New programs | — | need one approval each |

## What's in it

| Feature | Command |
|---|---|
| Seal keys, auto-move new ones, sessions via `credential_process` | `zsp setup` |
| Account pin: a swapped-in key for another account is refused | automatic |
| MFA on this PC, or on your phone for every session | `zsp mfa enable --device pc\|phone` |
| AWS denies the key without MFA | `zsp mfa enforce` |
| Approve from your phone when you're away (e.g. driving an agent remotely) | `zsp phone add`, `zsp approve` |
| Cached sessions withheld while locked or idle; lock clears them | automatic (`zsp config set reuse-presence …`) |
| Config guard: refuses credentials if `endpoint_url`, a proxy or a CA bundle appears unapproved | automatic, `zsp guard approve` |
| Fresh Hello for credential-minting commands (`export-credentials`, `assume-role`, …) | automatic |
| Read/write tiers: 1 h read role, 15 min write role with a fresh Hello each time | `zsp tier set`, `deploy/tiered-roles.yaml` |
| Bind credentials to your networks | `zsp netbind --cidr …` |
| Revoke every issued session (scoped to your zsp sessions on shared roles) | `zsp revoke` |
| Auto-revoke sessions used from elsewhere (CloudTrail → Lambda) | `deploy/auto-revoke.yaml` |
| Audit: hash chain, Windows Event Log, S3 Object Lock | `zsp audit …`, `zsp ship setup`, `deploy/audit-bucket.yaml` |
| Rotate, check in IAM, restore to plain text | `zsp rotate`, `zsp check`, `zsp restore` |
| New-program approval, untrusted-client and pipe-squatting refusal | service mode |

## Quick start

Requirements: Windows 10/11 (x64 or ARM64), Windows Hello set up (a PIN is enough), AWS CLI v2.

**User mode**

```powershell
Expand-Archive aws-cli-zsp-windows-<ver>-amd64.zip -DestinationPath zsp; cd zsp
.\zsp.exe setup
aws sts get-caller-identity --profile <name>     # Windows Hello asks once per hour
zsp doctor
```

**Service mode**

```powershell
# elevated, once per PC:
.\zsp.exe install --service
# then as each normal user:
& 'C:\Program Files\aws-cli-zsp\zsp.exe' setup        # or `service migrate` from user mode
```

Read the **[User Guide](docs/USER-GUIDE.md)** before moving production keys. It covers the inventory, hardening in order, special setups (role profiles, Docker, WSL) and rollback.

## Documentation

- **[User Guide](docs/USER-GUIDE.md)**: install, migrate your existing credentials, harden, everyday use, troubleshooting.
- **[Design](docs/DESIGN.md)**: architecture, cryptography, split key, protocol, threat model, limitations.
- **[Test Plan](docs/TEST-PLAN.md)**: 113 test cases for verification on real hardware.
- **[Signing](docs/SIGNING.md)**: releases signed through SignPath Foundation.

## Status

**v1.0.0, pre-release.** The engine, policy, broker protocol, guard, tiers and audit shipping are covered by automated tests: AWS SigV4 and RFC 6238 test vectors, a fake STS/IAM/S3, and end-to-end runs of both modes. The auto-revoke Lambda is tested against stubbed AWS clients. The CloudFormation templates pass `cfn-lint`. **The Windows Hello, TPM, service and named-pipe code compiles for x64 and ARM64 but has not yet run on real hardware.** That is what the Test Plan is for. Try it with a throwaway IAM user first.

## Build

Standard library plus a vendored copy of `golang.org/x/sys` (Windows subtree). No other dependencies.

```bash
./scripts/build.sh            # or .\scripts\build.ps1 on Windows: dist/amd64, dist/arm64
go test ./...                 # on any OS; uses software key stand-ins
```

## Credits and licence

MIT, see [LICENSE](LICENSE). Design inspired by Andrew Baker's [aws-cli-zsp](https://github.com/andrewbakercloudscale/aws-cli-zsp) for macOS (MIT). The Windows Hello key-creation approach follows ByteNess [keyring/winhello](https://github.com/byteness/keyring) (MIT). `third_party/x-sys` is the Go project's `golang.org/x/sys` (BSD-3-Clause).
