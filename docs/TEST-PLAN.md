# aws-cli-zsp for Windows — Test Plan

This plan verifies v1.0 on real Windows hardware. The automated suite (`go test ./...`) already covers the platform-neutral logic with software key stand-ins: AWS SigV4 and RFC 6238 test vectors, the engine, guard, tiers, phone approval, audit chain and shipping, and the broker protocol, including split-key and caller-approval policy. **What only a real Windows machine can prove** is the Windows Hello and TPM integration, the service, the named pipe, WTS lock events, the Event Log and the installers. Those cases are marked **[HW]**.

Record each result as **P** (pass), **F** (fail, with notes) or **B** (blocked). Run `zsp audit export` after any failure and attach the report; it contains no secrets.

## 0. Test environment

| Item | Setup |
|---|---|
| PC A | Windows 11 x64 with TPM 2.0 (a Hyper-V VM with a virtual TPM is fine), Windows Hello PIN set up, AWS CLI v2, Terraform, Python 3 + boto3, PowerShell 7 |
| PC B (optional) | Windows 11 ARM64 (Snapdragon) for the ARM build |
| Second Windows user | Local standard user `tester2` on PC A, with its own Hello PIN |
| AWS test account | Throwaway account. IAM user `zsp-test` with AdministratorAccess (it must manage itself). IAM user `zsp-client` with `ReadOnlyAccess` only, to play the client's read-only key |
| Phone | Authenticator app (Microsoft/Google Authenticator, 1Password, …) |
| Tools | `aws cloudformation` (CloudShell is fine), Event Viewer, Process Explorer (optional) |
| Builds | `dist\amd64` and `dist\arm64` from `scripts\build.ps1`, or a signed release |

Create keys for both IAM users and put them in `~/.aws/credentials` as profiles `zsp-test` and `client`. Add a third profile `keepme` with any key (it can be invalid). Set `region = eu-west-1` for `zsp-test` in `~/.aws/config`.

---

## 1. User mode — install and import

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| U-01 [HW] | Setup creates Hello keys | `.\zsp.exe setup`; answer y for `zsp-test` and `client`, n for `keepme`; auto-move y | Two Hello prompts (vault key, pin key). "sealed zsp-test", "sealed client". Installed to `%LOCALAPPDATA%\Programs\aws-cli-zsp` | |
| U-02 | Files rewritten | Open `~/.aws/credentials` and `config` | No keys for `zsp-test`/`client`; `keepme` untouched; `credential_process` lines point at the installed `zsp.exe`; `region` preserved; comments preserved | |
| U-03 | Sealed files hold no secret | `Select-String -Path $env:LOCALAPPDATA\aws-cli-zsp\keys\* -Pattern 'AKIA\|<first 6 chars of secret>'` | No match | |
| U-04 [HW] | Doctor is green | `zsp doctor` | All OK (TPM session key: Platform Crypto Provider) | |
| U-05 [HW] | Watcher running | `zsp doctor`; Task Manager | "Automatic move (watcher): autostart=true running=true"; `zspw.exe` in Task Manager, no console window | |
| U-06 [HW] | Watcher moves a new key | `aws configure --profile newkey` (paste a key) | Within ~5 s a tray balloon "Moved 1 AWS key(s)…"; `newkey` gone from credentials and wired in config | |
| U-07 | Keep list honoured | Edit the `keepme` key | It stays in plain text; `zsp status` lists it under "left in plain text by choice" | |
| U-08 | Session token profiles untouched | Add a profile with `aws_session_token` | Not moved | |
| U-09 [HW] | Survives reboot | Reboot, sign in | Watcher running again; `zsp status` intact | |

## 2. Sessions, Windows Hello prompts and presence

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| S-01 [HW] | First session | `aws sts get-caller-identity --profile zsp-test` | Hello prompt names `zsp-test`, "1-hour session", "Requested by: aws sts get-caller-identity ← pwsh"; then the "Pin AWS profile" prompt; output shows the zsp-test ARN | |
| S-02 [HW] | Reuse | Run S-01 again 5 times | No prompt | |
| S-03 [HW] | Hello cancel | `zsp clear-sessions`; run S-01; press Cancel | Command fails "cancelled at the Windows Hello prompt"; audit `hello-declined` | |
| S-04 [HW] | Face / fingerprint / PIN | Repeat S-03 approving with each available method | All work | |
| S-05 [HW] | Lock clears sessions | Get a session; Win+L; unlock; run S-01 | Hello asks again; audit "workstation locked: 1 session(s) dropped" | |
| S-06 [HW] | Reuse withheld while idle | `zsp config set reuse-idle-minutes 1`; get a session; don't touch the PC for 2 min; run a command via Task Scheduler or remote shell | Refused "not handed out while no keyboard or mouse input…"; restore the setting to 30 afterwards | |
| S-07 [HW] | Nobody present, new session | `zsp clear-sessions`; lock the PC; trigger a command (scheduled task) | Fails at once (no hanging prompt) with "nobody is at this PC (the screen is locked)" | |
| S-08 [HW] | Parallel commands, one prompt | `zsp clear-sessions`; start 3 `aws s3 ls` at once (`1..3 \| % { Start-Job { aws s3 ls --profile zsp-test } }`) | One Hello prompt; all three succeed | |
| S-09 [HW] | Sensitive command | `aws configure export-credentials --profile zsp-test` with a cached session | Hello asks "PRINT or MINT credentials"; Cancel → refused | |
| S-10 | Durations | `zsp config set duration 15m --profile zsp-test`; clear; new session | `zsp status` shows expiry ~15 min out; `zsp config set duration 13h` is rejected | |
| S-11 [HW] | Terraform | `terraform init/plan` with an AWS provider using `profile = "zsp-test"` | Works; one prompt at most | |
| S-12 [HW] | boto3 | `python -c "import boto3;print(boto3.Session(profile_name='zsp-test').client('sts').get_caller_identity())"` | Works | |
| S-13 [HW] | IDE | AWS Toolkit for VS Code, profile zsp-test | Works; prompt names the calling program | |
| S-14 [HW] | Clock skew | Set the clock 6 min off; `zsp doctor`; run S-01 | Doctor flags the clock; AWS error mentions time | |

## 3. Config guard

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| G-01 | Clean config | `zsp guard status` | "No settings redirect…" (or only your approved proxy) | |
| G-02 [HW] | endpoint_url injected | Add `[default]\nendpoint_url = https://example.invalid` to config; run S-01 | REFUSED listing `config:[default].endpoint_url`; Event Log error 300 "guard-refused" | |
| G-03 [HW] | Approve | `zsp guard approve` | Hello prompt listing the setting; S-01 then works | |
| G-04 | Changed value | Change the endpoint URL value | Refused again (value is part of the approval) | |
| G-05 | Env proxy | `$env:HTTPS_PROXY='http://127.0.0.1:9'`; run S-01 | Refused for `env:HTTPS_PROXY` | |
| G-06 | services block | Add `[services evil]` with `s3 =\n  endpoint_url = …` and `services = evil` on the profile | Refused | |
| G-07 | credential_process hijack | Change `client`'s credential_process to `notepad.exe`; run a command with `zsp-test` | Refused naming `config:[profile client].credential_process`; within seconds the watcher restores the line and shows a balloon | |
| G-08 | role_arn in a zsp profile | Add `role_arn = …` to `[profile zsp-test]` | Refused | |
| G-09 | Corporate proxy | Set a real proxy; `zsp setup` again | Setup lists it and asks to approve once; commands then work | |

## 4. Account pin and quarantine

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| P-01 [HW] | Pin created | After S-01, check `%LOCALAPPDATA%\aws-cli-zsp\pins\zsp-test.json` | Contains the account and ARN plus a signature | |
| P-02 [HW] | Pin tamper | Change one digit of the account in that file; run S-01 | "account pin … is invalid … altered"; no credentials | |
| P-03 [HW] | Key swap | Restore the file. Write the `client` key into `[zsp-test]` in credentials (the watcher seals it as zsp-test); run S-01 | REFUSED "belongs to account …/user/zsp-client, but this profile is pinned to …"; audit `pin-mismatch`. Then put the right key back | |
| P-04 [HW] | Quarantine | With MFA on for zsp-test (M-01), write a new key for it | `zsp status` shows QUARANTINED NEW KEY; old key still works; `zsp adopt --profile zsp-test` asks Hello twice and swaps it | |

## 5. MFA, enforcement and phone

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| M-01 [HW] | PC MFA | `zsp mfa enable --profile zsp-test --device pc` | Waits for the next code window; "This PC is now an MFA device"; IAM console shows the device `zsp-<host>-zsp-test` | |
| M-02 [HW] | Sessions carry MFA | `zsp test --profile zsp-test` | `mfa=true`; still one Hello | |
| M-03 [HW] | Enforce | `zsp mfa enforce --profile zsp-test` | Policy `aws-cli-zsp-require-mfa` on the user | |
| M-04 | Plain key useless | Use the raw key (from IAM, a second key) without MFA: `aws s3 ls` | AccessDenied | |
| M-05 [HW] | Phone approval | `zsp phone add --profile zsp-test`; add to the app; enter two codes | "Phone approval is on" | |
| M-06 [HW] | Approve remotely | Lock the PC; from a remote shell run a command | Fails telling you to run `zsp approve`; `zsp approve --profile zsp-test <code>` succeeds; the command then works while locked | |
| M-07 | Wrong / reused code | `zsp approve` with a wrong code, then with the same valid code twice | Refused by AWS both times | |
| M-08 [HW] | Phone-only MFA | New IAM key profile `p2`: `zsp mfa enable --profile p2 --device phone`; new session | Hello prompt, then "6-digit code from your authenticator app" in the terminal; works | |
| M-09 [HW] | Phone-only from an IDE | Trigger p2 from VS Code (no console) | A small input box asks for the code | |
| M-10 | Unenforce safety | `zsp mfa unenforce` while phone approval is on | Refused "remove phone approval first" | |
| M-11 | Disable safety | `zsp mfa disable` while enforced | Refused | |
| M-12 | Teardown | `zsp phone remove`, `zsp mfa unenforce`, `zsp mfa disable` | Each succeeds; IAM devices and policy removed | |

## 6. Tiers (v0.3)

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| T-01 | Deploy roles | `deploy/tiered-roles.yaml` with `ZspUserName=zsp-test` | Stack completes; outputs include `ZspCommand` | |
| T-02 [HW] | Wire tiers | Run the `ZspCommand` with `--profile zsp-test` | Hello; "read role OK", "write role OK"; config gains `[profile zsp-test-write]` with `--tier write` | |
| T-03 [HW] | Read tier | `aws s3 ls --profile zsp-test`; `aws s3 mb s3://zsp-t03-<random> --profile zsp-test` | List works; make-bucket is AccessDenied; CloudTrail shows session `zsp-zsp-test-zsp-test-r` | |
| T-04 [HW] | Write tier | `aws s3 mb s3://zsp-t04-<random> --profile zsp-test-write` | Hello prompt says WRITE session; works; session ~15 min | |
| T-05 [HW] | Fresh Hello per write session | `zsp clear-sessions --profile zsp-test`; run T-04 again | Hello again | |
| T-06 | Write tier presence | Get a write session; idle 6 min; reuse | Withheld | |
| T-07 [HW] | Scoped revoke | Get read + write sessions; `zsp revoke --profile zsp-test`; reuse an exported old session (`aws configure export-credentials` before revoking) | Old sessions AccessDenied; the role inline policy has the `aws:userid` condition; a new zsp session works | |
| T-08 | Boundaries hold | Using a write session, `aws iam put-role-policy` granting `iam:*` on the write role, then try an IAM call | Either the put is denied, or the IAM call stays denied (boundary = PowerUser) | |
| T-09 | Tier clear | `zsp tier clear --profile zsp-test` | Write profile removed from config; sessions are base sessions again | |

## 7. Source-IP binding and auto-revoke

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| N-01 | Lockout refused | `zsp netbind --profile zsp-test --cidr 10.0.0.0/8` | Refused "your public IP … would lock yourself out" | |
| N-02 [HW] | Bind | `--cidr <your IP>/32` | Policy `aws-cli-zsp-source-ip` on the user (and on roles if tiers are on) | |
| N-03 | Stolen session elsewhere | Export a session; use it from CloudShell or a phone hotspot | AccessDenied | |
| N-04 | Unbind | `zsp netbind --profile zsp-test --off` | Policies removed | |
| N-05 | Auto-revoke deploy | `deploy/auto-revoke.yaml` in us-east-1 and your region, `AllowedCidrs=<your IP>/32` | Stack completes; confirm the SNS email | |
| N-06 | Auto-revoke fires | Export a session; call `aws sts get-caller-identity` and `aws s3 ls` from CloudShell with it | Within ~1–2 min: email; revoke policy on the user; the session stops working; your next local command asks for Hello and works | |
| N-07 | No false positive | Normal use from your network for an hour | No revoke | |

## 8. Audit

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| A-01 | Show & verify | `zsp audit show -n 50`; `zsp audit verify` | Callers named; chain intact | |
| A-02 | Edit detected | Change one character in `audit.jsonl` | verify: "entry N was edited" | |
| A-03 | Truncation detected | Delete the last line | verify: "newest entries were removed" | |
| A-04 [HW] | Event Log | Event Viewer › Windows Logs › Application, source aws-cli-zsp | Info 100 for sessions; Warning 200 for refusals; Error 300 for guard/pin | |
| A-05 | Ship setup | Deploy `audit-bucket.yaml`; create a key; `zsp ship setup …` | Test object written; `zsp status` shows shipping | |
| A-06 | Shipped and immutable | Generate events; wait 5 min (or `zsp ship now`); try `aws s3 rm` on an object as admin | Objects present; delete refused (Object Lock compliance) | |
| A-07 | Refusal ships at once | Cause a refusal (G-02) | A new object appears within seconds | |
| A-08 | Tamper alert | Edit a shipped line locally; `zsp ship now` | `…-TAMPER.json` object; Event Log error | |
| A-09 | Export redaction | `zsp audit export` | No secrets; key IDs masked; account IDs show the last 4 digits only | |

## 9. Settings protection

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| C-01 [HW] | Hello on change | `zsp config set reuse-presence off`; Cancel | Refused; `zsp config show` unchanged | |
| C-02 [HW] | Approved change | Repeat and approve | Changed; audit `setting` | |
| C-03 | Bad values | `zsp config set idle-minutes 0`, `duration 5m` | Rejected | |

## 10. Rotation, revoke, restore

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| R-01 [HW] | Rotate | `zsp rotate --profile zsp-test` | New key created and verified; old key deleted in IAM; sessions cleared; phone copy updated | |
| R-02 | Rotate with two keys | Create a second key in IAM; rotate | Refused "already has two access keys" | |
| R-03 [HW] | Check | `zsp check --profile zsp-test` and `--profile client` | Full listing; client shows "read-only · client's key" | |
| R-04 [HW] | Restore | `zsp restore --profile client` | Hello; key back in credentials; added to the keep list; not re-moved by the watcher | |

## 11. Service mode — install and isolation

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| V-01 | Not elevated | `zsp install --service` in a normal shell | "needs an elevated terminal" | |
| V-02 [HW] | Install | Elevated: `.\zsp.exe install --service` | Running as `NT SERVICE\AwsCliZsp`; binaries in Program Files; next-steps printed | |
| V-03 [HW] | Key backend | `zsp service status` | key backend `tpm` (note if `dpapi`: that means the virtual account cannot use the TPM; report it) | |
| V-04 [HW] | Folder ACL | `icacls C:\ProgramData\aws-cli-zsp` | Owner Administrators; only SYSTEM, Administrators, NT SERVICE\AwsCliZsp; inheritance disabled; the normal user cannot list `users\` | |
| V-05 [HW] | Squatting defence | Uninstall; as a standard user create `C:\ProgramData\aws-cli-zsp`; reinstall | Warning; the folder is moved to `.suspect-…`; the new folder is locked down | |
| V-06 [HW] | Enrol and set up | Standard user: `& 'C:\Program Files\aws-cli-zsp\zsp.exe' setup` | One Hello (register); keys moved; `zsp status` says service mode | |
| V-07 [HW] | Sessions not on disk | After a session, search `C:\ProgramData\aws-cli-zsp` (as admin) for `sessions` content | No session files | |
| V-08 [HW] | Untrusted client | Copy `zsp.exe` to Desktop; run `.\zsp.exe status` from there | Refused "only the installed zsp.exe…" | |
| V-09 [HW] | Pipe squatting | Stop the service (admin); as a user run a tiny named-pipe server on `\\.\pipe\aws-cli-zsp` (e.g. PowerShell `[System.IO.Pipes.NamedPipeServerStream]`); run `zsp status` | zsp says the service isn't running, or REFUSED (server PID mismatch); nothing is sent to the fake pipe | |
| V-10 [HW] | Second user isolated | As `tester2`: `zsp status`, then try a profile name of user 1 | Empty vault; "not in the vault"; cannot read user 1's files | |
| V-11 [HW] | New program approval | `python -c "…"` (S-12) twice; then a script `deploy.py` twice | Inline code asks every time; the script asks once, then not again | |
| V-12 [HW] | Lock event | Get a session; Win+L; unlock; run a command | Hello again (service received WTS lock) | |
| V-13 [HW] | Re-enrol refused | Reset Windows Hello PIN (creates a new key); `zsp setup` | "already enrolled with a different Windows Hello key" | |
| V-14 [HW] | Admin reset | Elevated: `zsp service reset-user --sid <SID from whoami /user>`; user runs `zsp setup` | Works with fresh keys | |
| V-15 [HW] | Service restart | Admin restarts the service; run a command | Hello asks again (memory cache gone) | |
| V-16 [HW] | Crash recovery | Kill the service process in Task Manager (admin) | SCM restarts it within ~5 s | |
| V-17 [HW] | Event Log text | View an event from the service | Message text renders cleanly (registered source), includes the user | |

## 12. Service mode — split key

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| K-01 [HW] | Phished prompt yields no key | As the user, write a small script that connects to the pipe (it will be refused: V-08), or uses `zsp.exe restore` | restore needs Hello and is audited; no other path returns the long-lived key | |
| K-02 [HW] | Admin alone cannot open | As admin (or SYSTEM via `psexec -s`), copy a user's `keys\*.sealed` and try `zsp` on it | Cannot decrypt without the user's Hello (K1) | |
| K-03 [HW] | Copy to another PC | Copy `C:\ProgramData\aws-cli-zsp` to PC B | Useless there | |

## 13. Migration and lifecycle

| ID | Test | Steps | Expected | Result |
|---|---|---|---|---|
| L-01 [HW] | User → service | Start in user mode with 2 keys (one with MFA + phone + tiers); install the service; `zsp service migrate` | One Hello per key; MFA, phone, pins and tiers carried; config rewired to Program Files; user-mode copies deleted; `zsp doctor` green | |
| L-02 [HW] | Migrate re-run | `zsp service migrate --keep-local`, then `zsp service migrate` | Second run skips keys already in the service and deletes the local copies | |
| L-03 [HW] | Upgrade | Build a newer version; elevated `zsp install --service` from the new folder | Service stopped, binaries replaced, started; sessions require Hello again; watchers restart at next sign-in | |
| L-04 [HW] | Uninstall blocked with keys | Elevated `zsp uninstall --service` | Refused while keys are sealed | |
| L-05 [HW] | Restore then uninstall | Each user `zsp restore`; admin `zsp uninstall --service` | Service, Event source and HKLM Run entry gone | |
| L-06 [HW] | Purge | Install, seal a key, `zsp uninstall --service --purge`, type DELETE | Folder removed | |
| L-07 [HW] | User-mode uninstall | `zsp uninstall --restore-plaintext --purge` | Keys back in credentials; Hello and TPM keys deleted; vault folder removed | |

## 14. Compatibility

| ID | Test | Expected | Result |
|---|---|---|---|
| X-01 [HW] | ARM64 build on Snapdragon: U-01, S-01, V-02 | Same as x64 | |
| X-02 [HW] | Windows 10 22H2 | Same | |
| X-03 [HW] | WSL: `credential_process = "/mnt/c/Program Files/aws-cli-zsp/zsp.exe" credential-process --profile zsp-test` in WSL's config | Works (experimental) | |
| X-04 [HW] | PC without TPM (VM without vTPM) | User mode works with DPAPI; doctor flags it | |
| X-05 [HW] | Device joined to Entra ID / Hello for Business | Works; prompt is the Hello for Business one | |
| X-06 | Signed release | `Get-AuthenticodeSignature` on both exes | Valid, SignPath Foundation | |

## Sign-off

| Area | Tester | Date | Pass / Fail / Blocked counts |
|---|---|---|---|
| User mode (U, S, G, P, M, C, R, A) | | | |
| Tiers and AWS-side (T, N) | | | |
| Service mode (V, K, L) | | | |
| Compatibility (X) | | | |
