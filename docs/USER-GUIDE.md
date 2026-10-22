# aws-cli-zsp for Windows — User Guide

**From plain-text AWS keys to Zero Standing Permissions.** This guide takes you from a `~/.aws/credentials` file full of long-lived keys to a setup where no key is readable on disk, every session expires on its own, and Windows Hello approves each one. Your AWS CLI, Terraform, boto3 and IDE plugins keep working unchanged.

Allow 15 minutes for the basic move, plus 30–60 minutes per AWS account if you add the hardening steps in Part 5.

- [Part 1 — Before you start](#part-1--before-you-start)
- [Part 2 — Choose a mode](#part-2--choose-a-mode)
- [Part 3 — Install and move your keys](#part-3--install-and-move-your-keys)
- [Part 4 — Check everything still works](#part-4--check-everything-still-works)
- [Part 5 — Harden, one step at a time](#part-5--harden-one-step-at-a-time)
- [Part 6 — Everyday use](#part-6--everyday-use)
- [Part 7 — Special setups](#part-7--special-setups)
- [Part 8 — Moving from user mode to service mode](#part-8--moving-from-user-mode-to-service-mode)
- [Part 9 — Rolling back and uninstalling](#part-9--rolling-back-and-uninstalling)
- [Part 10 — Troubleshooting](#part-10--troubleshooting)

---

## Part 1 — Before you start

### Requirements

- Windows 10 21H2 or later, or Windows 11, x64 or ARM64.
- **Windows Hello set up**: Settings › Accounts › Sign-in options › PIN (and face or fingerprint if your device has them). A PIN alone is enough; Windows Hello keys live in the TPM either way.
- A TPM 2.0 (any PC sold with Windows 11 has one). Without a TPM, zsp still works but the session cache falls back to software (DPAPI) and `zsp doctor` tells you.
- **AWS CLI v2** (`aws --version` should print `aws-cli/2…`).
- For service mode: local administrator rights, once, to install.

### Take an inventory (5 minutes)

Open PowerShell and look at what you have today:

```powershell
aws configure list-profiles
Get-Content $HOME\.aws\credentials     # long-lived keys live here (AKIA...)
Get-Content $HOME\.aws\config
Get-ChildItem Env:AWS_*                # keys in environment variables bypass every profile
[Environment]::GetEnvironmentVariable('AWS_ACCESS_KEY_ID','User')
Select-String -Path $PROFILE -Pattern 'AWS_ACCESS_KEY_ID|AWS_SECRET' -ErrorAction SilentlyContinue
```

Make a note of:

| You find | What zsp does |
|---|---|
| `aws_access_key_id = AKIA…` + secret | **Moves it** into the vault |
| `aws_session_token` in a profile | Leaves it alone (already temporary) |
| `sso_…` or `sso_session` profiles | Leaves them alone (IAM Identity Center is already better than keys) |
| `role_arn` + `source_profile = X` | Leaves the role profile alone; if `X` has a key, `X` moves and the role profile keeps working through it |
| `AWS_ACCESS_KEY_ID` in the environment or `$PROFILE` | **You remove it** (step 3.4); otherwise the CLI uses it and ignores the vault |
| Keys you deliberately want to keep in plain text (rare) | Answer "n" during setup; they go on the keep list |

> **Do not make a "backup" copy of the credentials file.** A backup of plain-text keys is exactly the standing permission you are removing. If something goes wrong, `zsp restore` gives a key back, and you can always create a new key for the IAM user in the console.

### Get the binaries

1. Download `aws-cli-zsp-windows-<version>-amd64.zip` (or `-arm64.zip` for Snapdragon PCs) and `SHA256SUMS.txt` from the GitHub release.
2. Verify:
   ```powershell
   Get-FileHash .\aws-cli-zsp-windows-*-amd64.zip -Algorithm SHA256
   Expand-Archive .\aws-cli-zsp-windows-*-amd64.zip -DestinationPath .\zsp
   Get-AuthenticodeSignature .\zsp\zsp.exe     # "Valid", signed via SignPath Foundation
   Unblock-File .\zsp\*.exe
   ```
3. Keep `zsp.exe` and `zspw.exe` together.

---

## Part 2 — Choose a mode

| Choose **user mode** if… | Choose **service mode** if… |
|---|---|
| You can't get admin rights, or want to try it first | You have admin rights once, or IT can push it |
| It's your personal machine with one Windows user | It's a work machine, or several people use it |
| — | You want malware running as you to be unable to get your long-lived keys at all |
| — | You want new programs and scripts to need approval before they use a key |

You can start in user mode and move to service mode later (Part 8). Both modes use the same commands.

---

## Part 3 — Install and move your keys

### 3.1 User mode

From the folder you unzipped (a normal, **non-elevated** PowerShell):

```powershell
.\zsp.exe setup
```

What happens:
1. Windows Hello asks you to approve twice: once to create the vault key, once for the account-pin key.
2. zsp lists the plain-text keys it found and asks, per key, whether to move it.
3. It asks whether keys written to `~/.aws` later should move automatically (say **yes**: if a tool or `aws configure` writes a new key, it's sealed within seconds).
4. If your config or environment redirects AWS traffic (a corporate proxy, a custom CA bundle, an `endpoint_url`), it lists those and asks you to approve them once (see 5.6).
5. It installs itself to `%LOCALAPPDATA%\Programs\aws-cli-zsp`, starts the watcher, and sets it to start at sign-in.

Non-interactive (for scripts):

```powershell
.\zsp.exe setup --move all --keep personal --auto on --duration 1h --yes
```

### 3.2 Service mode

**As administrator, once per PC** (elevated PowerShell, from the unzipped folder):

```powershell
.\zsp.exe install --service
```

This copies the binaries to `C:\Program Files\aws-cli-zsp`, creates the `AwsCliZsp` service under its own virtual account, creates a locked-down vault in `C:\ProgramData\aws-cli-zsp`, registers the Event Log source, and starts a watcher at sign-in for every user.

**Then, as each normal user** (non-elevated PowerShell):

```powershell
& 'C:\Program Files\aws-cli-zsp\zsp.exe' setup
```

This registers your Windows Hello key with the service (one prompt) and moves your keys exactly as in 3.1. From now on, always use the copy in Program Files: the service refuses any other `zsp.exe`.

Tip: add it to your PATH once.

```powershell
[Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';C:\Program Files\aws-cli-zsp', 'User')
```

### 3.3 What changed in your files

Before:

```ini
# ~/.aws/credentials
[default]
aws_access_key_id = AKIA…
aws_secret_access_key = wJalr…
[bedrock]
aws_access_key_id = AKIA…
aws_secret_access_key = 9fQ…

# ~/.aws/config
[profile bedrock]
region = af-south-1
```

After:

```ini
# ~/.aws/credentials
(no keys for moved profiles; the section is removed if nothing else was in it)

# ~/.aws/config
[default]
credential_process = "C:\Users\you\AppData\Local\Programs\aws-cli-zsp\zsp.exe" credential-process --profile default
[profile bedrock]
region = af-south-1
credential_process = "C:\Users\you\AppData\Local\Programs\aws-cli-zsp\zsp.exe" credential-process --profile bedrock
```

The key left the file only after its sealed copy had been written and read back successfully.

### 3.4 Remove keys from the environment

If your inventory found `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in the environment, remove them, or the AWS CLI will keep using them and never ask zsp:

```powershell
[Environment]::SetEnvironmentVariable('AWS_ACCESS_KEY_ID', $null, 'User')
[Environment]::SetEnvironmentVariable('AWS_SECRET_ACCESS_KEY', $null, 'User')
notepad $PROFILE      # delete any $env:AWS_ACCESS_KEY_ID = ... lines
```

If the key isn't in a profile yet, put it in one first (`aws configure --profile name`); the watcher moves it straight into the vault. Then open a new terminal.

---

## Part 4 — Check everything still works

```powershell
zsp doctor
aws sts get-caller-identity --profile bedrock
```

- `zsp doctor` should show `OK` on every line. Each `!!` line comes with the fix.
- The first `aws` command shows a Windows Hello prompt that names the profile, the session length and the command, for example *"Unlock AWS key 'bedrock' for a 1-hour session. Requested by: aws sts get-caller-identity ← pwsh"*. The very first session per profile asks a second time, to **pin** the profile to the AWS account and IAM user it returned.
- Run the command again: no prompt, the session is reused.
- `zsp status` shows each key, its live sessions and what last used it.

Then check your other tools in the way you normally use them: Terraform (`terraform plan`), Python (`boto3.Session(profile_name='bedrock')`), the AWS Toolkit in VS Code, CDK/SAM. They all read `credential_process` from the shared config. In service mode each new program asks for one approval the first time.

---

## Part 5 — Harden, one step at a time

Do these in order. Each step is reversible and each has a check.

### 5.1 Make the PC an MFA device (or your phone)

```powershell
zsp mfa enable --profile bedrock --device pc       # convenience: seed sealed in the vault, still one Hello
# or, for production accounts:
zsp mfa enable --profile bedrock --device phone    # every new session: Hello + a code from your phone
```

`--device phone` shows a key and an `otpauth://` URI to add to your authenticator app, then asks for two consecutive codes. Phone mode means even malware with admin rights on the PC can't mint an MFA session without your phone.

Check: `zsp test --profile bedrock` shows `mfa=true`.

### 5.2 Make AWS require MFA for the key

```powershell
zsp mfa enforce --profile bedrock
```

zsp attaches an inline policy to the IAM user. Everything the key does without MFA is denied, and creating keys, MFA devices or policies needs MFA from the last five minutes. A copy of the key on its own is now worthless. zsp refuses to apply this until an MFA session from this PC has worked, so it can't lock you out.

Client keys: if the IAM user may not change itself, `zsp check` shows *read-only · client's key*. Skip 5.2–5.4 for that key and ask the client to apply the policy.

### 5.3 Separate read from write (tiers)

Deploy the roles in each AWS account (CloudShell or the console):

```bash
aws cloudformation deploy --template-file deploy/tiered-roles.yaml --stack-name zsp-tiers-richard \
  --capabilities CAPABILITY_NAMED_IAM --parameter-overrides ZspUserName=richard
aws cloudformation describe-stacks --stack-name zsp-tiers-richard --query "Stacks[0].Outputs"
```

Then on the PC, using the `ZspCommand` output:

```powershell
zsp tier set --profile bedrock --read-role arn:aws:iam::111122223333:role/zsp-read-richard `
                               --write-role arn:aws:iam::111122223333:role/zsp-write-richard
```

zsp checks both roles work, and creates a second AWS profile, `bedrock-write`.

| Use | Gets | Asks |
|---|---|---|
| `aws --profile bedrock …` | read-only role, 1 h | Hello once per hour |
| `aws --profile bedrock-write …` / Terraform apply | write role (PowerUser), 15 min | Hello for **every** new write session |

Point Terraform at the write profile only when applying, for example `$env:AWS_PROFILE='bedrock-write'; terraform apply`.

### 5.4 Bind the key to your networks

```powershell
zsp netbind --profile bedrock --cidr 196.25.1.0/24,41.0.0.10/32
```

AWS now refuses the key and its sessions from anywhere else (calls AWS services make for you, like CloudFormation, still work). zsp checks your current public IP first and refuses a binding that would lock you out. If you travel, add the VPN egress range, or remove it with `--off`.

### 5.5 Copy the audit trail off the PC

Deploy the bucket once (ideally in a separate log-archive account):

```bash
aws cloudformation deploy --template-file deploy/audit-bucket.yaml --stack-name zsp-audit \
  --capabilities CAPABILITY_NAMED_IAM --parameter-overrides BucketName=acme-zsp-audit RetentionDays=365
aws iam create-access-key --user-name aws-cli-zsp-audit-shipper-af-south-1
```

On each PC:

```powershell
zsp ship setup --bucket acme-zsp-audit --region af-south-1 --prefix aws-cli-zsp
```

Paste the key id and secret when asked. zsp seals them; don't keep another copy. From then on, new entries go to S3 every five minutes and immediately after any refusal. Objects are locked in compliance mode: nobody can change or delete them before retention ends.

### 5.6 Approve your traffic settings (proxy, CA bundle)

If you're behind a corporate proxy or TLS inspection, zsp shows those settings during setup and asks you to approve them once. If one changes later (a new proxy, a new `endpoint_url`), credentials are refused until you look:

```powershell
zsp guard status
zsp guard approve      # only if you made the change
```

### 5.7 Auto-revoke stolen sessions (AWS side)

```bash
aws cloudformation deploy --template-file deploy/auto-revoke.yaml --stack-name zsp-auto-revoke \
  --capabilities CAPABILITY_IAM --region us-east-1 \
  --parameter-overrides WatchedUserNames=richard AllowedCidrs=196.25.1.0/24 NotifyEmail=you@example.com
```

Repeat in each region you use (or use a StackSet). If a zsp session is used from outside your networks, the Lambda revokes every session issued so far and emails you.

### 5.8 Phone approval for when you're away

For when you drive Claude Code or another agent remotely and nobody is at the PC to answer Windows Hello. This needs 5.2 first.

```powershell
zsp phone add --profile bedrock
```

When the PC is locked or idle, a new session fails at once with a message telling the caller to ask you for a code. You read the 6-digit code from your phone and the agent runs `zsp approve --profile bedrock 123456`. AWS checks the code, not zsp.

---

## Part 6 — Everyday use

| You want to | Run |
|---|---|
| See keys, sessions, last use | `zsp status` |
| End all sessions now (leaving your desk) | `zsp clear-sessions` (locking the PC does this too) |
| Change session length | `zsp config set duration 2h --profile bedrock` |
| Check a key in IAM | `zsp check --profile bedrock` |
| Rotate a key | `zsp rotate --profile bedrock` (new key, verified, swapped in, old deleted) |
| Something looks wrong | `zsp revoke --profile bedrock`, then `zsp rotate` |
| Read the audit trail | `zsp audit show -n 50`, `zsp audit verify` |
| Send diagnostics to support | `zsp audit export` (secrets removed, IDs masked) |
| Forget which programs you approved | `zsp callers forget --profile bedrock` (service mode) |

**Prompts you'll see**

| Prompt says | Why | If you didn't expect it |
|---|---|---|
| "Unlock AWS key 'X' for a 1-hour session. Requested by: aws …" | New session | Press **Cancel**, run `zsp audit show` |
| "… WRITE session …" | Write tier | Cancel unless you're about to change something |
| "Allow a program that has not used this key before…" | Service mode, new program or script | Cancel if you don't recognise the program |
| "'configure export-credentials' wants to PRINT or MINT credentials…" | A command that hands out credentials | Almost always Cancel |
| "Pin AWS profile 'X' to account …" | First session for a profile | Approve only if the account is yours |
| "Change zsp setting …" / "Approve AWS traffic settings …" | Someone is changing zsp's policy | Cancel unless it was you |

---

## Part 7 — Special setups

- **Role profiles** (`role_arn` + `source_profile = bedrock`) keep working: the CLI gets `bedrock`'s session from zsp and assumes the role from it. Don't put `role_arn` inside the zsp profile itself; the guard refuses that.
- **IAM Identity Center (SSO)** profiles are untouched. Prefer them for any account you control. zsp is for the keys you can't get rid of yet.
- **Docker**: containers can't run `zsp.exe`. Pass a session explicitly: `aws configure export-credentials --profile bedrock --format env` (a sensitive command, so Hello asks every time) and feed it to `docker run --env-file`.
- **WSL**: WSL can run Windows executables. In the Linux `~/.aws/config`, use `credential_process = "/mnt/c/Program Files/aws-cli-zsp/zsp.exe" credential-process --profile bedrock`. This works in service mode; in user mode use the `%LOCALAPPDATA%` path. Treat it as experimental (see the Test Plan).
- **IDE plugins without a console**: when a phone code is needed, zsp shows a small input box instead of the terminal prompt.
- **Several Windows users on one PC**: in service mode each user has a separate vault and must run `zsp setup` themselves; no user can reach another's keys.
- **Long jobs**: a cached session is not handed out in its last few minutes (5 min for 1 h sessions), so a long `terraform apply` doesn't run out halfway. For multi-hour jobs, raise the duration for that profile.

---

## Part 8 — Moving from user mode to service mode

1. As administrator: `.\zsp.exe install --service` (from the new release folder).
2. As yourself (non-elevated): `& 'C:\Program Files\aws-cli-zsp\zsp.exe' service migrate`
   - registers your Windows Hello key with the service;
   - opens each user-mode key once (one Hello prompt per key) and hands it to the service, which re-seals it with the split key;
   - carries MFA devices, phone approval, account pins, tiers and your keep list across;
   - rewires `~/.aws/config` to the Program Files copy, retires the user-mode watcher, and **deletes the user-mode copies** (add `--keep-local` to keep them while you test, then delete them by running `migrate` again without the flag).
3. `zsp doctor` (it flags any keys still left in the user-mode vault).

---

## Part 9 — Rolling back and uninstalling

| Goal | Command |
|---|---|
| Put one key back in plain text | `zsp restore --profile bedrock` (if AWS requires MFA for it, run `zsp mfa unenforce` first) |
| Remove tiers | `zsp tier clear --profile bedrock` |
| Remove the network binding | `zsp netbind --profile bedrock --off` |
| User mode: uninstall and restore every key | `zsp uninstall --restore-plaintext --purge` |
| Service mode: uninstall | Each user runs `zsp restore` for their keys; then an admin runs `zsp uninstall --service` (`--purge` destroys any keys left, after typing DELETE) |

`restore` is the only way a long-lived key leaves the vault, and it always needs Windows Hello.

---

## Part 10 — Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Windows Hello is not ready (0x80090029)` | No Hello PIN set up | Settings › Accounts › Sign-in options › PIN |
| AWS CLI ignores the vault, no prompt ever | `AWS_ACCESS_KEY_ID` in the environment | Part 3.4; `zsp doctor` names the source |
| `REFUSED: your AWS config or environment now redirects…` | New proxy, CA bundle or endpoint | `zsp guard status`; `zsp guard approve` if it was you |
| `a session … is cached, but it is not handed out while the screen is locked` | Presence on reuse | Unlock / touch the keyboard; or `zsp config set reuse-presence lock` |
| `nobody is at this PC … Ask the user for the 6-digit code` | Remote use | `zsp approve --profile X <code>` (needs Part 5.8) |
| `REFUSED: the key sealed as 'X' belongs to account …` | A different key was sealed under that name | If you did it on purpose: `zsp pin reset --profile X`; otherwise `zsp revoke` and investigate |
| `QUARANTINED NEW KEY` in status | A new key was written over an MFA profile | `zsp adopt --profile X` |
| `refused: only the installed zsp.exe … may talk to the zsp service` | Running zsp from Downloads in service mode | Use `C:\Program Files\aws-cli-zsp\zsp.exe`; `zsp repair` |
| `the AwsCliZsp service is installed but not running` | Service stopped | Admin: `sc start AwsCliZsp`; check Event Viewer › Application › aws-cli-zsp |
| `SignatureDoesNotMatch` / `RequestTimeTooSkewed` | Clock more than 5 min off | `w32tm /resync` |
| After resetting your Windows Hello PIN nothing opens | Hello keys were deleted with the PIN | Create new access keys in IAM; service mode: admin runs `zsp service reset-user --sid <your SID>`; then `zsp setup` |
| Want to see what happened | — | `zsp audit show -n 100`, Event Viewer › Application › source aws-cli-zsp |
