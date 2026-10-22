# Code signing with SignPath Foundation

Releases are signed by [SignPath Foundation](https://signpath.org/), which offers free code signing to open-source projects. The certificate belongs to SignPath Foundation, and every signature is tied to a build of this repository on GitHub-hosted runners. Nobody holds a private key on their own machine.

## One-time setup

1. **Apply** at https://signpath.org/ with the repository URL. SignPath checks the project (OSI licence, public repo, active maintenance, a release policy).
2. When accepted, in the SignPath web app:
   - Add the **GitHub.com trusted build system** to the organisation and link it to the project.
   - Create the project with slug `aws-cli-zsp`.
   - Create the signing policy `release-signing` (SignPath Foundation's release certificate).
   - Add an artifact configuration with slug `default`, using the contents of [`.signpath/artifact-configuration.xml`](../.signpath/artifact-configuration.xml).
   - Create a CI user with submitter rights for the policy and copy its API token.
   - Optionally install the SignPath GitHub App on the repository (needed for audit-log based policies).
3. In GitHub, under repository Settings › Secrets and variables › Actions:
   - Secret `SIGNPATH_API_TOKEN`: the CI user's token.
   - Variable `SIGNPATH_ORGANIZATION_ID`: your SignPath organisation ID.
   - Variables `SIGNPATH_PROJECT_SLUG` and `SIGNPATH_SIGNING_POLICY_SLUG`, only if you chose other slugs.

## Releasing

```bash
git tag v1.0.0
git push origin v1.0.0
```

[`release.yml`](../.github/workflows/release.yml) then:
1. runs the tests and builds `dist/amd64` and `dist/arm64` (`zsp.exe`, `zspw.exe`) from the tag, with the version stamped in;
2. uploads them unsigned as a workflow artifact;
3. submits a signing request to SignPath and waits for it (SignPath Foundation may require a manual approval for each release);
4. publishes a GitHub Release with per-architecture zips and `SHA256SUMS.txt`.

## Why signing matters here

- Users can verify the binary with `Get-AuthenticodeSignature` before giving it their AWS keys.
- SmartScreen and Smart App Control warn less, or not at all, once the signature has reputation.
- In service mode the broker accepts only clients from its own Program Files folder. Signed binaries also make it practical for organisations to add WDAC or AppLocker rules by publisher.
