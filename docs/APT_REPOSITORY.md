# Signed Debian 13 APT repository

The public repository is live at:

`https://2e0lxy.github.io/Advanced-IP-Analyser`

Archive signing-key fingerprint:

`6A28 5F7A 209A A948 09E7 7BAD 8EB4 FBAB A4FD EB99`

The dedicated RSA-3072 key is valid until 1 September 2031. Verify this
fingerprint before trusting a downloaded keyring.

Tagged releases can publish a signed APT repository through GitHub Pages. The
release workflow builds and tests the `.deb`, creates Debian `Packages`, `Release`,
`InRelease`, and detached signature metadata, and deploys the repository only
when a dedicated signing key is configured.

## Maintainer configuration

The repository uses a dedicated archive-signing key stored in the encrypted
GitHub Actions secrets `APT_SIGNING_KEY_B64` and `APT_SIGNING_KEY_ID`. GitHub
Pages uses the Actions deployment source, and the `github-pages` environment
allows `main` plus version tags matching `v*`.

For a future key rotation, create a replacement on a protected maintainer system:

```sh
gpg --batch --quick-generate-key "Advanced IP Analyser Archive <2E0LXY@users.noreply.github.com>" rsa3072 sign 5y
gpg --armor --export-secret-keys "Advanced IP Analyser Archive" | base64 -w0
gpg --with-colons --list-secret-keys "Advanced IP Analyser Archive"
```

Replace `APT_SIGNING_KEY_B64` with the base64 output and `APT_SIGNING_KEY_ID`
with the full fingerprint. Restrict access to these secrets and retain an
encrypted offline backup and revocation certificate when rotating the key.

Pushing a version tag then performs all package tests before publishing the APT
metadata. If the signing secret is ever absent, the normal `.deb` release still
succeeds and the APT deployment is safely skipped.

## Debian 13 user installation

Install the archive key and source on Debian 13:

```sh
curl -fsSL https://2e0lxy.github.io/Advanced-IP-Analyser/advanced-ip-analyser-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/advanced-ip-analyser-archive-keyring.gpg >/dev/null
echo "deb [arch=all signed-by=/usr/share/keyrings/advanced-ip-analyser-archive-keyring.gpg] https://2e0lxy.github.io/Advanced-IP-Analyser trixie main" \
  | sudo tee /etc/apt/sources.list.d/advanced-ip-analyser.list
sudo apt update
sudo apt install advanced-ip-analyser
```

Future tagged releases are then offered through normal `apt upgrade` and Debian
graphical update tools. Users should compare the key fingerprint published in
the GitHub repository before trusting the archive.

## Official Debian inclusion

Publishing this repository does not add the package to Debian's official archive.
Official inclusion additionally requires Debian source packaging, policy and
copyright review, an ITP bug, a sponsoring Debian Developer or Maintainer, and
review through the Debian mentors workflow. That route should follow after the
application and its package have accumulated wider testing.
