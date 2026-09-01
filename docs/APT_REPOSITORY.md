# Publishing the Debian 13 APT repository

Tagged releases can publish a signed APT repository through GitHub Pages. The
release workflow builds and tests the `.deb`, creates Debian `Packages`, `Release`,
`InRelease`, and detached signature metadata, and deploys the repository only
when a dedicated signing key is configured.

## One-time maintainer setup

Create a dedicated, non-expiring repository key on a protected maintainer system:

```sh
gpg --batch --quick-generate-key "Advanced IP Analyser Archive <24845841+2E0LXY@users.noreply.github.com>" rsa3072 sign 0
gpg --armor --export-secret-keys "Advanced IP Analyser Archive" | base64 -w0
gpg --with-colons --list-secret-keys "Advanced IP Analyser Archive"
```

Add the base64 output as the GitHub Actions secret `APT_SIGNING_KEY_B64`. Add the
key ID from the `sec` record as the optional secret `APT_SIGNING_KEY_ID`. Restrict
access to these secrets and retain an encrypted offline backup of the key and its
revocation certificate.

In the GitHub repository settings, open **Pages**, choose **GitHub Actions** as
the deployment source, and allow the `github-pages` environment to deploy.

Pushing a version tag then performs all package tests before publishing the APT
metadata. If the signing secret is absent, the normal `.deb` release still
succeeds and the APT deployment is safely skipped.

## Debian 13 user installation

After the first signed Pages deployment, users install the archive key and source:

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
