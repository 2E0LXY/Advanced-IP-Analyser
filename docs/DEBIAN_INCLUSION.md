# Official Debian inclusion

The signed project APT repository and the official Debian archive are separate
distribution channels. This directory contains a Debian Policy-oriented source
package for review and sponsorship; it does not imply that Debian has accepted
the package.

## Current package state

- Source format: `3.0 (quilt)`
- Proposed Debian version: `2.1.0-1`
- Distribution: `UNRELEASED` until an ITP number and sponsor review exist
- Section and priority: `net`, `optional`
- Architecture: `all`
- Build system: debhelper 13, pybuild, and PEP 517/setuptools
- Automated checks: source build, binary build, unit tests, Lintian, AppStream,
  desktop-file validation, uscan, and autopkgtest

The workflow deliberately produces unsigned review artifacts. A maintainer must
inspect and sign the source upload personally; the existing project APT signing
key is not a Debian maintainer identity key.

Debian 13 (`trixie`) is already stable, and stable normally does not receive new
feature packages. Initial inclusion therefore targets Debian unstable (`sid`),
from which an accepted package can migrate to testing (`forky`). Once it is in
testing, a separate Debian Backports submission can be considered for Debian 13.
Until then, Debian 13 users should continue to use the project's signed APT
repository.

## Steps requiring the maintainer

1. Choose a monitored public email address. Debian's bug tracker and sponsors
   conduct reviews by email. Replace the GitHub noreply address in
   `debian/control`, `debian/changelog`, `debian/copyright`, and
   `debian/itp.txt` if it is not monitored.
2. Create accounts on [Debian Salsa](https://salsa.debian.org/) and
   [mentors.debian.net](https://mentors.debian.net/), and prepare a personal
   OpenPGP key for signing Debian source uploads.
3. Check the live [WNPP ITP list](https://www.debian.org/devel/wnpp/being_packaged)
   again immediately before filing.
4. Run `reportbug wnpp`, choose **ITP**, and use `debian/itp.txt` as the body.
   Filing is a public action and should not happen until the maintainer confirms
   the public name and email address.
5. Replace `UNRELEASED` with `unstable` and add `(Closes: #NNNNNN)` to the first
   changelog entry, using the assigned ITP bug number.
6. Build in a clean current Debian unstable environment, review all Lintian and
   autopkgtest results, and sign the `.dsc` and source `.changes` files with the
   maintainer's personal OpenPGP key.
7. Publish the packaging repository on Salsa and upload the signed source
   package to mentors.debian.net. Submit the generated Request For Sponsorship
   bug and respond to review comments with revised `-2`, `-3`, and later Debian
   revisions as required.
8. A Debian Developer reviews and, if satisfied, sponsors the upload. Debian's
   FTP masters can perform a further NEW-queue review before the package enters
   unstable. Migration to testing is handled later by Debian's normal release
   process.

## Building the review package locally

Run this from a Debian unstable machine or clean container after fetching the
repository and the `v2.1.0` tag:

```sh
version=2.1.0
mkdir -p build-area
git archive --format=tar --prefix="advanced-ip-analyser-$version/" "v$version" \
  | gzip -n > "build-area/advanced-ip-analyser_${version}.orig.tar.gz"
tar -C build-area -xzf "build-area/advanced-ip-analyser_${version}.orig.tar.gz"
cp -a debian "build-area/advanced-ip-analyser-$version/"
cd "build-area/advanced-ip-analyser-$version"
dpkg-buildpackage --no-sign -S
dpkg-buildpackage --no-sign -b
```

The GitHub workflow in `.github/workflows/debian-source.yml` repeats this build
on Debian unstable and retains the complete unsigned source-package set for
sponsor review.

## Authoritative references

- [Debian Policy Manual](https://www.debian.org/doc/debian-policy/)
- [Debian source package rules](https://www.debian.org/doc/debian-policy/ch-source)
- [Debian Python Policy](https://www.debian.org/doc/packaging-manuals/python-policy/)
- [Debian Developer's Reference: new packages and ITP](https://www.debian.org/doc/manuals/developers-reference/pkgs.html)
- [Debian Developer's Reference: sponsoring packages](https://www.debian.org/doc/manuals/developers-reference/beyond-pkging.html)
