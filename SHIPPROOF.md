# ShipProof — Advanced IP Analyser

ShipProof adds evidence-based milestone gates while preserving existing Windows, Debian, and Android workflows. Native workflow steps remain responsible for install and removal tests, Debian package validation, Gradle tests/lint, and APK signing.

## Gates
| Event | Verification |
|---|---|
| Meaningful development batch | `python scripts/shipproof.py --stage change`: compile |
| Pull request | Python compile and desktop unit regression suite |
| Main push | Python compile and desktop unit regression suite |
| Windows installer built | Independent EXE existence and SHA-256, after smoke-tested install/upgrade/removal |
| Debian package built | Independent DEB existence and SHA-256, after Debian package tests |
| Android debug APK built | Independent APK existence and SHA-256, after Gradle test/lint |
| Signed Android APK built | Independent APK existence and SHA-256, after signature verification |

ShipProof creates `.shipproof/report.json` and `.shipproof/report.md`. Each workflow uploads the evidence even if a gate fails. **No installer/firmware runs on real hardware from this generic gate.** On-device validation is UNVERIFIED until tested and recorded. In particular, network and Wi-Fi behavior require real network/device evidence.

## Development commands
Install desktop dependencies with `python -m pip install -e .`, then run `python scripts/shipproof.py --stage change` or `--stage pr`. To check a platform release, use `--stage release --config shipproof.<platform>.json` on the runner that produced the corresponding built artefact.

Review any changes to `shipproof*.json` before executing as a privileged runner. ShipProof does not create or publish releases; existing release workflows retain their current behaviour. Enforcing a required status check is a separate protected-branch setting.
