# Development verification rules

- Prefer targeted tests after meaningful code changes and run ShipProof at PR/merge/release milestones.
- Do not treat successful Python tests as proof of live device/network behaviour, Windows installation, Debian installation or Android hardware compatibility.
- Use `python scripts/shipproof.py --stage pr` before describing a PR as ready.
- Report precisely: implemented, built, tested, hardware tested, pushed and published.
- Never invent CI outcomes, performance metrics, working installer results or successful remote pushes.
- No unapproved releases, remote network actions, production changes or credential exposure.
