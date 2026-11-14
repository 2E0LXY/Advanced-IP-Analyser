# Reusable ShipProof baseline

This reusable workflow is intentionally read-only and cannot certify functionality.

Use a pinned commit SHA for the central workflow:

```yaml
name: ShipProof Portfolio
on:
  pull_request:
  push:
    branches: [main, master]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  inventory:
    uses: 2E0LXY/Advanced-IP-Analyser/.github/workflows/shipproof-portfolio-reusable.yml@<PINNED_COMMIT>
    permissions:
      contents: read
```

This checks tracked files, native CI/test discovery and obvious potential credential leaks. It **never** runs arbitrary repository-defined commands, and its green CI execution only means the inventory ran; the JSON report retains `UNVERIFIED` functionality status. Existing native CI and each project's dedicated ShipProof stage gate must provide actual build/test evidence. Hardware verification remains manual.

Updating the central workflow does not silently change pinned callers. Updating callers requires a reviewed commit bump.
