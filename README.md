# Cloud Health Check Continuous

Cloud Health Check Continuous scans Terraform, Kubernetes, Docker and cloud configuration inside the GitHub runner. The verified Linux bundle includes the native Cloud Health Check engine plus pinned Trivy and KubeLinter engines. It adds file/line annotations, maintains one pull-request comment, uploads SARIF to GitHub code scanning and can block a merge by severity.

Repository contents remain in the runner. Only the license entitlement is validated against Cloud Health Check.

## Usage

Create the repository secret `CHC_LICENSE_KEY`, then add:

```yaml
name: Cloud Health Check

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jatobi/cloud-health-check-ghactions@v4
        with:
          license-key: ${{ secrets.CHC_LICENSE_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: critical
```

To retain the complete HTML/JSON/SARIF report as a workflow artifact:

```yaml
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cloud-health-check-report
          path: cloud-health-check-report/
```

## Inputs

| Input | Default | Purpose |
|---|---:|---|
| `license-key` | required | Continuous entitlement; always use a repository or organisation secret. |
| `github-token` | empty | Enables PR comments and SARIF upload. |
| `path` | `.` | File or repository directory to scan. |
| `fail-on` | `critical` | `critical`, `high`, `medium`, `low`, `info` or `never`. |
| `language` | `en` | `en`, `es` or `auto`. |
| `comment-on-pr` | `true` | Create/update a single PR comment. |
| `annotations` | `true` | Publish up to 50 workflow annotations. |
| `upload-sarif` | `true` | Upload results to GitHub code scanning. |
| `report-directory` | `cloud-health-check-report` | Generated report directory. |

## Security notes

- Pin the Action to a full commit SHA in security-sensitive repositories.
- Pull requests from forks do not receive repository secrets by default; keep that protection enabled.
- The Action downloads the complete Linux ZIP from R2 and verifies its SHA-256 checksum before extraction.
- The Action verifies that Cloud Health Check, Trivy and KubeLinter are present and executable before scanning.
- Do not print or pass the license through command-line arguments.

## License

The wrapper source is distributable under the repository license. Use of Continuous capabilities requires an active Cloud Health Check Continuous subscription.
