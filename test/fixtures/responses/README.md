# Fixtures

- `github_*.json`: recorded on 2026-10-30 by the "Record API fixtures"
  workflow (`.github/workflows/record-fixtures.yml`) from
  `GET /advisories?ecosystem=pub&affects=dio@4.0.6,http@0.13.2` and
  `GET /repos/{owner}/{repo}/security-advisories?state=published` for
  dart-lang/sdk, flutter/flutter and cfug/dio. To refresh them, run the
  workflow and copy the artifact's files over these.
- `pub_dev_*.json`: recorded as-is from pub.dev on 2026-10-30
  (`/api/packages/dio`, `/api/packages/{http,dio}/advisories`).
- `osv_vuln_*.json`: single records taken unchanged from the pub.dev
  advisories responses above. pub.dev serves OSV-schema records, the same
  shape as `GET https://api.osv.dev/v1/vulns/{id}`.

Nothing here is trimmed: extra fields in real responses are part of what the
tests exercise.
