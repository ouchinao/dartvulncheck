# Fixtures

- `github_*.json`: recorded on 2026-10-30 by the "Record API fixtures"
  workflow (`.github/workflows/record-fixtures.yml`) from
  `GET /advisories?ecosystem=pub&affects=dio@4.0.6,http@0.13.2` and
  `GET /repos/{owner}/{repo}/security-advisories?state=published` for
  dart-lang/sdk, flutter/flutter and cfug/dio. To refresh them, run the
  workflow and copy the artifact's files over these.
- `pub_dev_*.json`: recorded as-is from pub.dev on 2026-10-30
  (`/api/packages/dio`, `/api/packages/{http,dio}/advisories`).
- `flutter_releases_linux.json`: recorded as-is on 2026-11-05 from
  `https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json`,
  Flutter's release manifest, which the workflow above also records (with
  `curl`, since `gh api` reaches only GitHub). The Linux file is used on
  every OS: its version-to-Dart map is the same as the macOS one and a
  superset of the Windows one.
- `osv_vuln_*.json`: single records taken unchanged from the pub.dev
  advisories responses above. pub.dev serves OSV-schema records, the same
  shape as `GET https://api.osv.dev/v1/vulns/{id}`.

Nothing here is trimmed: extra fields in real responses are part of what the
tests exercise.
