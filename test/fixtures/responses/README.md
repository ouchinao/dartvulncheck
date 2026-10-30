# Fixtures

- `pub_dev_*.json`: recorded as-is from pub.dev on 2026-10-30
  (`/api/packages/dio`, `/api/packages/{http,dio}/advisories`).
- `osv_vuln_*.json`: single records taken unchanged from the pub.dev advisories
  responses above. pub.dev serves OSV-schema records, the same shape as
  `GET https://api.osv.dev/v1/vulns/{id}`.
- `github_*.json`: hand-built from the GitHub REST docs
  (`GET /advisories`, `GET /repos/{owner}/{repo}/security-advisories`).
  The GitHub API was not reachable when these were written.
  TODO: replace with recorded responses, kept untrimmed so that extra
  fields in real responses keep being exercised.
