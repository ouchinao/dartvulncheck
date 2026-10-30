# dartvulncheck

govulncheck for Dart and Flutter. It checks the packages pinned in `pubspec.lock`, and the Flutter/Dart SDK you build with, against known vulnerabilities, and fails CI when it finds one. Pure Dart, no Flutter required.

What it adds over the warning from `flutter pub get`:

| `flutter pub get` warning | dartvulncheck |
| --- | --- |
| Printed only; CI still passes | Fails CI through its exit code |
| pub packages only | Also checks the Flutter/Dart SDK itself |
| Only after GitHub has reviewed the advisory | Also reads repository advisories as soon as maintainers publish them |
| Human-readable text only | Machine-readable output with `--json` |

## Install

```sh
dart pub global activate dartvulncheck 0.2.3
```

Or from git, at a release tag: `dart pub global activate --source git https://github.com/ouchinao/dartvulncheck --git-ref v0.2.3`. Either way, name a version rather than the head of `main`, so that the tool does not change under you between runs.

## Usage

```sh
dartvulncheck                           # current directory
dartvulncheck app packages/core         # several directories (monorepo)
```

It reads `pubspec.lock`, so run `dart pub get` (or `flutter pub get`) first.

| Option | Meaning | Default |
| --- | --- | --- |
| `--json` | Print JSON | Text |
| `--fail-on <level>` | Exit 3 if anything at this severity or above is found (`low` / `moderate` / `high` / `critical`) | `low` |
| `--ignore <id>` | Advisory ID to ignore (GHSA or CVE). Repeatable. Added to `ignored_advisories` in `pubspec.yaml` | None |
| `--strict` | Also count advisories whose affected range cannot be read ("unverified") | Not counted |
| `--no-repo-advisories` | Skip repository advisories (the early-warning stage) | Skipped automatically without `GITHUB_TOKEN` |
| `--sdk-version <ver>` | Pass the Flutter version by hand | `.fvmrc` (or `.fvm/fvm_config.json`) → `flutter --version` → `dart --version` |
| `--no-sdk` | Do not check the SDK | Checked |
| `--no-transitive` | Do not check transitive dependencies | Checked |
| `--verbose` | Show how many packages were queried and ignored, and which could not be looked up | Off |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No problems (also when every finding is ignored) |
| 1 | Could not check (`pubspec.lock` missing, network failure, bad arguments) |
| 3 | Vulnerabilities found (same value as govulncheck) |

"Could not check" never passes as "no problems", and there is no option to make it do so.

### Ignoring an advisory

Use pub's own key in `pubspec.yaml`. The same list also silences the `flutter pub get` warning.

```yaml
ignored_advisories:
  - GHSA-xxxx-xxxx-xxxx  # iOS only; this app ships on Android
```

Ignored findings are counted in the summary line, kept in the JSON output with `"ignored": true`, and listed by `--verbose`, so a growing ignore list stays visible. The text report lists them under `Ignored`.

## GitHub Actions

```yaml
vulncheck:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: subosito/flutter-action@v2
      with:
        channel: stable
    - run: dart pub global activate dartvulncheck 0.2.3
    - run: dart pub global run dartvulncheck app packages/core
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- No `pub get` needed: only the committed `pubspec.lock` is read.
- `flutter-action` is there so the SDK version can be read from `flutter --version`. For pure Dart projects, `dart-lang/setup-dart` is enough.
- `GITHUB_TOKEN` is needed because the repository-advisory stage makes dozens of requests (60/hour without a token, 1,000/hour with one). The default Actions token is enough.
- Run it on a weekly `schedule` as well as on pull requests: new advisories appear even when your code does not change.
- This complements Dependabot alerts rather than replacing them. Dependabot opens fix PRs; this tool stops CI and also covers the SDK and unreviewed advisories.

## Data sources

| Stage | Source | Covers |
| --- | --- | --- |
| Primary | GitHub Advisory Database (`GET /advisories?ecosystem=pub&affects=…`) | Hosted packages |
| Early warning | Repository security advisories (`GET /repos/{owner}/{repo}/security-advisories`) | Packages with a GitHub repository, plus `dart-lang/sdk` and `flutter/flutter` |
| Fallback | OSV.dev (`POST /v1/querybatch`) | Used only when GitHub is unreachable or answers something that is not an advisory list. Not on rate limiting or a rejected token: those need a fix on your side |

Base URLs can be overridden with `DARTVULNCHECK_GITHUB_API_URL`, `DARTVULNCHECK_OSV_API_URL` and `DARTVULNCHECK_PUB_URL` (for tests and GitHub Enterprise). Overrides must be `https`; `http` is accepted for localhost only, and every override in effect is reported on stderr.

## Limitations

- It does not check whether vulnerable code is actually called. pub advisories do not say which functions are affected, so there is nothing to match a call graph against.
- Advisories that only affect some platforms are reported for all platforms. Use `ignored_advisories` with a comment for the ones that do not apply.
- `git` and `path` dependencies cannot be looked up. They are listed with `--verbose`.
- Repository advisories describe affected versions in free text written by the maintainers. The forms seen so far are read (`< 3.13.7 (stable), < 3.14.0-315.3.beta (beta)`, `Prior to 3.11.0`, `Dart version prior to 2.18.2, Flutter version prior to 3.3.3`, `>=1.0.0 <= 2.7.1`); anything else is reported as "unverified" and not counted unless `--strict`.
- Withdrawn advisories are dropped, and advisories of `dart-lang/sdk` that name no package are matched against the SDK only, not against the packages published from that repository (`meta`, `analyzer`, …).

## Security

[doc/threat-model.md](doc/threat-model.md) is a STRIDE review of the tool itself: what it is trusted with, where untrusted input enters, what is mitigated and what is accepted.

## Development

```sh
dart pub get
dart analyze
dart test
UPDATE_GOLDENS=1 dart test test/report_test.dart  # after an intended output change
```

The GitHub API responses under `test/fixtures/responses/` are recorded, not written by hand. To refresh them, run the `Record API fixtures` workflow in Actions and copy the files from its artifact over the existing ones.

A release is a version bump in `pubspec.yaml` and `lib/src/version.dart`, an entry in `CHANGELOG.md`, and, once that is merged, a `v<version>` tag on `main`; the `Publish to pub.dev` workflow publishes that tag.

Code under `lib/src/` is split by layer: `lockfile/` (input) → `sources/` (lookup) → `match/` (matching) → `report/` (output). `check/` runs them in order, `cli/` handles arguments and exit codes, and `model/` holds the shared types. Only `sources/` talks to the network, so every test runs offline.

## License

MIT
