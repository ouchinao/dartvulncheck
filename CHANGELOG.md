## 0.4.0

- Repository advisories of a package whose GitHub repository was renamed or
  transferred are read again (#10). GitHub answers the old name with a 301 to
  the repository's id on api.github.com; a `GET` now follows a redirect, but
  only to the same origin as the request, with the same headers, for at most
  3 hops. Any other redirect, a redirect of a `POST` and a longer chain are
  still refused, so `GITHUB_TOKEN` never leaves the configured origin.
  `--verbose` lists the repositories that had moved; the `repository advisory
  lookups failed` warning no longer appears for them, and a renamed SDK
  repository no longer fails the SDK check.
- The Dart SDK version is no longer unknown when the Flutter version comes
  from `.fvmrc`, `.fvm/fvm_config.json` or `--sdk-version` (#11). It is taken
  from `flutter` on PATH when that is the same release, otherwise from
  Flutter's release manifest (one request of about 270 KB to
  storage.googleapis.com, without the token). Dart-only SDK advisories are
  then checked for FVM projects and in CI without Flutter, which can turn a
  previously green run red.
- If the manifest cannot be reached or does not list the version, the "Dart
  SDK version is unknown" warning says why, and the exit code stays what it
  was without the lookup. Where the manifest host is blocked, that warning
  can take about 20 seconds to appear (two attempts of 10 seconds).
  `DARTVULNCHECK_FLUTTER_RELEASES_URL` overrides its base URL under the same
  https rule as the other overrides.
- The report names where the Dart version came from when that is not where
  the Flutter version came from: `Flutter 3.47.8 (.fvmrc) / Dart 3.13.7
  (Flutter release manifest)`. The JSON `sdk` object gains
  `dartOrigin`; the format version stays 1.
- A Dart SDK version written `3.14.0 (build 3.14.0-315.1.beta)`, as
  `flutter --version` and `dart --version` print it on the beta channel, is
  read as `3.14.0-315.1.beta`. 0.3.0 read it as `3.14.0`, which compared as
  fixed against a bound such as `< 3.14.0-315.3.beta (beta)`.
- The override warning mentions the token only for
  `DARTVULNCHECK_GITHUB_API_URL`, the one override that receives it.
- Library: `RepositoryAdvisoryFetcher.fetch` returns a sealed
  `RepositoryLookup`, `GitHubClient.getAllPages` gains an optional `onMoved`
  callback, and `Checker` takes a `FlutterReleases`.

## 0.3.0

- Each run asks pub.dev for the latest release of dartvulncheck and warns on
  stderr when a newer one exists. Upgrade with the same install command and
  the new version. A failed lookup never changes the output or the exit
  code; `--verbose` says why it was skipped.

## 0.2.3

- The install lines in the README and the example name the current version;
  0.2.2 still showed 0.2.1. A test now keeps them in step with the version.
- The threat model and a code comment gave a wrong reason for not following
  redirects. No change to the tool.

## 0.2.2

- Published to pub.dev by the `Publish to pub.dev` workflow from the
  `v<version>` tag. No change to the tool.

## 0.2.1

- First version on pub.dev: `dart pub global activate dartvulncheck`.
- `docs/` is now `doc/`, as the pub package layout expects; the threat model
  is at `doc/threat-model.md`.
- An `example/` with the CI job and the command lines.

## 0.2.0

- Endpoint overrides (`DARTVULNCHECK_*_URL`) must be `https`; `http` is
  accepted for localhost only. Every override in effect is reported on
  stderr.
- Redirects are no longer followed, and page links are followed only within
  the configured API origin, so `GITHUB_TOKEN` is never sent elsewhere.
- Pagination stops after 50 pages, and a response is read with a 16 MiB cap.
- A repository's advisories apply only to the packages pub.dev maps to that
  repository, not to every locked package they name.
- On Windows, `flutter` and `dart` are started from their `PATH` location,
  never from the project directory.
- The SDK version from `.fvmrc` or `--sdk-version` is compared with `flutter`
  on `PATH`, and a difference is warned about.
- Packages from a registry other than pub.dev are warned about on every run;
  `--verbose` prints only the registry's host.
- The text report lists ignored findings under `Ignored`.
- `docs/threat-model.md`: a STRIDE review of the tool itself.

## 0.1.0

- First version.
- Checks hosted packages in `pubspec.lock` against the GitHub Advisory
  Database, with OSV.dev as a fallback when GitHub is unreachable.
- Checks repository security advisories of each package's GitHub repository
  (needs `GITHUB_TOKEN`), to catch issues before GitHub reviews them.
- Checks the Flutter / Dart SDK version against advisories in
  `dart-lang/sdk` and `flutter/flutter`.
- Honours `ignored_advisories` in `pubspec.yaml`.
- Text and `--json` output; exit codes 0 / 1 / 3.
