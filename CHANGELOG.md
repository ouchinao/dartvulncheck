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
