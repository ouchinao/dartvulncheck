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
