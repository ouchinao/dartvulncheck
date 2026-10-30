import 'dart:convert';

import '../model/finding.dart';
import '../version.dart';
import '../check/result.dart';
import '../model/package_ref.dart';
import 'summary.dart';

// Readers check this, so bump it on any incompatible change instead of
// changing the shape silently.
const jsonFormatVersion = 1;

String renderJson(CheckResult result) {
  final s = Summary.of(result);
  final json = {
    'version': jsonFormatVersion,
    'tool': {'name': 'dartvulncheck', 'version': packageVersion},
    'sdk': _sdk(result.sdk),
    'projects': [for (final p in result.projects) _project(p)],
    'summary': {
      'findings': s.findings,
      'ignored': s.ignored,
      'unverified': s.unverified,
    },
  };
  return '${const JsonEncoder.withIndent('  ').convert(json)}\n';
}

Map<String, Object?>? _sdk(SdkStatus status) {
  final (info, error) = switch (status) {
    SdkNotChecked() || SdkNotFound() => (null, null),
    SdkChecked(:final info) => (info, null),
    SdkFailed(:final info, :final error) => (info, error),
  };
  if (info == null) return null;
  return {
    'flutter': info.flutter?.toString(),
    'dart': info.dart?.toString(),
    'channel': info.channel,
    'origin': info.origin,
    if (error != null) 'error': error.message,
  };
}

Map<String, Object?> _project(ProjectResult p) => switch (p) {
      FailedProject(:final error) => {
          'path': p.dir,
          'error': error.message,
          'packages': null,
          'findings': const <Object?>[],
        },
      CheckedProject(:final packages, :final findings) => {
          'path': p.dir,
          'packages': {
            'total': packages.total,
            'queried': packages.queried,
            'skipped': [
              for (final s in packages.skipped) '${s.name} (${s.reason})',
            ],
          },
          'findings': [
            for (final f in sortFindings(findings)) findingToJson(f)
          ],
        },
    };

// JSON names live here, not on the model enums: they are this format's
// contract, and the model should not change when the format does.
Map<String, Object?> findingToJson(Finding f) => {
      'id': f.id,
      'aliases': f.aliases,
      'kind': f.kind.name,
      'subject': f.subject,
      'current': '${f.current}',
      'fixed': f.fixed?.toString(),
      'alsoFixedIn': {
        for (final e in f.alsoFixedIn.entries) e.key: '${e.value}',
      },
      'dependency': switch (f.dependency) {
        null => null,
        Dependency.directMain => 'direct main',
        Dependency.directDev => 'direct dev',
        Dependency.directOverridden => 'direct overridden',
        Dependency.transitive => 'transitive',
      },
      'severity': f.severity.name,
      'summary': f.summary,
      'url': '${f.url}',
      'ignored': f.ignored,
    };
