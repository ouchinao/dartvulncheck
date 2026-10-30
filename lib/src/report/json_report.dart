import 'dart:convert';

import '../model/finding.dart';
import '../version.dart';
import 'result.dart';

// Readers check this, so bump it on any incompatible change instead of
// changing the shape silently.
const jsonFormatVersion = 1;

String renderJson(CheckResult result) {
  final s = result.summarize();
  final sdk = result.sdk;
  final json = {
    'version': jsonFormatVersion,
    'tool': {'name': 'dartvulncheck', 'version': packageVersion},
    'sdk': sdk == null
        ? null
        : {
            'flutter': sdk.flutter?.toString(),
            'dart': sdk.dart?.toString(),
            'channel': sdk.channel,
            'origin': sdk.origin,
          },
    'projects': [for (final p in result.projects) _project(p)],
    'summary': {
      'findings': s.findings,
      'ignored': s.ignored,
      'unverified': s.unverified,
    },
  };
  return '${const JsonEncoder.withIndent('  ').convert(json)}\n';
}

Map<String, Object?> _project(ProjectResult p) {
  final lock = p.lockfile;
  return {
    'path': p.dir,
    if (p.error != null) 'error': p.error!.message,
    'packages': lock == null
        ? null
        : {
            'total': lock.total,
            'queried': p.queried,
            'skipped': [for (final s in lock.skipped) '$s'],
          },
    'findings': [for (final f in p.findings) findingToJson(f)],
  };
}

Map<String, Object?> findingToJson(Finding f) => {
      'id': f.id,
      'aliases': f.aliases,
      'kind': f.kind.jsonName,
      'subject': f.subject,
      'current': '${f.current}',
      'fixed': f.fixed?.toString(),
      'alsoFixedIn': {
        for (final e in f.alsoFixedIn.entries) e.key: '${e.value}',
      },
      'dependency': f.dependency?.jsonName,
      'severity': f.severity.name,
      'summary': f.summary,
      'url': '${f.url}',
      'ignored': f.ignored,
    };
