import '../model/finding.dart';
import '../model/package_ref.dart';
import '../check/result.dart';
import 'summary.dart';

// No colours: escape codes garble CI logs.
String renderText(CheckResult result) {
  final out = StringBuffer();
  var sdkLinePrinted = false;

  final sdk = result.sdk;
  if (sdk is SdkFailed) {
    out
      ..writeln('SDK (${sdk.info})')
      ..writeln('  Could not check: ${sdk.error.message}')
      ..writeln();
  }

  for (final (i, project) in result.projects.indexed) {
    if (i > 0) out.writeln();
    switch (project) {
      case FailedProject(:final lockPath, :final error):
        out
          ..writeln(lockPath)
          ..writeln('  Could not check: ${error.message}');
      case CheckedProject():
        out.writeln(_header(project));
        if (!sdkLinePrinted && sdk is SdkChecked) {
          out.writeln('${sdk.info} (${sdk.info.origin})');
          sdkLinePrinted = true;
        }
        _writeFindings(out, project.findings);
    }
  }

  final s = Summary.of(result);
  out
    ..writeln()
    ..writeln([
      '${s.findings} ${s.findings == 1 ? 'finding' : 'findings'} '
          '(SDK ${s.sdk}, packages ${s.packages})',
      '${s.ignored} ignored',
      if (s.unverified > 0) '${s.unverified} unverified',
    ].join(', '));
  return out.toString();
}

void _writeFindings(StringBuffer out, List<Finding> findings) {
  final visible = sortFindings(findings.where((f) => !f.ignored));
  if (visible.isEmpty) {
    out.writeln('  No problems found');
    return;
  }
  for (final (title, group) in [
    ('SDK', visible.where((f) => f.kind.isSdk)),
    ('Packages', visible.where((f) => !f.kind.isSdk)),
  ]) {
    if (group.isEmpty) continue;
    out
      ..writeln()
      ..writeln(title);
    for (final f in group) {
      _writeFinding(out, f);
    }
  }
}

String _header(CheckedProject project) {
  final counts = project.packages.bySource;
  final total = project.packages.total;
  final hosted = counts[PackageSource.hosted] ?? 0;
  final detail = hosted == total
      ? ''
      : ' (${[
          'hosted $hosted',
          for (final s in PackageSource.values)
            if (s != PackageSource.hosted && (counts[s] ?? 0) > 0)
              '${s.name} ${counts[s]}',
        ].join(', ')})';
  final noun = total == 1 ? 'package' : 'packages';
  return '${project.lockPath}  $total $noun$detail';
}

void _writeFinding(StringBuffer out, Finding f) {
  final dep =
      f.dependency == null ? '' : ' (${_dependencyLabel(f.dependency!)})';
  final severity =
      f.kind.isUnverified ? 'UNVERIFIED' : f.severity.name.toUpperCase();
  out.writeln(
      '  ${f.id}  ${f.subject} ${f.current}$dep  $severity  ${f.summary}');
  if (f.kind.isUnverified) {
    out.writeln('    Unverified: the advisory gives no affected range, so the '
        'version cannot decide. Read it, and add it to ignored_advisories '
        'if it does not apply');
  }
  out
    ..writeln('    Fix: ${_fixLine(f)}')
    ..writeln('    ${f.url}');
}

String _dependencyLabel(Dependency d) => switch (d) {
      Dependency.directMain => 'direct',
      Dependency.directDev => 'direct dev',
      Dependency.directOverridden => 'override',
      Dependency.transitive => 'transitive',
    };

String _fixLine(Finding f) {
  final fixed = f.fixed;
  if (fixed == null) return 'no fixed version yet';
  if (f.kind.isSdk) {
    final also = f.alsoFixedIn.entries.map((e) => '${e.key} ${e.value}');
    final suffix = also.isEmpty ? '' : ' (${also.join(', ')})';
    return 'upgrade to ${f.subject} $fixed$suffix and rebuild';
  }
  if (f.dependency == Dependency.transitive) {
    return '$fixed or later. It is transitive: upgrade the package that '
        'depends on it, or use dependency_overrides';
  }
  return '$fixed or later';
}
