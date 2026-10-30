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
      ..writeln('SDK（${sdk.info}）')
      ..writeln('  調べられませんでした: ${sdk.error.message}')
      ..writeln();
  }

  for (final (i, project) in result.projects.indexed) {
    if (i > 0) out.writeln();
    switch (project) {
      case FailedProject(:final lockPath, :final error):
        out
          ..writeln(lockPath)
          ..writeln('  調べられませんでした: ${error.message}');
      case CheckedProject():
        out.writeln(_header(project));
        if (!sdkLinePrinted && sdk is SdkChecked) {
          out.writeln('${sdk.info}（${sdk.info.origin}）');
          sdkLinePrinted = true;
        }
        _writeFindings(out, project.findings);
    }
  }

  final s = Summary.of(result);
  out
    ..writeln()
    ..writeln([
      '${s.findings} 件（SDK ${s.sdk}、パッケージ ${s.packages}）',
      '無視 ${s.ignored}',
      if (s.unverified > 0) '要確認 ${s.unverified}',
    ].join('、'));
  return out.toString();
}

void _writeFindings(StringBuffer out, List<Finding> findings) {
  final visible = sortFindings(findings.where((f) => !f.ignored));
  if (visible.isEmpty) {
    out.writeln('  問題なし');
    return;
  }
  for (final (title, group) in [
    ('SDK', visible.where((f) => f.kind.isSdk)),
    ('パッケージ', visible.where((f) => !f.kind.isSdk)),
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
      : '（${[
          'hosted $hosted',
          for (final s in PackageSource.values)
            if (s != PackageSource.hosted && (counts[s] ?? 0) > 0)
              '${s.name} ${counts[s]}',
        ].join('、')}）';
  return '${project.lockPath}  $total packages$detail';
}

void _writeFinding(StringBuffer out, Finding f) {
  final dep =
      f.dependency == null ? '' : '（${_dependencyLabel(f.dependency!)}）';
  final severity = f.kind.isUnverified ? '要確認' : f.severity.name.toUpperCase();
  out.writeln(
      '  ${f.id}  ${f.subject} ${f.current}$dep  $severity  ${f.summary}');
  if (f.kind.isUnverified) {
    out.writeln('    要確認: 影響する版の範囲が書かれていないので版で判定できません。'
        '本文を確認し、該当しなければ ignored_advisories に加えてください');
  }
  out
    ..writeln('    修正: ${_fixLine(f)}')
    ..writeln('    ${f.url}');
}

String _dependencyLabel(Dependency d) => switch (d) {
      Dependency.directMain => '直接',
      Dependency.directDev => '直接 dev',
      Dependency.directOverridden => 'override',
      Dependency.transitive => '推移的',
    };

String _fixLine(Finding f) {
  final fixed = f.fixed;
  if (fixed == null) return '修正版なし';
  if (f.kind.isSdk) {
    final also = f.alsoFixedIn.entries.map((e) => '${e.key} ${e.value}');
    final version = also.isEmpty
        ? '${f.subject} $fixed '
        : '${f.subject} $fixed（${also.join('、')}）';
    return '$versionに上げてビルドし直す';
  }
  if (f.dependency == Dependency.transitive) {
    return '$fixed 以上。推移的な依存なので、親を更新するか dependency_overrides で上げる';
  }
  return '$fixed 以上';
}
