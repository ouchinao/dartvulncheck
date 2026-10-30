import '../model/finding.dart';
import '../model/package_ref.dart';
import 'result.dart';

// No colours: escape codes garble CI logs.
String renderText(CheckResult result) {
  final out = StringBuffer();
  var sdkLinePrinted = false;

  for (final (i, project) in result.projects.indexed) {
    if (i > 0) out.writeln();
    out.writeln(_header(project));

    if (!sdkLinePrinted && result.sdk != null && project.error == null) {
      out.writeln('${result.sdk}（${result.sdk!.origin}）');
      sdkLinePrinted = true;
    }

    if (project.error != null) {
      out.writeln('  調べられませんでした: ${project.error!.message}');
      continue;
    }

    final visible = project.findings.where((f) => !f.ignored).toList();
    if (visible.isEmpty) {
      out.writeln('  問題なし');
      continue;
    }

    final sdk = visible.where((f) => f.kind.isSdk).toList();
    final packages = visible.where((f) => !f.kind.isSdk).toList();
    if (sdk.isNotEmpty) {
      out
        ..writeln()
        ..writeln('SDK');
      for (final f in sdk) {
        _writeFinding(out, f);
      }
    }
    if (packages.isNotEmpty) {
      out
        ..writeln()
        ..writeln('パッケージ');
      for (final f in packages) {
        _writeFinding(out, f);
      }
    }
  }

  final s = result.summarize();
  out
    ..writeln()
    ..writeln([
      '${s.findings} 件（SDK ${s.sdk}、パッケージ ${s.packages}）',
      '無視 ${s.ignored}',
      if (s.unverified > 0) '要確認 ${s.unverified}',
    ].join('、'));
  return out.toString();
}

String _header(ProjectResult project) {
  final lock = project.lockfile;
  if (lock == null) return project.lockPath;
  final counts = lock.countBySource;
  final hosted = counts[PackageSource.hosted] ?? 0;
  final detail = hosted == lock.total
      ? ''
      : '（${[
          'hosted $hosted',
          for (final s in PackageSource.values)
            if (s != PackageSource.hosted && (counts[s] ?? 0) > 0)
              '${s.name} ${counts[s]}',
        ].join('、')}）';
  return '${project.lockPath}  ${lock.total} packages$detail';
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
