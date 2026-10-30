import '../check/result.dart';

String renderVerbose(CheckResult result) {
  final out = StringBuffer();
  for (final project in result.projects.whereType<CheckedProject>()) {
    final counts = project.packages;
    final ignored = project.findings.where((f) => f.ignored).toList();
    out.writeln('${project.dir}: 照会 ${counts.queried} 件、'
        '無視 ${ignored.length} 件');
    if (counts.skippedTransitive > 0) {
      out.writeln('  --no-transitive で飛ばした推移的依存: '
          '${counts.skippedTransitive} 件');
    }
    if (counts.skipped.isNotEmpty) {
      out.writeln('  照会できなかったパッケージ: ${counts.skipped.join(', ')}');
    }
    for (final pkg in counts.thirdPartyHosted) {
      out.writeln('  $pkg: pub.dev 以外でホストされています。'
          'pub.dev の同名パッケージのアドバイザリと照合しています');
    }
    for (final f in ignored) {
      out.writeln('  無視: ${f.id} ${f.subject} ${f.current}');
    }
  }
  if (result.sourceNotes.isNotEmpty) {
    out.writeln('リポジトリアドバイザリ:');
    for (final note in result.sourceNotes) {
      out.writeln('  $note');
    }
  }
  return '$out';
}
