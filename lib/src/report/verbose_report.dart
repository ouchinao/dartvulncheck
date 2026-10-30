import '../check/result.dart';

String renderVerbose(CheckResult result) {
  final out = StringBuffer();
  for (final project in result.projects.whereType<CheckedProject>()) {
    final counts = project.packages;
    final ignored = project.findings.where((f) => f.ignored).toList();
    out.writeln('${project.dir}: ${counts.queried} queried, '
        '${ignored.length} ignored');
    if (counts.skippedTransitive > 0) {
      out.writeln('  transitive dependencies skipped by --no-transitive: '
          '${counts.skippedTransitive}');
    }
    if (counts.skipped.isNotEmpty) {
      out.writeln('  not looked up: ${counts.skipped.join(', ')}');
    }
    for (final pkg in counts.thirdPartyHosted) {
      out.writeln('  $pkg: hosted outside pub.dev; checked against '
          'advisories for the pub.dev package of the same name');
    }
    for (final f in ignored) {
      out.writeln('  ignored: ${f.id} ${f.subject} ${f.current}');
    }
  }
  if (result.sourceNotes.isNotEmpty) {
    out.writeln('repository advisories:');
    for (final note in result.sourceNotes) {
      out.writeln('  $note');
    }
  }
  return '$out';
}
