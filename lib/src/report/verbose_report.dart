import '../check/result.dart';
import '../model/package_ref.dart';
import 'notice_text.dart';

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
      out.writeln(
          '  not looked up: ${counts.skipped.map(_skippedLabel).join(', ')}');
    }
    for (final pkg in counts.thirdPartyHosted) {
      // The host only, not the URL: a registry URL may carry credentials in
      // its userinfo, and this line ends up in a CI log.
      out.writeln(
          '  ${pkg.name} (${pkg.hostedUrl?.host}): hosted outside pub.dev; '
          'checked against '
          'advisories for the pub.dev package of the same name');
    }
    for (final f in ignored) {
      out.writeln('  ignored: ${f.id} ${f.subject} ${f.current}');
    }
  }
  if (result.sourceNotes.isNotEmpty) {
    out.writeln('repository advisories:');
    for (final note in result.sourceNotes) {
      out.writeln('  ${note.subject}: ${describeNote(note)}');
    }
  }
  return '$out';
}

String _skippedLabel(SkippedPackage s) => switch (s) {
      NotHosted(:final source) => '${s.name} (${source.name})',
      InvalidVersion(:final version) =>
        '${s.name} (invalid version "$version")',
    };
