import 'package:pub_semver/pub_semver.dart';

import '../model/advisory.dart';
import '../model/finding.dart';
import 'range.dart';

enum Verdict { vulnerable, unreadable, notAffected }

class Evaluation {
  final Verdict verdict;
  final Version? fixed;
  const Evaluation(this.verdict, [this.fixed]);
}

Evaluation evaluate(
  Version version,
  List<AffectedPackage> entries, {
  String? channel,
  String? product,
}) {
  var vulnerable = false;
  var unreadable = false;
  final fixes = <List<Version>>[];

  for (final e in entries) {
    if (e.ranges.isEmpty) {
      unreadable = true;
      fixes.add(parsePatchedVersions(e.patched));
      continue;
    }
    final ranges = e.ranges.map(parseVulnerableRange).toList();
    if (ranges.contains(null)) {
      unreadable = true;
      fixes.add(parsePatchedVersions(e.patched));
      continue;
    }
    if (ranges
        .any((r) => r!.allows(version, channel: channel, product: product))) {
      vulnerable = true;
      fixes.add(parsePatchedVersions(e.patched));
    }
  }

  if (!vulnerable && !unreadable) {
    return const Evaluation(Verdict.notAffected);
  }
  return Evaluation(
    vulnerable ? Verdict.vulnerable : Verdict.unreadable,
    _pickFix(version, fixes),
  );
}

// No fix when any matching range has none: another range's fix would
// suggest an upgrade that does not help.
// The smallest fix above the current version, not the first listed: SDK
// advisories list one fix per channel ("3.13.7, 3.14.0-315.3.beta"), and a
// beta build must be pointed at the beta fix.
Version? _pickFix(Version current, List<List<Version>> fixes) {
  if (fixes.isEmpty || fixes.any((f) => f.isEmpty)) return null;
  final above = [
    for (final f in fixes)
      for (final v in f)
        if (v > current) v
  ]..sort();
  return above.isEmpty ? null : above.first;
}

// Marked, not removed, so a growing ignore list stays visible.
List<Finding> applyIgnored(List<Finding> findings, Set<String> ignored) {
  if (ignored.isEmpty) return findings;
  final upper = {for (final i in ignored) i.toUpperCase()};
  return [
    for (final f in findings)
      f.allIds.intersection(upper).isNotEmpty ? f.copyWith(ignored: true) : f,
  ];
}
