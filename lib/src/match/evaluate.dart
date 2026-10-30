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

Evaluation evaluate(Version version, List<AffectedPackage> entries) {
  var vulnerable = false;
  var unreadable = false;
  final fixes = <Version?>[];

  for (final e in entries) {
    if (e.ranges.isEmpty) {
      unreadable = true;
      fixes.add(parsePatchedVersion(e.patched));
      continue;
    }
    final constraints = e.ranges.map(parseVulnerableRange).toList();
    if (constraints.contains(null)) {
      unreadable = true;
      fixes.add(parsePatchedVersion(e.patched));
      continue;
    }
    if (constraints.any((c) => c!.allows(version))) {
      vulnerable = true;
      fixes.add(parsePatchedVersion(e.patched));
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
Version? _pickFix(Version current, List<Version?> fixes) {
  if (fixes.isEmpty || fixes.contains(null)) return null;
  final above = fixes.whereType<Version>().where((v) => v > current).toList()
    ..sort();
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
