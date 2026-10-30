import '../model/advisory.dart';
import '../model/finding.dart';
import '../model/package_ref.dart';
import 'evaluate.dart';

// Server-matched advisories are re-checked, not trusted outright: one
// advisory can list several packages, not all at affected versions.
// A repository advisory is not used when a reviewed one with the same id
// covers the package: the reviewed range is the more reliable one.
List<Finding> matchPackages(
  List<PackageRef> packages,
  List<Advisory> advisories, {
  Set<String> ignored = const {},
}) {
  final byName = {for (final p in packages) p.name: p};
  final ordered = [
    ...advisories.where((a) => a.origin.serverMatched),
    ...advisories.where((a) => !a.origin.serverMatched),
  ];
  final reviewedIds = <String, Set<String>>{};
  final findings = <Finding>[];

  for (final advisory in ordered) {
    final entriesByName = <String, List<AffectedPackage>>{};
    for (final e in advisory.affected) {
      if (e.hasName) (entriesByName[e.name!] ??= []).add(e);
    }
    for (final MapEntry(key: name, value: entries) in entriesByName.entries) {
      final package = byName[name];
      if (package == null) continue;

      final seen = reviewedIds[name] ??= {};
      if (advisory.origin.serverMatched) {
        seen.addAll(advisory.allIds);
      } else if (seen.intersection(advisory.allIds).isNotEmpty) {
        continue;
      }

      final result = evaluate(package.version, entries);
      final FindingKind kind;
      switch (result.verdict) {
        case Verdict.vulnerable:
          kind = FindingKind.package;
        case Verdict.unreadable:
          // Not 要確認: the server already matched the version.
          kind = advisory.origin.serverMatched
              ? FindingKind.package
              : FindingKind.packageUnverified;
        case Verdict.notAffected:
          continue;
      }

      _addOrMerge(
        findings,
        Finding(
          id: advisory.id,
          aliases: advisory.aliases,
          kind: kind,
          subject: package.name,
          current: package.version,
          fixed: result.fixed,
          dependency: package.dependency,
          severity: advisory.severity,
          summary: advisory.summary,
          url: advisory.url,
        ),
      );
    }
  }
  return applyIgnored(findings, ignored);
}

void _addOrMerge(List<Finding> findings, Finding next) {
  for (var i = 0; i < findings.length; i++) {
    final f = findings[i];
    if (f.subject != next.subject) continue;
    if (f.allIds.intersection(next.allIds).isEmpty) continue;
    final aliases = _mergeAliases(f, next);
    final keepNext = f.kind.isUnverified && !next.kind.isUnverified;
    findings[i] = (keepNext ? next : f).copyWith(aliases: aliases);
    return;
  }
  findings.add(next);
}

List<String> _mergeAliases(Finding a, Finding b) {
  final primary = a.id.toUpperCase();
  final out = <String>{};
  for (final x in [...a.aliases, b.id, ...b.aliases]) {
    if (x.toUpperCase() != primary) out.add(x);
  }
  return out.toList();
}
