import 'package:pub_semver/pub_semver.dart';

import '../model/advisory.dart';
import '../model/finding.dart';
import '../model/package_ref.dart';
import '../model/sdk_info.dart';
import '../model/severity.dart';
import 'range.dart';

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

      final result = _evaluate(package.version, entries);
      final FindingKind kind;
      switch (result.verdict) {
        case _Verdict.vulnerable:
          kind = FindingKind.package;
        case _Verdict.unreadable:
          // Not 要確認: the server already matched the version.
          kind = advisory.origin.serverMatched
              ? FindingKind.package
              : FindingKind.packageUnverified;
        case _Verdict.notAffected:
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

class SdkMatch {
  final List<Finding> findings;
  final bool dartVersionUnknown;
  const SdkMatch(this.findings, {this.dartVersionUnknown = false});
}

// Flutter advisories are not applied to pure Dart projects: they do not
// ship the Flutter framework.
SdkMatch matchSdk(
  SdkInfo sdk,
  List<Advisory> advisories, {
  bool includeFlutter = true,
  Set<String> ignored = const {},
}) {
  var dartUnknown = false;
  final raw = <Finding>[];

  for (final advisory in advisories) {
    final bySubject = <String, List<AffectedPackage>>{};
    // Not skipped when vulnerabilities[] is empty: it still concerns the SDK
    // of its repository, as 要確認.
    final entries = advisory.affected.isEmpty
        ? const [AffectedPackage()]
        : advisory.affected;
    for (final e in entries) {
      final subject = sdkSubject(e, advisory.repository);
      if (subject != null) (bySubject[subject] ??= []).add(e);
    }
    for (final MapEntry(key: subject, value: entries) in bySubject.entries) {
      if (subject == 'Flutter' && !includeFlutter) continue;
      final current = subject == 'Flutter' ? sdk.flutter : sdk.dart;
      if (current == null) {
        if (subject == 'Dart') dartUnknown = true;
        continue;
      }
      final result = _evaluate(current, entries);
      final FindingKind kind;
      switch (result.verdict) {
        case _Verdict.vulnerable:
          kind = FindingKind.sdk;
        case _Verdict.unreadable:
          kind = FindingKind.sdkUnverified;
        case _Verdict.notAffected:
          continue;
      }
      raw.add(Finding(
        id: advisory.id,
        aliases: advisory.aliases,
        kind: kind,
        subject: subject,
        current: current,
        fixed: result.fixed,
        severity: advisory.severity,
        summary: advisory.summary,
        url: advisory.url,
      ));
    }
  }

  return SdkMatch(applyIgnored(_mergeSdk(raw), ignored),
      dartVersionUnknown: dartUnknown);
}

String? sdkSubject(AffectedPackage e, String? repository) {
  if (!e.hasName) {
    return switch (repository) {
      'flutter/flutter' => 'Flutter',
      'dart-lang/sdk' => 'Dart',
      _ => null,
    };
  }
  final name = e.name!.trim().toLowerCase();
  if (name == 'flutter' || name == 'flutter sdk' || name == 'flutter_sdk') {
    return 'Flutter';
  }
  if (name == 'dart' ||
      name == 'sdk' ||
      name == 'dart sdk' ||
      name == 'dart-sdk' ||
      name == 'dart_sdk') {
    return 'Dart';
  }
  return null;
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

enum _Verdict { vulnerable, unreadable, notAffected }

class _Evaluation {
  final _Verdict verdict;
  final Version? fixed;
  const _Evaluation(this.verdict, [this.fixed]);
}

_Evaluation _evaluate(Version version, List<AffectedPackage> entries) {
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
    return const _Evaluation(_Verdict.notAffected);
  }
  return _Evaluation(
    vulnerable ? _Verdict.vulnerable : _Verdict.unreadable,
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

// Merged by id or alias rather than reported per repository: the same
// issue is often published in both dart-lang/sdk and flutter/flutter.
List<Finding> _mergeSdk(List<Finding> raw) {
  final groups = <List<Finding>>[];
  for (final f in raw) {
    final hits = groups
        .where((g) => g.any((x) => x.allIds.intersection(f.allIds).isNotEmpty))
        .toList();
    if (hits.isEmpty) {
      groups.add([f]);
    } else {
      final merged = [for (final g in hits) ...g, f];
      groups.removeWhere(hits.contains);
      groups.add(merged);
    }
  }

  return [
    for (final g in groups) _pickSdk(g),
  ];
}

Finding _pickSdk(List<Finding> group) {
  int score(Finding f) =>
      (f.kind.isUnverified ? 0 : 2) + (f.subject == 'Flutter' ? 1 : 0);
  // First highest score wins, so the order advisories arrived in decides
  // ties (dart-lang/sdk is fetched before flutter/flutter).
  var main = group.first;
  for (final f in group.skip(1)) {
    if (score(f) > score(main)) main = f;
  }

  final also = <String, Version>{};
  for (final f in group) {
    if (f.subject != main.subject && !f.kind.isUnverified && f.fixed != null) {
      also.putIfAbsent(f.subject, () => f.fixed!);
    }
  }
  final ids = <String>{};
  for (final f in group) {
    ids
      ..add(f.id)
      ..addAll(f.aliases);
  }
  ids.removeWhere((x) => x.toUpperCase() == main.id.toUpperCase());

  final severity = group.map((f) => f.severity).reduce((a, b) => _worse(a, b));

  return Finding(
    id: main.id,
    aliases: ids.toList(),
    kind: main.kind,
    subject: main.subject,
    current: main.current,
    fixed: main.fixed,
    alsoFixedIn: also,
    severity: severity,
    summary: main.summary,
    url: main.url,
  );
}

Severity _worse(Severity a, Severity b) {
  if (a == Severity.unknown) return b;
  if (b == Severity.unknown) return a;
  return a.rank >= b.rank ? a : b;
}
