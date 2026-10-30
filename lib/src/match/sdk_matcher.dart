import 'package:pub_semver/pub_semver.dart';

import '../model/advisory.dart';
import '../model/finding.dart';
import '../model/sdk_info.dart';
import '../model/severity.dart';
import 'evaluate.dart';

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
    // of its repository, as unverified.
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
      final result = evaluate(current, entries);
      final FindingKind kind;
      switch (result.verdict) {
        case Verdict.vulnerable:
          kind = FindingKind.sdk;
        case Verdict.unreadable:
          kind = FindingKind.sdkUnverified;
        case Verdict.notAffected:
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
  // A first-max loop, not List.sort: sort is not stable, so ties would be
  // decided at random instead of by arrival (dart-lang/sdk first).
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
