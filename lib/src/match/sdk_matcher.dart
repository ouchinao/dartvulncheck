import 'package:pub_semver/pub_semver.dart';

import '../model/advisory.dart';
import '../model/finding.dart';
import '../model/sdk_info.dart';
import '../model/severity.dart';
import 'evaluate.dart';

// Flutter advisories are not applied to pure Dart projects: they do not
// ship the Flutter framework.
List<Finding> matchSdk(
  SdkInfo sdk,
  List<Advisory> advisories, {
  bool includeFlutter = true,
  Set<String> ignored = const {},
}) {
  final raw = <Finding>[];

  for (final advisory in advisories) {
    final bySubject = <String, List<AffectedPackage>>{};
    for (final e in _entries(advisory)) {
      final subject = sdkSubject(e, advisory.repository);
      if (subject != null) (bySubject[subject] ??= []).add(e);
    }
    for (final MapEntry(key: subject, value: entries) in bySubject.entries) {
      if (subject == 'Flutter' && !includeFlutter) continue;
      final current = subject == 'Flutter' ? sdk.flutter : sdk.dart;
      if (current == null) continue;
      final result =
          evaluate(current, entries, channel: sdk.channel, product: subject);
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

  return applyIgnored(_mergeSdk(raw), ignored);
}

// Asked once per run, not reported by matchSdk per project: whether the
// Dart version matters depends only on the advisories, and the warning
// should appear once.
bool hasDartAdvisories(List<Advisory> advisories) => advisories
    .any((a) => _entries(a).any((e) => sdkSubject(e, a.repository) == 'Dart'));

// Not skipped when vulnerabilities[] is empty: it still concerns the SDK of
// its repository, as unverified.
List<AffectedPackage> _entries(Advisory a) =>
    a.affected.isEmpty ? const [AffectedPackage()] : a.affected;

// The ecosystem field is read as well as the name: dart-lang/sdk writes its
// advisories by hand, with names such as "Core SDK" and ecosystems such as
// "dart sdk", "core sdk", "dart" or nothing at all.
String? sdkSubject(AffectedPackage e, String? repository) {
  final name = (e.name ?? '').trim().toLowerCase();
  final ecosystem = (e.ecosystem ?? '').trim().toLowerCase();
  if (_flutterWords.contains(name)) return 'Flutter';
  if (_dartWords.contains(name)) return 'Dart';
  final generic = name.isEmpty || _genericWords.contains(name);
  if (generic && _flutterWords.contains(ecosystem)) return 'Flutter';
  if (generic && _dartWords.contains(ecosystem)) return 'Dart';
  if (_genericWords.contains(name)) return 'Dart';
  if (name.isEmpty) {
    return switch (repository) {
      'flutter/flutter' => 'Flutter',
      'dart-lang/sdk' => 'Dart',
      _ => null,
    };
  }
  return null;
}

const _flutterWords = {'flutter', 'flutter sdk', 'flutter_sdk', 'flutter-sdk'};
const _dartWords = {'dart', 'dart sdk', 'dart_sdk', 'dart-sdk'};
const _genericWords = {'sdk', 'core sdk', 'core_sdk', 'core-sdk'};

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
