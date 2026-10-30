import 'package:pub_semver/pub_semver.dart';

import 'package_ref.dart';
import 'severity.dart';

enum FindingKind {
  package,
  packageUnverified,
  sdk,
  sdkUnverified;

  bool get isSdk => this == sdk || this == sdkUnverified;

  bool get isUnverified => this == packageUnverified || this == sdkUnverified;

  String get jsonName => name;
}

class Finding {
  final String id;
  final List<String> aliases;
  final FindingKind kind;
  final String subject;
  final Version current;
  final Version? fixed;
  final Map<String, Version> alsoFixedIn;
  final Dependency? dependency;
  final Severity severity;
  final String summary;
  final Uri url;
  final bool ignored;

  const Finding({
    required this.id,
    this.aliases = const [],
    required this.kind,
    required this.subject,
    required this.current,
    this.fixed,
    this.alsoFixedIn = const {},
    this.dependency,
    required this.severity,
    required this.summary,
    required this.url,
    this.ignored = false,
  });

  Set<String> get allIds =>
      {id.toUpperCase(), for (final a in aliases) a.toUpperCase()};

  Finding copyWith({
    List<String>? aliases,
    Version? fixed,
    Map<String, Version>? alsoFixedIn,
    bool? ignored,
  }) =>
      Finding(
        id: id,
        aliases: aliases ?? this.aliases,
        kind: kind,
        subject: subject,
        current: current,
        fixed: fixed ?? this.fixed,
        alsoFixedIn: alsoFixedIn ?? this.alsoFixedIn,
        dependency: dependency,
        severity: severity,
        summary: summary,
        url: url,
        ignored: ignored ?? this.ignored,
      );

  bool counts({required Severity failOn, required bool strict}) {
    if (ignored) return false;
    if (kind.isUnverified && !strict) return false;
    return severity.isAtLeast(failOn);
  }
}
