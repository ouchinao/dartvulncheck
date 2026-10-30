import 'severity.dart';

enum AdvisoryOrigin {
  global,
  repository,
  osv;

  bool get serverMatched => this != AdvisoryOrigin.repository;
}

class AffectedPackage {
  final String? name;
  final String? ecosystem;

  // Kept as text, not parsed here: match/ turns an unreadable range into
  // unverified instead of the source silently dropping it.
  final List<String> ranges;
  final String? patched;

  const AffectedPackage({
    this.name,
    this.ecosystem,
    this.ranges = const [],
    this.patched,
  });

  bool get hasName => name != null && name!.trim().isNotEmpty;
}

class Advisory {
  final String id;
  final List<String> aliases;
  final String summary;
  final Severity severity;
  final Uri url;
  final AdvisoryOrigin origin;
  final List<AffectedPackage> affected;
  final String? repository;

  const Advisory({
    required this.id,
    this.aliases = const [],
    required this.summary,
    required this.severity,
    required this.url,
    required this.origin,
    this.affected = const [],
    this.repository,
  });

  Set<String> get allIds =>
      {id.toUpperCase(), for (final a in aliases) a.toUpperCase()};
}
