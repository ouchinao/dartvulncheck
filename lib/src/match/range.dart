import 'package:pub_semver/pub_semver.dart';

class RangeClause {
  final VersionConstraint constraint;

  // `stable` / `beta` / `dev` / `main`, from "< 3.13.7 (stable)".
  final String? channel;

  // `Dart` / `Flutter`, from "Flutter version prior to 3.3.3".
  final String? product;

  const RangeClause(this.constraint, {this.channel, this.product});
}

class VulnerableRange {
  final List<RangeClause> clauses;
  const VulnerableRange(this.clauses);

  bool get _annotated =>
      clauses.any((c) => c.channel != null || c.product != null);

  // Plain clauses are intersected, as in GitHub's own ">= 1.0.0, < 1.2.0".
  // Annotated clauses are not: SDK advisories write one clause per channel
  // or product ("< 3.13.7 (stable), < 3.14.0-315.3.beta (beta)"), and
  // intersecting those would match nothing, while a plain union would flag
  // a fixed stable build as below the beta bound. Each clause applies only
  // to its channel or product, and the version is affected if any applies.
  bool allows(Version version, {String? channel, String? product}) {
    if (!_annotated) {
      return clauses.every((c) => c.constraint.allows(version));
    }
    final versionChannel =
        _channel(channel) ?? (version.isPreRelease ? null : 'stable');
    for (final c in clauses) {
      if (c.product != null && c.product != product) continue;
      if (c.channel != null) {
        // A pre-release of unknown channel may be beta, dev or main, so
        // every non-stable clause applies to it.
        if (versionChannel == null
            ? c.channel == 'stable'
            : c.channel != versionChannel) {
          continue;
        }
      }
      if (c.constraint.allows(version)) return true;
    }
    return false;
  }
}

// Not VersionConstraint.parse: it treats `<3.13.7` as excluding
// `3.13.7-dev.1`, which is right for dependency resolution but wrong here. A
// pre-release of the fixed version was cut before the fix, and missing it
// would let beta builds such as `3.50.0-0.2.pre` through. And GitHub's
// repository advisories are free text that `parse` would reject outright:
// "Prior to 3.11.0", ">=1.0.0 <= 2.7.1", "Dart version prior to 2.18.2".
VulnerableRange? parseVulnerableRange(String text) {
  final clauses = <RangeClause>[];
  for (final part in text.split(',')) {
    if (part.trim().isEmpty) continue;
    final clause = _parseClause(part.trim());
    if (clause == null) return null;
    clauses.add(clause);
  }
  return clauses.isEmpty ? null : VulnerableRange(clauses);
}

List<Version> parsePatchedVersions(String? text) {
  if (text == null) return const [];
  final out = <Version>[];
  for (final m in _versionToken.allMatches(text)) {
    try {
      out.add(Version.parse(m.group(0)!));
    } on FormatException {
      continue;
    }
  }
  return out;
}

final _channelSuffix =
    RegExp(r'\s*\((stable|beta|dev|main|master)\)\s*$', caseSensitive: false);
final _productPrefix = RegExp(r'^(dart|flutter)(\s+sdk)?(\s+versions?)?\b\s*',
    caseSensitive: false);
final _versionsPrefix = RegExp(r'^versions?\s+', caseSensitive: false);
final _prose = RegExp(
    r'\b(prior to|earlier than|older than|lower than|less than|before)\s+',
    caseSensitive: false);
final _constraint = RegExp(r'(>=|<=|>|<|==|=)?\s*([0-9][^\s,()]*)');
final _versionToken = RegExp(r'[0-9][^\s,()]*');

RangeClause? _parseClause(String part) {
  var text = part;
  String? channel, product;
  final ch = _channelSuffix.firstMatch(text);
  if (ch != null) {
    channel = _channel(ch.group(1));
    text = text.substring(0, ch.start);
  }
  final pr = _productPrefix.firstMatch(text);
  if (pr != null) {
    product = pr.group(1)!.toLowerCase() == 'dart' ? 'Dart' : 'Flutter';
    text = text.substring(pr.end);
  }
  text = text.replaceFirst(_versionsPrefix, '').replaceAll(_prose, '< ');

  final constraints = <(String?, Version)>[];
  var cursor = 0;
  for (final m in _constraint.allMatches(text)) {
    if (text.substring(cursor, m.start).trim().isNotEmpty) return null;
    final Version version;
    try {
      version = Version.parse(m.group(2)!);
    } on FormatException {
      return null;
    }
    constraints.add((m.group(1), version));
    cursor = m.end;
  }
  if (constraints.isEmpty || text.substring(cursor).trim().isNotEmpty) {
    return null;
  }
  final constraint = _combine(constraints);
  if (constraint == null) return null;
  return RangeClause(constraint, channel: channel, product: product);
}

VersionConstraint? _combine(List<(String?, Version)> constraints) {
  Version? min, max;
  var includeMin = false, includeMax = false;
  for (final (op, version) in constraints) {
    switch (op) {
      case null || '=' || '==':
        if (constraints.length != 1) return null;
        return version;
      case '>=':
        if (min == null || version > min) (min, includeMin) = (version, true);
      case '>':
        if (min == null || version >= min) (min, includeMin) = (version, false);
      case '<=':
        if (max == null || version < max) (max, includeMax) = (version, true);
      case '<':
        if (max == null || version <= max) (max, includeMax) = (version, false);
    }
  }
  if (min != null && max != null) {
    if (min > max) return VersionConstraint.empty;
    if (min == max && !(includeMin && includeMax)) {
      return VersionConstraint.empty;
    }
  }
  return VersionRange(
    min: min,
    max: max,
    includeMin: includeMin,
    includeMax: includeMax,
    alwaysIncludeMaxPreRelease: true,
  );
}

String? _channel(String? raw) {
  if (raw == null) return null;
  final c = raw.trim().toLowerCase();
  if (c.isEmpty) return null;
  return c == 'master' ? 'main' : c;
}
