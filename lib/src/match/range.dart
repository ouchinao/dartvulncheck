import 'package:pub_semver/pub_semver.dart';

// Not VersionConstraint.parse: it treats `<3.13.7`
// as excluding `3.13.7-dev.1`, which is right for dependency resolution but
// wrong here. A pre-release of the fixed version was cut before the fix, and
// missing it would let beta builds such as `3.50.0-0.2.pre` through.
VersionConstraint? parseVulnerableRange(String text) {
  final trimmed = text.trim();
  if (trimmed.isEmpty) return null;

  Version? min, max;
  var includeMin = false, includeMax = false;
  final parts =
      trimmed.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty);
  if (parts.isEmpty) return null;

  for (final part in parts) {
    final m = RegExp(r'^(>=|<=|>|<|==|=)?\s*(\S+)$').firstMatch(part);
    if (m == null) return null;
    final Version version;
    try {
      version = Version.parse(m.group(2)!);
    } on FormatException {
      return null;
    }
    switch (m.group(1)) {
      case null || '=' || '==':
        if (parts.length != 1) return null;
        return version;
      case '>=':
        if (min == null || version > min || (version == min && !includeMin)) {
          (min, includeMin) = (version, true);
        }
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

Version? parsePatchedVersion(String? text) {
  if (text == null) return null;
  for (final token in text.split(RegExp(r'[\s,]+'))) {
    final cleaned = token.replaceAll(RegExp(r'^[<>=~^]+'), '');
    if (cleaned.isEmpty) continue;
    try {
      return Version.parse(cleaned);
    } on FormatException {
      continue;
    }
  }
  return null;
}
