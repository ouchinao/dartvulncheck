import 'dart:io';

import 'package:pub_semver/pub_semver.dart';
import 'package:yaml/yaml.dart';

import '../model/errors.dart';
import '../model/package_ref.dart';

class SkippedPackage {
  final String name;
  final String reason;
  const SkippedPackage(this.name, this.reason);

  @override
  String toString() => '$name ($reason)';
}

class Lockfile {
  final String path;
  final List<PackageRef> hosted;

  // Kept rather than dropped, so "no problems" never hides "not checked".
  final List<SkippedPackage> skipped;
  final Map<PackageSource, int> countBySource;
  final Set<String> sdkKeys;

  const Lockfile({
    required this.path,
    required this.hosted,
    required this.skipped,
    required this.countBySource,
    required this.sdkKeys,
  });

  int get total => countBySource.values.fold(0, (a, b) => a + b);

  bool get usesFlutter => sdkKeys.contains('flutter');
}

Lockfile readLockfile(String path) {
  final file = File(path);
  if (!file.existsSync()) throw LockfileNotFound(path);
  return parseLockfile(file.readAsStringSync(), path: path);
}

Lockfile parseLockfile(String content, {required String path}) {
  final root = _loadYaml(content, path);
  if (root is! Map) {
    throw LockfileUnreadable(path, 'the top level is not a map');
  }
  final packages = root['packages'] ?? const {};
  if (packages is! Map) {
    throw LockfileUnreadable(path, '`packages:` is not a map',
        line: _lineOf(packages));
  }

  final hosted = <PackageRef>[];
  final skipped = <SkippedPackage>[];
  final counts = <PackageSource, int>{};

  for (final entry in packages.entries) {
    final name = '${entry.key}';
    final value = entry.value;
    if (value is! Map) {
      throw LockfileUnreadable(path, 'package $name is malformed',
          line: _lineOf(value));
    }
    final source = PackageSource.parse(value['source']);
    counts[source] = (counts[source] ?? 0) + 1;

    if (source != PackageSource.hosted) {
      skipped.add(SkippedPackage(name, '${value['source']}'));
      continue;
    }

    final Version version;
    try {
      version = Version.parse('${value['version']}');
    } on FormatException {
      skipped.add(SkippedPackage(name, 'invalid version'));
      continue;
    }

    final description = value['description'];
    Uri? url;
    if (description is Map && description['url'] is String) {
      url = Uri.tryParse(description['url'] as String);
    }
    // description.name, not the map key: they can differ, and advisories
    // use the published name.
    final hostedName = description is Map && description['name'] is String
        ? description['name'] as String
        : name;

    hosted.add(PackageRef(
      name: hostedName,
      version: version,
      source: source,
      dependency: Dependency.parse(value['dependency']),
      hostedUrl: url,
    ));
  }

  final sdks = root['sdks'];
  return Lockfile(
    path: path,
    hosted: hosted,
    skipped: skipped,
    countBySource: counts,
    sdkKeys: sdks is Map ? {for (final k in sdks.keys) '$k'} : const {},
  );
}

// pub's own key, not a config file of our own, so one list silences both
// `pub get` and this tool.
Set<String> readIgnoredAdvisories(String path) {
  final file = File(path);
  if (!file.existsSync()) return const {};
  final root = _loadYaml(file.readAsStringSync(), path);
  if (root is! Map) return const {};
  final ignored = root['ignored_advisories'];
  if (ignored == null) return const {};
  if (ignored is! List) {
    throw LockfileUnreadable(path, '`ignored_advisories:` must be a list',
        line: _lineOf(ignored));
  }
  return {for (final id in ignored) '$id'.trim().toUpperCase()};
}

Object? _loadYaml(String content, String path) {
  try {
    return loadYamlNode(content, sourceUrl: Uri.file(path));
  } on YamlException catch (e) {
    final span = e.span;
    throw LockfileUnreadable(path, e.message,
        line: span == null ? null : span.start.line + 1);
  }
}

int? _lineOf(Object? node) =>
    node is YamlNode ? node.span.start.line + 1 : null;
