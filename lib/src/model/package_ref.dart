import 'package:pub_semver/pub_semver.dart';

enum PackageSource {
  hosted,
  git,
  path,
  sdk,
  other;

  static PackageSource parse(Object? value) => switch (value) {
        'hosted' => PackageSource.hosted,
        'git' => PackageSource.git,
        'path' => PackageSource.path,
        'sdk' => PackageSource.sdk,
        _ => PackageSource.other,
      };
}

enum Dependency {
  directMain,
  directDev,
  directOverridden,
  transitive;

  static Dependency parse(Object? value) => switch (value) {
        'direct main' => Dependency.directMain,
        'direct dev' => Dependency.directDev,
        'direct overridden' => Dependency.directOverridden,
        _ => Dependency.transitive,
      };

  bool get isDirect => this != Dependency.transitive;
}

class PackageRef {
  final String name;
  final Version version;
  final PackageSource source;
  final Dependency dependency;
  final Uri? hostedUrl;

  const PackageRef({
    required this.name,
    required this.version,
    required this.source,
    required this.dependency,
    this.hostedUrl,
  });

  bool get isThirdPartyHosted {
    final host = hostedUrl?.host;
    if (host == null || host.isEmpty) return false;
    return host != 'pub.dev' && host != 'pub.dartlang.org';
  }

  @override
  String toString() => '$name $version';
}

class SkippedPackage {
  final String name;
  final String reason;
  const SkippedPackage(this.name, this.reason);
}
