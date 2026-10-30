import 'package:path/path.dart' as p;

import '../lockfile/lockfile.dart';
import '../match/package_matcher.dart';
import '../match/sdk_matcher.dart';
import '../model/advisory.dart';
import '../model/errors.dart';
import '../model/finding.dart';
import '../model/notices.dart';
import '../model/package_ref.dart';
import '../sdk/sdk_detector.dart';
import '../sources/advisory_source.dart';
import '../sources/github_repository.dart';
import 'result.dart';

class CheckOptions {
  final List<String> directories;
  final Set<String> ignore;

  // Null means --no-sdk. Not a separate bool: the version override only
  // means something when the SDK is checked.
  final SdkCheck? sdk;
  final bool transitive;

  const CheckOptions({
    this.directories = const ['.'],
    this.ignore = const {},
    this.sdk = const SdkCheck(),
    this.transitive = true,
  });
}

class SdkCheck {
  final String? flutterVersion;
  const SdkCheck({this.flutterVersion});
}

// Sources are passed in, not built here, so tests and the CLI decide what
// talks to the network.
class Checker {
  final AdvisorySource packages;
  final RepositoryPackageSource? repository;
  final SdkAdvisorySource sdkAdvisories;
  final SdkDetector sdkDetector;
  final void Function(Warning warning) onWarning;

  Checker({
    required this.packages,
    this.repository,
    required this.sdkAdvisories,
    required this.sdkDetector,
    required this.onWarning,
  });

  Future<CheckResult> check(CheckOptions options) async {
    final (sdk, sdkList) = await _checkSdk(options);
    final loaded = [for (final dir in options.directories) _load(dir, options)];

    final readable = loaded.whereType<_Loaded>().toList();
    final List<Advisory> advisories;
    final List<LookupNote> notes;
    try {
      (advisories, notes) = await _fetch(readable);
    } on VulncheckException catch (e) {
      return CheckResult(sdk: sdk, projects: [
        for (final l in loaded)
          switch (l) {
            _Loaded() => FailedProject(l.dir, l.lockPath, e),
            _Unreadable(:final result) => result,
          },
      ]);
    }

    final projects = [
      for (final l in loaded)
        switch (l) {
          _Unreadable(:final result) => result,
          _Loaded() => _match(l, advisories, sdk, sdkList),
        },
    ];
    return CheckResult(sdk: sdk, projects: projects, sourceNotes: notes);
  }

  CheckedProject _match(_Loaded l, List<Advisory> advisories, SdkStatus sdk,
      List<Advisory> sdkList) {
    final findings = matchPackages(l.targets, advisories, ignored: l.ignored);
    if (sdk is! SdkChecked) return _checked(l, findings);
    return _checked(l, [
      ...findings,
      ...matchSdk(sdk.info, sdkList,
          includeFlutter: l.lock.usesFlutter, ignored: l.ignored),
    ]);
  }

  Future<(SdkStatus, List<Advisory>)> _checkSdk(CheckOptions options) async {
    final sdkCheck = options.sdk;
    if (sdkCheck == null) return (const SdkNotChecked(), const <Advisory>[]);
    final detection = await sdkDetector.detect(
        flutterOverride: sdkCheck.flutterVersion,
        projectDirs: [...options.directories, '.']);
    detection.warnings.forEach(onWarning);
    final info = detection.info;
    if (info == null) return (const SdkNotFound(), const <Advisory>[]);
    final List<Advisory> advisories;
    try {
      advisories = await sdkAdvisories.fetchAll();
    } on VulncheckException catch (e) {
      return (SdkFailed(info, e), const <Advisory>[]);
    }
    if (info.dart == null && hasDartAdvisories(advisories)) {
      onWarning(const DartVersionUnknown());
    }
    return (SdkChecked(info), advisories);
  }

  _Load _load(String dir, CheckOptions options) {
    final lockPath = p.normalize(p.join(dir, 'pubspec.lock'));
    try {
      final lock = readLockfile(lockPath);
      return _Loaded(
        dir: dir,
        lockPath: lockPath,
        lock: lock,
        ignored: {
          ...readIgnoredAdvisories(p.join(dir, 'pubspec.yaml')),
          ...options.ignore,
        },
        targets: lock.hosted
            .where((pkg) => options.transitive || pkg.dependency.isDirect)
            .toList(),
      );
    } on VulncheckException catch (e) {
      return _Unreadable(FailedProject(dir, lockPath, e));
    }
  }

  // One query for all projects, not one per project: a monorepo shares most
  // of its packages, and asking twice only spends rate limit.
  Future<(List<Advisory>, List<LookupNote>)> _fetch(
      List<_Loaded> projects) async {
    final unique = <String, PackageRef>{
      for (final l in projects)
        for (final pkg in l.targets) '${pkg.name}@${pkg.version}': pkg,
    }.values.toList();
    if (unique.isEmpty) return (const <Advisory>[], const <LookupNote>[]);

    final advisories = [...await packages.query(unique)];
    final repository = this.repository;
    if (repository == null) return (advisories, const <LookupNote>[]);

    final early = await repository.query(unique);
    if (early.failures > 0) onWarning(RepositoryLookupsFailed(early.failures));
    return ([...advisories, ...early.advisories], early.notes);
  }

  CheckedProject _checked(_Loaded l, List<Finding> findings) => CheckedProject(
        l.dir,
        l.lockPath,
        packages: PackageCounts(
          bySource: l.lock.countBySource,
          queried: l.targets.length,
          skipped: l.lock.skipped,
          skippedTransitive: l.lock.hosted.length - l.targets.length,
          thirdPartyHosted: [
            for (final pkg in l.lock.hosted)
              if (pkg.isThirdPartyHosted) pkg,
          ],
        ),
        findings: findings,
      );
}

sealed class _Load {
  const _Load();
}

class _Unreadable extends _Load {
  final FailedProject result;
  const _Unreadable(this.result);
}

class _Loaded extends _Load {
  final String dir;
  final String lockPath;
  final Lockfile lock;
  final Set<String> ignored;
  final List<PackageRef> targets;
  const _Loaded({
    required this.dir,
    required this.lockPath,
    required this.lock,
    required this.ignored,
    required this.targets,
  });
}
