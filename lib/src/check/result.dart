import '../model/errors.dart';
import '../model/finding.dart';
import '../model/package_ref.dart';
import '../model/sdk_info.dart';

// Sealed states, not nullable `info` / `error` fields side by side: "SDK
// found but its advisories could not be read" and "no SDK found" must not
// look alike, and nullable pairs allow combinations that mean nothing.
sealed class SdkStatus {
  const SdkStatus();
}

class SdkNotChecked extends SdkStatus {
  const SdkNotChecked();
}

class SdkNotFound extends SdkStatus {
  const SdkNotFound();
}

class SdkChecked extends SdkStatus {
  final SdkInfo info;
  const SdkChecked(this.info);
}

class SdkFailed extends SdkStatus {
  final SdkInfo info;
  final VulncheckException error;
  const SdkFailed(this.info, this.error);
}

sealed class ProjectResult {
  final String dir;
  final String lockPath;
  const ProjectResult(this.dir, this.lockPath);
}

class CheckedProject extends ProjectResult {
  final PackageCounts packages;
  final List<Finding> findings;
  const CheckedProject(super.dir, super.lockPath,
      {required this.packages, required this.findings});
}

class FailedProject extends ProjectResult {
  final VulncheckException error;
  const FailedProject(super.dir, super.lockPath, this.error);
}

// Counts for the report, not the Lockfile itself: the report should not
// depend on how the input is read.
class PackageCounts {
  final Map<PackageSource, int> bySource;
  final int queried;
  final List<String> skipped;
  final int skippedTransitive;
  final List<String> thirdPartyHosted;

  const PackageCounts({
    required this.bySource,
    required this.queried,
    this.skipped = const [],
    this.skippedTransitive = 0,
    this.thirdPartyHosted = const [],
  });

  int get total => bySource.values.fold(0, (a, b) => a + b);
}

class CheckResult {
  final SdkStatus sdk;
  final List<ProjectResult> projects;

  // Run-wide, not per project: packages shared by several projects are
  // looked up once.
  final List<String> sourceNotes;

  const CheckResult({
    required this.sdk,
    required this.projects,
    this.sourceNotes = const [],
  });

  bool get hasErrors =>
      sdk is SdkFailed || projects.any((p) => p is FailedProject);

  Iterable<Finding> get findings =>
      projects.whereType<CheckedProject>().expand((p) => p.findings);
}
