import '../lockfile/lockfile.dart';
import '../model/errors.dart';
import '../model/finding.dart';
import '../model/sdk_info.dart';
import '../model/severity.dart';

class ProjectResult {
  final String dir;
  final String lockPath;
  final Lockfile? lockfile;
  final List<Finding> findings;
  final int queried;
  final VulncheckException? error;

  const ProjectResult({
    required this.dir,
    required this.lockPath,
    this.lockfile,
    this.findings = const [],
    this.queried = 0,
    this.error,
  });
}

class CheckResult {
  final SdkInfo? sdk;
  final List<ProjectResult> projects;
  const CheckResult({this.sdk, required this.projects});

  bool get hasErrors => projects.any((p) => p.error != null);

  Iterable<Finding> get _all => projects.expand((p) => p.findings);

  // Counted once across projects, not per project: an SDK finding appears
  // in every project but is one problem to fix.
  Summary summarize() {
    final sdk = <String>{}, packages = <String>{};
    final ignored = <String>{}, unverified = <String>{};
    for (final f in _all) {
      final key = f.kind.isSdk ? 'sdk:${f.id}' : '${f.subject}:${f.id}';
      if (f.ignored) {
        ignored.add(key);
      } else if (f.kind.isUnverified) {
        unverified.add(key);
      } else if (f.kind.isSdk) {
        sdk.add(key);
      } else {
        packages.add(key);
      }
    }
    return Summary(
      sdk: sdk.length,
      packages: packages.length,
      ignored: ignored.length,
      unverified: unverified.length,
    );
  }

  int exitCode({required Severity failOn, required bool strict}) {
    if (hasErrors) return 1;
    return _all.any((f) => f.counts(failOn: failOn, strict: strict)) ? 3 : 0;
  }
}

class Summary {
  final int sdk, packages, ignored, unverified;
  const Summary({
    required this.sdk,
    required this.packages,
    required this.ignored,
    required this.unverified,
  });

  int get findings => sdk + packages;
}

List<Finding> sortFindings(Iterable<Finding> findings) {
  int group(Finding f) =>
      (f.kind.isSdk ? 0 : 2) + (f.kind.isUnverified ? 1 : 0);
  return findings.toList()
    ..sort((a, b) {
      final g = group(a) - group(b);
      if (g != 0) return g;
      final s = b.severity.rank - a.severity.rank;
      if (s != 0) return s;
      final n = a.subject.compareTo(b.subject);
      if (n != 0) return n;
      return a.id.compareTo(b.id);
    });
}
