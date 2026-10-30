import '../check/result.dart';
import '../model/finding.dart';

class Summary {
  final int sdk, packages, ignored, unverified;
  const Summary({
    required this.sdk,
    required this.packages,
    required this.ignored,
    required this.unverified,
  });

  int get findings => sdk + packages;

  // Counted once across projects, not per project: an SDK finding appears
  // in every project but is one problem to fix.
  factory Summary.of(CheckResult result) {
    final sdk = <String>{}, packages = <String>{};
    final ignored = <String>{}, unverified = <String>{};
    for (final f in result.findings) {
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
