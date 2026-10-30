import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:pub_semver/pub_semver.dart';
import 'package:test/test.dart';

void main() {
  Finding finding(Severity s,
          {FindingKind kind = FindingKind.package, bool ignored = false}) =>
      Finding(
        id: 'GHSA-1',
        kind: kind,
        subject: 'dio',
        current: Version.parse('1.0.0'),
        severity: s,
        summary: '',
        url: Uri.parse('https://example.com'),
        ignored: ignored,
      );

  bool fails(Finding f,
          {Severity failOn = Severity.low, bool strict = false}) =>
      findingFails(f, failOn: failOn, strict: strict);

  test('a finding at the --fail-on threshold fails, one below does not', () {
    expect(fails(finding(Severity.high), failOn: Severity.high), isTrue);
    expect(fails(finding(Severity.moderate), failOn: Severity.high), isFalse);
  });

  test('unknown severity fails at every threshold', () {
    expect(fails(finding(Severity.unknown), failOn: Severity.critical), isTrue);
  });

  test('an unverified finding fails only with --strict', () {
    final f = finding(Severity.high, kind: FindingKind.packageUnverified);
    expect(fails(f), isFalse);
    expect(fails(f, strict: true), isTrue);
  });

  test('an ignored finding never fails', () {
    expect(fails(finding(Severity.critical, ignored: true), strict: true),
        isFalse);
  });

  test('a failed project means exit 1 even when nothing was found', () {
    final result = CheckResult(sdk: const SdkNotChecked(), projects: [
      FailedProject('app', 'app/pubspec.lock', const LockfileNotFound('x')),
    ]);
    expect(exitCodeFor(result, failOn: Severity.low, strict: false),
        ExitCodes.error);
  });

  test('a failed SDK check means exit 1 even when packages are clean', () {
    final result = CheckResult(
      sdk: SdkFailed(
          SdkInfo(flutter: Version.parse('3.47.6'), origin: SdkOrigin.override),
          const SourceUnreachable('GitHub', 'down')),
      projects: const [
        CheckedProject('app', 'app/pubspec.lock',
            packages: PackageCounts(bySource: {}, queried: 0), findings: []),
      ],
    );
    expect(exitCodeFor(result, failOn: Severity.low, strict: false),
        ExitCodes.error);
  });

  test('findings decide between 0 and 3', () {
    CheckResult result(List<Finding> findings) =>
        CheckResult(sdk: const SdkNotChecked(), projects: [
          CheckedProject('app', 'app/pubspec.lock',
              packages: const PackageCounts(bySource: {}, queried: 1),
              findings: findings),
        ]);
    expect(exitCodeFor(result([]), failOn: Severity.low, strict: false),
        ExitCodes.ok);
    expect(
        exitCodeFor(result([finding(Severity.low)]),
            failOn: Severity.low, strict: false),
        ExitCodes.vulnerable);
  });
}
