import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:pub_semver/pub_semver.dart';
import 'package:test/test.dart';

PackageRef pkg(String name, String version,
        [Dependency dep = Dependency.directMain]) =>
    PackageRef(
        name: name,
        version: Version.parse(version),
        source: PackageSource.hosted,
        dependency: dep);

Advisory advisory(
  String id, {
  AdvisoryOrigin origin = AdvisoryOrigin.repository,
  List<AffectedPackage> affected = const [],
  List<String> aliases = const [],
  Severity severity = Severity.high,
  String? repository,
}) =>
    Advisory(
      id: id,
      aliases: aliases,
      summary: 'summary of $id',
      severity: severity,
      url: Uri.parse('https://example.com/$id'),
      origin: origin,
      affected: affected,
      repository: repository,
    );

AffectedPackage affects(String? name, String range, [String? patched]) =>
    AffectedPackage(
        name: name, ranges: range.isEmpty ? [] : [range], patched: patched);

void main() {
  group('packages', () {
    test('a version inside the range is a finding with its fix', () {
      final f = matchPackages([
        pkg('dio', '4.0.6')
      ], [
        advisory('GHSA-1', affected: [affects('dio', '< 5.0.0', '5.0.0')]),
      ]).single;
      expect(f.kind, FindingKind.package);
      expect(f.fixed, Version.parse('5.0.0'));
      expect(f.dependency, Dependency.directMain);
    });

    test('a version outside the range is not a finding', () {
      expect(
          matchPackages([
            pkg('dio', '5.7.0')
          ], [
            advisory('GHSA-1', affected: [affects('dio', '< 5.0.0')]),
          ]),
          isEmpty);
    });

    test(
        'a global advisory listing another, unaffected package is dropped '
        'for that package', () {
      final findings = matchPackages(
        [pkg('http', '0.13.2'), pkg('async', '2.13.0')],
        [
          advisory('GHSA-1', origin: AdvisoryOrigin.global, affected: [
            affects('http', '< 0.13.3'),
            affects('async', '< 2.0.0'),
          ]),
        ],
      );
      expect(findings.map((f) => f.subject), ['http']);
    });

    test('a repository advisory without a range is "unverified"', () {
      final f = matchPackages([
        pkg('dio', '4.0.6')
      ], [
        advisory('GHSA-1', affected: [affects('dio', '')]),
      ]).single;
      expect(f.kind, FindingKind.packageUnverified);
    });

    test('a global advisory without a readable range is trusted', () {
      final f = matchPackages([
        pkg('dio', '4.0.6')
      ], [
        advisory('GHSA-1',
            origin: AdvisoryOrigin.global,
            affected: [affects('dio', 'something odd')]),
      ]).single;
      expect(f.kind, FindingKind.package);
    });

    test(
        'the same id from global and repository is one finding, '
        'using the reviewed global range', () {
      final findings = matchPackages([
        pkg('dio', '4.0.6')
      ], [
        advisory('GHSA-1', affected: [affects('dio', '')]),
        advisory('GHSA-1',
            origin: AdvisoryOrigin.global,
            affected: [affects('dio', '< 5.0.0', '5.0.0')]),
      ]);
      expect(findings.single.kind, FindingKind.package);
      expect(findings.single.fixed, Version.parse('5.0.0'));
    });

    test('advisories sharing a CVE alias merge', () {
      final findings = matchPackages([
        pkg('dio', '4.0.6')
      ], [
        advisory('GHSA-1',
            aliases: ['CVE-1'],
            origin: AdvisoryOrigin.osv,
            affected: [affects('dio', '< 5.0.0')]),
        advisory('GHSA-2',
            aliases: ['CVE-1'],
            origin: AdvisoryOrigin.osv,
            affected: [affects('dio', '< 5.0.0')]),
      ]);
      expect(findings.single.allIds, {'GHSA-1', 'GHSA-2', 'CVE-1'});
    });

    test('ignoring by CVE marks the finding ignored but keeps it', () {
      final f = matchPackages(
        [pkg('dio', '4.0.6')],
        [
          advisory('GHSA-1',
              aliases: ['CVE-2021-31402'],
              affected: [affects('dio', '< 5.0.0')]),
        ],
        ignored: {'cve-2021-31402'},
      ).single;
      expect(f.ignored, isTrue);
    });

    test('no fix in a matching entry means no fix', () {
      final f = matchPackages([
        pkg('dio', '4.0.6')
      ], [
        advisory('GHSA-1', affected: [affects('dio', '>= 4.0.0')]),
      ]).single;
      expect(f.fixed, isNull);
    });
  });

  group('SDK', () {
    final sdk = SdkInfo(
        flutter: Version.parse('3.47.6'),
        dart: Version.parse('3.13.5'),
        origin: 'test');

    test(
        'Dart and Flutter entries of one advisory become one Flutter finding '
        'with the Dart fix alongside', () {
      final m = matchSdk(sdk, [
        advisory('GHSA-frr6-h895-5pxp', repository: 'dart-lang/sdk', affected: [
          affects('Flutter', '< 3.47.8', '3.47.8'),
          affects('Dart SDK', '< 3.13.7', '3.13.7'),
        ]),
      ]);
      final f = m.findings.single;
      expect(f.subject, 'Flutter');
      expect(f.kind, FindingKind.sdk);
      expect(f.fixed, Version.parse('3.47.8'));
      expect(f.alsoFixedIn, {'Dart': Version.parse('3.13.7')});
    });

    test('the same issue in dart-lang/sdk and flutter/flutter is one finding',
        () {
      final m = matchSdk(sdk, [
        advisory('GHSA-A',
            repository: 'dart-lang/sdk',
            affected: [affects('Dart SDK', '< 3.13.7', '3.13.7')]),
        advisory('GHSA-B',
            aliases: ['GHSA-A'],
            repository: 'flutter/flutter',
            affected: [affects('flutter', '< 3.47.8', '3.47.8')]),
      ]);
      expect(m.findings.single.subject, 'Flutter');
      expect(m.findings.single.allIds, {'GHSA-A', 'GHSA-B'});
    });

    test('a beta channel build is matched', () {
      final beta =
          SdkInfo(flutter: Version.parse('3.50.0-0.2.pre'), origin: 'test');
      final m = matchSdk(beta, [
        advisory('GHSA-1',
            repository: 'flutter/flutter',
            affected: [affects('flutter', '< 3.50.0', '3.50.0')]),
      ]);
      expect(m.findings.single.current, Version.parse('3.50.0-0.2.pre'));
    });

    test('an SDK advisory with no structured range is sdkUnverified', () {
      final m =
          matchSdk(sdk, [advisory('GHSA-1', repository: 'dart-lang/sdk')]);
      expect(m.findings.single.kind, FindingKind.sdkUnverified);
      expect(m.findings.single.subject, 'Dart');
    });

    test('Flutter advisories do not apply to a pure Dart project', () {
      final m = matchSdk(
        sdk,
        [
          advisory('GHSA-1',
              repository: 'flutter/flutter',
              affected: [affects('flutter', '< 3.47.8')]),
        ],
        includeFlutter: false,
      );
      expect(m.findings, isEmpty);
    });

    test(
        'with only the Flutter version known, Dart-only advisories are '
        'skipped and reported', () {
      final flutterOnly =
          SdkInfo(flutter: Version.parse('3.47.6'), origin: 'test');
      final m = matchSdk(flutterOnly, [
        advisory('GHSA-1',
            repository: 'dart-lang/sdk',
            affected: [affects('Dart SDK', '< 3.13.7')]),
      ]);
      expect(m.findings, isEmpty);
      expect(m.dartVersionUnknown, isTrue);
    });

    test('a package that lives in the SDK repo is not the SDK', () {
      final m = matchSdk(sdk, [
        advisory('GHSA-1',
            repository: 'flutter/flutter',
            affected: [affects('flutter_tools', '< 9.0.0')]),
      ]);
      expect(m.findings, isEmpty);
    });
  });

  group('--fail-on', () {
    Finding finding(Severity s, {FindingKind kind = FindingKind.package}) =>
        Finding(
          id: 'GHSA-1',
          kind: kind,
          subject: 'dio',
          current: Version.parse('1.0.0'),
          severity: s,
          summary: '',
          url: Uri.parse('https://example.com'),
        );

    test('a finding at the threshold counts, one below does not', () {
      expect(
          finding(Severity.high).counts(failOn: Severity.high, strict: false),
          isTrue);
      expect(
          finding(Severity.moderate)
              .counts(failOn: Severity.high, strict: false),
          isFalse);
    });

    test('unknown severity counts as the highest', () {
      expect(
          finding(Severity.unknown)
              .counts(failOn: Severity.critical, strict: false),
          isTrue);
    });

    test('unverified counts only with --strict', () {
      final f = finding(Severity.high, kind: FindingKind.packageUnverified);
      expect(f.counts(failOn: Severity.low, strict: false), isFalse);
      expect(f.counts(failOn: Severity.low, strict: true), isTrue);
    });

    test('ignored never counts', () {
      expect(
          finding(Severity.critical)
              .copyWith(ignored: true)
              .counts(failOn: Severity.low, strict: true),
          isFalse);
    });
  });
}
