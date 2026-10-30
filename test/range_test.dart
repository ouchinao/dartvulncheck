import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:pub_semver/pub_semver.dart';
import 'package:test/test.dart';

bool allows(String range, String version) =>
    parseVulnerableRange(range)!.allows(Version.parse(version));

void main() {
  test('"< 3.13.7" includes 3.13.6 and excludes 3.13.7', () {
    expect(allows('< 3.13.7', '3.13.6'), isTrue);
    expect(allows('< 3.13.7', '3.13.7'), isFalse);
  });

  test('"< 3.13.7" includes 3.13.7-dev.1 (a pre-release cut before the fix)',
      () {
    expect(allows('< 3.13.7', '3.13.7-dev.1'), isTrue);
  });

  test('a beta build below the fixed beta is affected', () {
    const range = '>= 3.14.0-0, < 3.14.0-315.3.beta';
    expect(allows(range, '3.14.0-200.1.beta'), isTrue);
    expect(allows(range, '3.14.0-315.3.beta'), isFalse);
    expect(allows(range, '3.13.9'), isFalse);
  });

  test('Flutter pre-release "3.50.0-0.2.pre" is in "< 3.50.0"', () {
    expect(allows('< 3.50.0', '3.50.0-0.2.pre'), isTrue);
  });

  test('">= 4.0.0, < 4.0.7" with and without spaces', () {
    expect(allows('>= 4.0.0, < 4.0.7', '4.0.6'), isTrue);
    expect(allows('>=4.0.0,<4.0.7', '3.9.9'), isFalse);
  });

  test('"<= 1.2.3" includes 1.2.3', () {
    expect(allows('<= 1.2.3', '1.2.3'), isTrue);
    expect(allows('<= 1.2.3', '1.2.4'), isFalse);
  });

  test('"= 1.2.3" and a bare version mean exactly that version', () {
    expect(allows('= 1.2.3', '1.2.3'), isTrue);
    expect(allows('1.2.3', '1.2.4'), isFalse);
  });

  test('unreadable ranges return null', () {
    expect(parseVulnerableRange(''), isNull);
    expect(parseVulnerableRange('all versions'), isNull);
    expect(parseVulnerableRange('< banana'), isNull);
  });

  test('the patched version is the first version-looking token', () {
    expect(parsePatchedVersion('3.47.8'), Version.parse('3.47.8'));
    expect(parsePatchedVersion('>= 3.47.8'), Version.parse('3.47.8'));
    expect(parsePatchedVersion('3.47.8, 3.48.1'), Version.parse('3.47.8'));
    expect(parsePatchedVersion(null), isNull);
    expect(parsePatchedVersion('none'), isNull);
  });
}
