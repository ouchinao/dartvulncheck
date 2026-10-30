import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:pub_semver/pub_semver.dart';
import 'package:test/test.dart';

bool allows(String range, String version, {String? channel, String? product}) =>
    parseVulnerableRange(range)!
        .allows(Version.parse(version), channel: channel, product: product);

void main() {
  test('"< 3.13.7" includes 3.13.6 and excludes 3.13.7', () {
    expect(allows('< 3.13.7', '3.13.6'), isTrue);
    expect(allows('< 3.13.7', '3.13.7'), isFalse);
  });

  test('"< 3.13.7" includes 3.13.7-dev.1 (a pre-release cut before the fix)',
      () {
    expect(allows('< 3.13.7', '3.13.7-dev.1'), isTrue);
  });

  test('Flutter pre-release "3.50.0-0.2.pre" is in "< 3.50.0"', () {
    expect(allows('< 3.50.0', '3.50.0-0.2.pre'), isTrue);
  });

  test('">= 4.0.0, < 4.0.7" is one range, with or without spaces', () {
    expect(allows('>= 4.0.0, < 4.0.7', '4.0.6'), isTrue);
    expect(allows('>=4.0.0,<4.0.7', '3.9.9'), isFalse);
    expect(allows('>=4.0.0,<4.0.7', '4.0.7'), isFalse);
  });

  test('">=1.0.0 <= 2.7.1" (no comma, as cfug/dio writes it) is one range', () {
    expect(allows('>=1.0.0 <= 2.7.1', '2.7.1'), isTrue);
    expect(allows('>=1.0.0 <= 2.7.1', '2.8.0'), isFalse);
    expect(allows('>=1.0.0 <= 2.7.1', '0.9.0'), isFalse);
  });

  group('channel clauses, as dart-lang/sdk writes them', () {
    const range = '< 3.13.7 (stable), < 3.14.0-315.3.beta (beta)';

    test('a stable build below the stable fix is affected', () {
      expect(allows(range, '3.13.6', channel: 'stable'), isTrue);
    });

    test('a fixed stable build is not caught by the beta bound', () {
      expect(allows(range, '3.13.7', channel: 'stable'), isFalse);
      expect(allows(range, '3.13.7'), isFalse);
    });

    test('a beta build is judged by the beta clause only', () {
      expect(allows(range, '3.14.0-200.1.beta', channel: 'beta'), isTrue);
      expect(allows(range, '3.14.0-315.3.beta', channel: 'beta'), isFalse);
    });

    test('a pre-release of unknown channel is matched by non-stable clauses',
        () {
      expect(allows(range, '3.14.0-200.1.beta'), isTrue);
      expect(allows(range, '3.14.0-315.3.beta'), isFalse);
    });
  });

  test('"Prior to 3.11.0" means < 3.11.0', () {
    expect(allows('Prior to 3.11.0', '3.10.9'), isTrue);
    expect(allows('Prior to 3.11.0', '3.11.0'), isFalse);
  });

  test(
      '"Dart version prior to 2.18.2, Flutter version prior to 3.3.3" '
      'applies each clause to its product', () {
    const range =
        'Dart version prior to 2.18.2, Flutter version prior to 3.3.3';
    expect(allows(range, '2.18.1', product: 'Dart'), isTrue);
    expect(allows(range, '2.18.2', product: 'Dart'), isFalse);
    expect(allows(range, '3.3.2', product: 'Dart'), isFalse);
    expect(allows(range, '3.3.2', product: 'Flutter'), isTrue);
    expect(allows(range, '2.18.1'), isFalse);
  });

  test(
      '"Dart version prior to 2.16.0, Flutter version < 2.10.0" mixes '
      'prose and operators', () {
    const range = 'Dart version prior to 2.16.0, Flutter version < 2.10.0';
    expect(allows(range, '2.15.0', product: 'Dart'), isTrue);
    expect(allows(range, '2.9.0', product: 'Flutter'), isTrue);
    expect(allows(range, '2.10.0', product: 'Flutter'), isFalse);
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
    expect(parseVulnerableRange('< 2.0 (see the description)'), isNull);
  });

  test('every version in a patched field is read, in order', () {
    List<String> patched(String? text) =>
        [for (final v in parsePatchedVersions(text)) '$v'];
    expect(patched('3.47.8'), ['3.47.8']);
    expect(patched('>= 3.47.8'), ['3.47.8']);
    expect(
        patched('3.13.7, 3.14.0-315.3.beta'), ['3.13.7', '3.14.0-315.3.beta']);
    expect(patched('Dart version 2.18.2, Flutter version 3.3.3'),
        ['2.18.2', '3.3.3']);
    expect(patched(null), isEmpty);
    expect(patched('none'), isEmpty);
  });
}
