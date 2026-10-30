import 'dart:io';

import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'helpers.dart';

void main() {
  group('pubspec.lock', () {
    late Lockfile lock;
    setUp(() => lock =
        parseLockfile(fixture('lockfiles/app.lock'), path: 'app/pubspec.lock'));

    test('hosted packages with a valid version are queried', () {
      expect(lock.hosted.map((p) => p.name),
          ['async', 'dio', 'http', 'internal_utils', 'lints']);
    });

    test('git, path and sdk packages are skipped with their source', () {
      expect(
          lock.skipped.map((s) => '$s'),
          containsAll(
              ['flutter (sdk)', 'my_fork (git)', 'zeibun_core (path)']));
    });

    test('a version that is not semver is skipped, not fatal', () {
      expect(lock.skipped.map((s) => '$s'),
          contains('weird_version (invalid version)'));
    });

    test('direct main, direct dev and transitive are told apart', () {
      final byName = {for (final p in lock.hosted) p.name: p};
      expect(byName['dio']!.dependency, Dependency.directMain);
      expect(byName['lints']!.dependency, Dependency.directDev);
      expect(byName['http']!.dependency, Dependency.transitive);
    });

    test('counts per source cover every package', () {
      expect(lock.total, 9);
      expect(lock.countBySource[PackageSource.hosted], 6);
      expect(lock.countBySource[PackageSource.path], 1);
    });

    test('a package hosted outside pub.dev is flagged', () {
      final internal =
          lock.hosted.firstWhere((p) => p.name == 'internal_utils');
      expect(internal.isThirdPartyHosted, isTrue);
      expect(lock.hosted.firstWhere((p) => p.name == 'dio').isThirdPartyHosted,
          isFalse);
    });

    test('sdks: keys tell whether the project uses Flutter', () {
      expect(lock.usesFlutter, isTrue);
      expect(
          parseLockfile(fixture('lockfiles/pure_dart.lock'), path: 'x')
              .usesFlutter,
          isFalse);
    });
  });

  test('broken YAML reports the file and line', () {
    expect(
      () => parseLockfile(fixture('lockfiles/broken.lock'),
          path: 'app/pubspec.lock'),
      throwsA(isA<LockfileUnreadable>().having((e) => e.line, 'line', 5).having(
          (e) => e.message, 'message', startsWith('app/pubspec.lock:5'))),
    );
  });

  test('a missing pubspec.lock asks for pub get', () {
    expect(
      () => readLockfile('does/not/exist/pubspec.lock'),
      throwsA(isA<LockfileNotFound>()
          .having((e) => e.message, 'message', contains('dart pub get'))),
    );
  });

  group('ignored_advisories', () {
    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('dvc'));
    tearDown(() => tmp.deleteSync(recursive: true));

    test('is read from pubspec.yaml and upper-cased', () {
      final f = File(p.join(tmp.path, 'pubspec.yaml'))
        ..writeAsStringSync('name: app\n'
            'ignored_advisories:\n'
            '  - ghsa-9324-jv53-9cc8\n'
            '  - CVE-2020-35669\n');
      expect(readIgnoredAdvisories(f.path),
          {'GHSA-9324-JV53-9CC8', 'CVE-2020-35669'});
    });

    test('a missing pubspec.yaml means nothing is ignored', () {
      expect(readIgnoredAdvisories(p.join(tmp.path, 'pubspec.yaml')), isEmpty);
    });
  });
}
