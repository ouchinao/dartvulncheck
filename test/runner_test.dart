import 'dart:convert';
import 'dart:io';

import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'helpers.dart';

class Run {
  final int code;
  final String out;
  final String err;
  final FakeApi api;
  Run(this.code, this.out, this.err, this.api);
}

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('dvc'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<Run> run(
    List<String> args, {
    FakeApi? api,
    ProcessRunner? processes,
    Map<String, String> env = const {'GITHUB_TOKEN': 'tkn'},
  }) async {
    api ??= FakeApi();
    final out = StringBuffer(), err = StringBuffer();
    final code = await Runner(
      client: api.client,
      processRunner: processes ?? flutterInstalled(),
      environment: env,
      out: out,
      err: err,
      retryDelay: Duration.zero,
    ).run([
      // Not Directory.current = tmp: it is process-wide and breaks test
      // files that run in parallel.
      for (final a in args)
        !a.startsWith('-') && Directory(p.join(tmp.path, a)).existsSync()
            ? p.join(tmp.path, a)
            : a,
    ]);
    String rel(StringBuffer b) => '$b'.replaceAll('${tmp.path}/', '');
    return Run(code, rel(out), rel(err), api);
  }

  group('exit codes', () {
    test('0 when nothing is found', () async {
      makeProject(tmp, 'app', 'pure_dart.lock');
      final r = await run(['app', '--no-sdk']);
      expect(r.code, ExitCodes.ok);
      expect(r.out, contains('No problems found'));
    });

    test('3 when a vulnerability is found', () async {
      makeProject(tmp, 'app', 'app.lock');
      final r = await run(['app']);
      expect(r.code, ExitCodes.vulnerable);
    });

    test('1 when pubspec.lock is missing', () async {
      Directory(p.join(tmp.path, 'empty')).createSync();
      final r = await run(['empty']);
      expect(r.code, ExitCodes.error);
      expect(r.err, contains('dart pub get'));
    });

    test('1 for a bad argument, with usage', () async {
      final r = await run(['--fail-on', 'banana']);
      expect(r.code, ExitCodes.error);
      expect(r.err, contains('Usage'));
    });

    test('1 when GitHub and OSV are both down', () async {
      makeProject(tmp, 'app', 'app.lock');
      final api = FakeApi()
        ..githubStatus = 503
        ..osvStatus = 503;
      final r = await run(['app', '--no-sdk'], api: api);
      expect(r.code, ExitCodes.error);
      expect(r.err, contains('OSV.dev'));
    });

    test('1 on rate limiting, pointing at GITHUB_TOKEN', () async {
      makeProject(tmp, 'app', 'app.lock');
      final api = FakeApi()
        ..githubStatus = 403
        ..githubHeaders = {'x-ratelimit-remaining': '0'};
      final r = await run(['app', '--no-sdk'], api: api, env: const {});
      expect(r.code, ExitCodes.error);
      expect(r.err, contains('GITHUB_TOKEN'));
    });

    test('only ignored findings still exit 0', () async {
      makeProject(tmp, 'app', 'app.lock');
      final r = await run([
        'app',
        '--no-sdk',
        '--no-repo-advisories',
        '--ignore',
        'GHSA-9324-jv53-9cc8,CVE-2020-35669',
      ]);
      expect(r.code, ExitCodes.ok);
      expect(r.out, contains('2 ignored'));
      expect(
          r.out,
          contains('Ignored\n'
              '  GHSA-9324-jv53-9cc8  dio 4.0.6  CVE-2021-31402\n'
              '  GHSA-4rgh-jx4f-qfcq  http 0.13.2  CVE-2020-35669\n'));
    });
  });

  test(
      'several directories: one failing does not stop the others, and the '
      'run exits 1', () async {
    makeProject(tmp, 'app', 'app.lock');
    Directory(p.join(tmp.path, 'broken')).createSync();
    final r = await run(['broken', 'app']);
    expect(r.code, ExitCodes.error);
    expect(r.out, contains('app/pubspec.lock'));
    expect(r.out, contains('GHSA-9324-jv53-9cc8'));
    expect(r.err, contains('broken'));
  });

  test('ignored_advisories in pubspec.yaml is honoured, for SDK too', () async {
    makeProject(tmp, 'app', 'app.lock',
        pubspec: 'name: app\nignored_advisories:\n  - GHSA-frr6-h895-5pxp\n');
    final r = await run(['app', '--json']);
    final findings = (jsonDecode(r.out)['projects'] as List).single['findings']
        as List<Object?>;
    final sdk = findings
        .cast<Map<String, Object?>>()
        .firstWhere((f) => f['id'] == 'GHSA-frr6-h895-5pxp');
    expect(sdk['ignored'], isTrue);
  });

  test('--fail-on critical ignores a HIGH-only result', () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run(
        ['app', '--no-sdk', '--no-repo-advisories', '--fail-on', 'critical']);
    expect(r.code, ExitCodes.ok);
    expect(r.out, contains('GHSA-9324-jv53-9cc8'));
  });

  test('--strict counts unverified advisories', () async {
    makeProject(tmp, 'app', 'pure_dart.lock');
    // Dart 3.13.7 from `dart --version`, not Flutter's 3.13.5: at 3.13.5 the
    // eMudhra advisory would also match and exit 3 whatever --strict says.
    final processes = FakeProcessRunner({
      'dart': ProcessOutput(0, '', fixture('sdk/dart_version.txt')),
    });
    FakeApi api() => FakeApi()
      ..extraAdvisories['dart-lang/sdk'] = [
        repositoryAdvisoryJson('GHSA-dddd-eeee-ffff',
            repo: 'dart-lang/sdk',
            summary: 'Dart SDK issue without a readable range',
            vulnerabilities: [
              vulnerabilityJson(
                  ecosystem: 'dart sdk',
                  name: 'Dart SDK',
                  range: 'see the description'),
            ]),
      ];
    final loose = await run(['app'], api: api(), processes: processes);
    final strict =
        await run(['app', '--strict'], api: api(), processes: processes);
    expect(loose.out, contains('UNVERIFIED'));
    expect(loose.code, ExitCodes.ok);
    expect(strict.code, ExitCodes.vulnerable);
  });

  test('--no-transitive skips transitive packages', () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run(['app', '--no-sdk', '--no-transitive']);
    expect(r.out, isNot(contains('http 0.13.2')));
    final affects = r.api.requests
        .firstWhere((q) => q.url.path == '/advisories')
        .url
        .queryParameters['affects']!;
    expect(affects, isNot(contains('http@')));
  });

  test('without GITHUB_TOKEN the repository stage is skipped with a note',
      () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run(['app', '--no-sdk'], env: const {});
    expect(r.err, contains('GITHUB_TOKEN is not set'));
    expect(
        r.api.requests.where((q) =>
            q.url.host == 'pub.dev' &&
            q.url.path != '/api/packages/dartvulncheck'),
        isEmpty);
  });

  test('without flutter on PATH the SDK check is skipped with a warning',
      () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run(['app'], processes: nothingInstalled());
    expect(r.err, contains('--sdk-version'));
    expect(r.out, isNot(contains('\nSDK\n')));
    expect(r.code, ExitCodes.vulnerable);
  });

  test('--sdk-version is used when flutter is not installed', () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run(['app', '--sdk-version', '3.47.6'],
        processes: nothingInstalled());
    expect(r.out, contains('GHSA-frr6-h895-5pxp  Flutter 3.47.6'));
    expect(r.err, contains('Dart SDK version is unknown'));
  });

  test('--json writes only JSON to stdout', () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run(['app', '--json', '--verbose'], env: const {});
    expect(() => jsonDecode(r.out), returnsNormally);
    expect(r.err, isNotEmpty);
  });

  test('--verbose lists packages that could not be looked up', () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run(['app', '--no-sdk', '--verbose']);
    expect(r.err, contains('my_fork (git)'));
    expect(r.err, contains('zeibun_core (path)'));
    expect(r.err, contains('internal_utils (dart.example.com)'));
    expect(r.err, contains('registry other than pub.dev'));
  });

  test('--version prints the version', () async {
    final r = await run(['--version']);
    expect(r.out.trim(), 'dartvulncheck $packageVersion');
  });

  test('packages shared by two projects are looked up once', () async {
    makeProject(tmp, 'app', 'app.lock');
    makeProject(tmp, 'app2', 'app.lock');
    final r = await run(['app', 'app2', '--no-sdk']);
    expect(
        r.api.requests.where((q) => q.url.path == '/advisories'), hasLength(1));
    expect(r.api.requests.where((q) => q.url.path == '/api/packages/dio'),
        hasLength(1));
    expect(r.out, contains('app2/pubspec.lock'));
  });

  test(
      'SDK advisories that cannot be read fail the run but the packages '
      'are still checked', () async {
    makeProject(tmp, 'app', 'app.lock');
    final api = FakeApi()..forbiddenRepos = {'dart-lang/sdk'};
    final r = await run(['app'], api: api);
    expect(r.code, ExitCodes.error);
    expect(r.out, contains('GHSA-9324-jv53-9cc8'));
    expect(
        r.out,
        contains('Flutter 3.47.6 stable / Dart 3.13.5 (flutter --version)\n'
            '  Could not check:'));
    expect(r.err, contains('dartvulncheck: SDK:'));
  });

  test('the repository-stage warning appears once for several projects',
      () async {
    makeProject(tmp, 'app', 'app.lock');
    makeProject(tmp, 'app2', 'app.lock');
    final api = FakeApi()..pubDevStatus = 503;
    final r = await run(['app', 'app2', '--no-sdk'], api: api);
    expect(
        'repository advisory lookups failed'.allMatches(r.err), hasLength(1));
  });

  test('a 401 from GitHub blames the token and does not fall back to OSV',
      () async {
    makeProject(tmp, 'app', 'app.lock');
    final api = FakeApi()..githubStatus = 401;
    final r = await run(['app'], api: api);
    expect(r.code, ExitCodes.error);
    expect(r.err, contains('rejected the token'));
    expect(r.api.requests.where((q) => q.url.host == 'api.osv.dev'), isEmpty);
  });

  test('an endpoint override is said out loud, and plain http is refused',
      () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run([
      'app',
      '--no-sdk'
    ], env: const {
      'GITHUB_TOKEN': 'tkn',
      'DARTVULNCHECK_OSV_API_URL': 'https://osv.internal.example',
    });
    expect(r.err, contains('DARTVULNCHECK_OSV_API_URL is set'));
    expect(r.code, ExitCodes.vulnerable);

    final refused = await run([
      'app',
      '--no-sdk'
    ], env: const {
      'DARTVULNCHECK_GITHUB_API_URL': 'http://ghe.example/api/v3',
    });
    expect(refused.code, ExitCodes.error);
    expect(refused.err, contains('DARTVULNCHECK_GITHUB_API_URL'));
    expect(refused.api.requests, isEmpty);
  });

  group('release notice', () {
    test('a newer release on pub.dev is named on stderr, not stdout', () async {
      makeProject(tmp, 'app', 'pure_dart.lock');
      final r = await run(['app', '--no-sdk'],
          api: FakeApi()..releasedVersion = '99.0.0');
      expect(r.err, contains('dartvulncheck 99.0.0 is available'));
      expect(r.out, isNot(contains('99.0.0')));
      expect(r.code, ExitCodes.ok);
    });

    test('the running release, or an older one, raises no notice', () async {
      makeProject(tmp, 'app', 'pure_dart.lock');
      for (final v in [packageVersion, '0.0.1']) {
        final r =
            await run(['app', '--no-sdk'], api: FakeApi()..releasedVersion = v);
        expect(r.err, isNot(contains('is available')), reason: v);
      }
    });

    test('a failed lookup changes neither the exit code nor the output',
        () async {
      makeProject(tmp, 'app', 'pure_dart.lock');
      final r =
          await run(['app', '--no-sdk'], api: FakeApi()..pubDevStatus = 500);
      expect(r.code, ExitCodes.ok);
      expect(r.err, isNot(contains('pub.dev')));
    });

    test('--verbose names why the lookup was skipped', () async {
      makeProject(tmp, 'app', 'pure_dart.lock');
      final r = await run(['app', '--no-sdk', '--verbose'],
          api: FakeApi()..pubDevStatus = 500);
      expect(r.err, contains('release check skipped: '));
      expect(r.code, ExitCodes.ok);
    });
  });

  test('--help wins over every other option', () async {
    final r = await run(['--json', '--strict', '--help']);
    expect(r.code, ExitCodes.ok);
    expect(r.out, startsWith('Usage'));
  });

  test('version.dart matches pubspec.yaml', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    expect(pubspec, contains('\nversion: $packageVersion\n'));
  });

  test('the install lines in README and example name the current version', () {
    final installLine =
        RegExp(r'activate dartvulncheck (\S+)|--git-ref v(\S+?)[`\s]');
    for (final path in ['README.md', 'example/README.md']) {
      final named = [
        for (final m in installLine.allMatches(File(path).readAsStringSync()))
          m.group(1) ?? m.group(2),
      ];
      expect(named, isNotEmpty, reason: path);
      expect(named, everyElement(packageVersion), reason: path);
    }
  });
}
