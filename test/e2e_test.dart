@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';

import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'helpers.dart';

// A real process, not Runner in-process: exit codes and the stdout/stderr
// split are only proven at the process boundary.
void main() {
  late HttpServer server;
  late FakeApi api;
  late Directory tmp;
  final bin = p.absolute('bin', 'dartvulncheck.dart');

  setUpAll(() async {
    api = FakeApi();
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((req) async {
      final segments = req.uri.pathSegments;
      final host = switch (segments.first) {
        'github' => 'api.github.com',
        'pub' => 'pub.dev',
        'flutter' => 'storage.googleapis.com',
        _ => 'api.osv.dev',
      };
      final url = Uri.https(host, '/${segments.skip(1).join('/')}',
          req.uri.queryParameters.isEmpty ? null : req.uri.queryParameters);
      final forwarded = http.Request(req.method, url)
        ..body = await utf8.decodeStream(req);
      final res = await api.handle(forwarded);
      req.response.statusCode = res.statusCode;
      req.response.headers.contentType = ContentType.json;
      // A Location is forwarded, rewritten onto this server: FakeApi names
      // api.github.com, which from here would be another origin and refused,
      // and the point of forwarding it is to drive a hop through the real
      // client.
      if (res.headers['location'] case final location?) {
        final target = Uri.parse(location);
        req.response.headers.set(
            'location',
            Uri.http('${server.address.host}:${server.port}',
                    '/${segments.first}${target.path}', target.queryParameters)
                .toString());
      }
      req.response.add(res.bodyBytes);
      await req.response.close();
    });
  });
  tearDownAll(() => server.close(force: true));

  setUp(() => tmp = Directory.systemTemp.createTempSync('dvc'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> run(List<String> args) {
    final base = 'http://${server.address.host}:${server.port}';
    return Process.run(
      Platform.resolvedExecutable,
      ['run', bin, ...args],
      workingDirectory: tmp.path,
      environment: {
        'GITHUB_TOKEN': 'tkn',
        'DARTVULNCHECK_GITHUB_API_URL': '$base/github',
        'DARTVULNCHECK_PUB_URL': '$base/pub',
        'DARTVULNCHECK_OSV_API_URL': '$base/osv',
        // Without it the two --sdk-version runs would reach the real bucket.
        'DARTVULNCHECK_FLUTTER_RELEASES_URL': '$base/flutter',
      },
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );
  }

  test('exit 0: nothing to find', () async {
    makeProject(tmp, 'app', 'no_hosted.lock');
    final r = await run(['app', '--sdk-version', '3.47.8']);
    expect(r.exitCode, ExitCodes.ok, reason: '${r.stdout}${r.stderr}');
  });

  test("a renamed repository's advisories are read through the real client",
      () async {
    makeProject(tmp, 'app', 'app.lock');
    api.movedRepos = {'cfug/dio': 123};
    addTearDown(() => api.movedRepos = {});
    final r = await run(['app', '--no-sdk', '--verbose']);
    expect(r.exitCode, ExitCodes.vulnerable, reason: '${r.stderr}');
    expect(r.stdout, contains('GHSA-9324-jv53-9cc8'));
    expect(r.stderr, isNot(contains('repository advisory lookups failed')));
    expect(r.stderr, contains('cfug/dio: renamed or transferred'));
  });

  test('exit 3: vulnerabilities found', () async {
    makeProject(tmp, 'app', 'app.lock');
    final r = await run(['app', '--sdk-version', '3.47.6']);
    expect(r.exitCode, ExitCodes.vulnerable, reason: '${r.stderr}');
    expect(r.stdout, contains('GHSA-frr6-h895-5pxp'));
    // The manifest was asked through the loopback server, not the bucket.
    expect(r.stdout, contains('Dart 3.13.5 (Flutter release manifest)'));
    expect(api.requests.map((q) => q.url.host),
        contains('storage.googleapis.com'));
    expect(r.stdout, contains('GHSA-9324-jv53-9cc8'));
  });

  test('exit 1: one directory broken, the other still checked', () async {
    makeProject(tmp, 'app', 'app.lock');
    Directory(p.join(tmp.path, 'nolock')).createSync();
    final r = await run(['nolock', 'app', '--no-sdk']);
    expect(r.exitCode, ExitCodes.error);
    expect(r.stdout, contains('GHSA-9324-jv53-9cc8'));
    expect(r.stderr, contains('dart pub get'));
  });
}
