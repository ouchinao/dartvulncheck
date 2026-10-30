import 'dart:convert';
import 'dart:io';

import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:path/path.dart' as p;

final fixturesDir = p.absolute('test', 'fixtures');

String fixture(String relative) =>
    File(p.join(fixturesDir, relative)).readAsStringSync();

Object? fixtureJson(String relative) => jsonDecode(fixture(relative));

/// A request seen by [FakeApi].
class SeenRequest {
  final String method;
  final Uri url;
  final Map<String, String> headers;
  final String body;
  SeenRequest(this.method, this.url, this.headers, this.body);
}

/// Serves the recorded fixtures as GitHub, pub.dev and OSV would.
///
/// Set [githubStatus] / [osvStatus] to simulate failures.
class FakeApi {
  final requests = <SeenRequest>[];
  int? githubStatus;
  Map<String, String> githubHeaders = const {};
  int? osvStatus;
  int? pubDevStatus;

  late final http.Client client = MockClient(handle);

  Future<http.Response> handle(http.Request request) async {
    requests.add(SeenRequest(
        request.method, request.url, request.headers, request.body));
    final url = request.url;
    switch (url.host) {
      case 'api.github.com':
        return _github(url);
      case 'pub.dev':
        if (pubDevStatus != null) return http.Response('', pubDevStatus!);
        return _pubDev(url);
      case 'api.osv.dev':
        if (osvStatus != null) return http.Response('', osvStatus!);
        return _osv(request);
    }
    return http.Response('not found', 404);
  }

  http.Response _json(Object? body, {Map<String, String> headers = const {}}) =>
      http.Response.bytes(utf8.encode(jsonEncode(body)), 200,
          headers: {'content-type': 'application/json', ...headers});

  http.Response _github(Uri url) {
    if (githubStatus != null) {
      return http.Response('{"message":"error"}', githubStatus!,
          headers: githubHeaders);
    }
    if (url.path == '/advisories') {
      return _json(fixtureJson('responses/github_global_advisories.json'));
    }
    final m = RegExp(r'^/repos/([^/]+/[^/]+)/security-advisories$')
        .firstMatch(url.path);
    if (m != null) {
      final file = switch (m.group(1)) {
        'dart-lang/sdk' => 'github_repo_advisories_dart_sdk.json',
        'flutter/flutter' => 'github_repo_advisories_flutter.json',
        'cfug/dio' => 'github_repo_advisories_cfug_dio.json',
        _ => null,
      };
      return _json(file == null ? [] : fixtureJson('responses/$file'));
    }
    return http.Response('{"message":"Not Found"}', 404);
  }

  http.Response _pubDev(Uri url) {
    final m = RegExp(r'^/api/packages/([^/]+)$').firstMatch(url.path);
    if (m == null) return http.Response('', 404);
    return switch (m.group(1)) {
      'dio' => _json(fixtureJson('responses/pub_dev_package_dio.json')),
      'http' => _json({
          'name': 'http',
          'latest': {
            'version': '1.5.0',
            'pubspec': {
              'name': 'http',
              'repository':
                  'https://github.com/dart-lang/http/tree/master/pkgs/http',
            },
          },
        }),
      _ => http.Response('{"error":{"code":"NotFound"}}', 404),
    };
  }

  http.Response _osv(http.Request request) {
    final url = request.url;
    if (url.path == '/v1/querybatch') {
      final queries =
          (jsonDecode(request.body) as Map)['queries'] as List<Object?>;
      final ids = {
        'dio': ['GHSA-9324-jv53-9cc8', 'GHSA-jwpw-q68h-r678'],
        'http': ['GHSA-4rgh-jx4f-qfcq'],
      };
      return _json({
        'results': [
          for (final q in queries.cast<Map<Object?, Object?>>())
            {
              'vulns': [
                for (final id
                    in ids[(q['package'] as Map)['name']] ?? const <String>[])
                  {'id': id, 'modified': '2024-02-16T08:19:11Z'},
              ],
            },
        ],
      });
    }
    final m = RegExp(r'^/v1/vulns/(.+)$').firstMatch(url.path);
    if (m != null) {
      final f =
          File(p.join(fixturesDir, 'responses', 'osv_vuln_${m.group(1)}.json'));
      if (f.existsSync()) return _json(jsonDecode(f.readAsStringSync()));
    }
    return http.Response('', 404);
  }
}

/// Replays recorded `flutter` / `dart` output.
class FakeProcessRunner implements ProcessRunner {
  final Map<String, ProcessOutput?> outputs;
  final calls = <String>[];
  FakeProcessRunner(this.outputs);

  @override
  Future<ProcessOutput?> run(String executable, List<String> arguments,
      {String? workingDirectory}) async {
    calls.add([executable, ...arguments].join(' '));
    return outputs[executable];
  }
}

FakeProcessRunner flutterInstalled() => FakeProcessRunner({
      'flutter':
          ProcessOutput(0, fixture('sdk/flutter_version_machine.txt'), ''),
      'dart': ProcessOutput(0, '', fixture('sdk/dart_version.txt')),
    });

FakeProcessRunner nothingInstalled() => FakeProcessRunner({});

/// Creates a project directory with [lockFixture] as pubspec.lock.
Directory makeProject(Directory parent, String name, String lockFixture,
    {String? pubspec}) {
  final dir = Directory(p.join(parent.path, name))..createSync(recursive: true);
  File(p.join(dir.path, 'pubspec.lock'))
      .writeAsStringSync(fixture('lockfiles/$lockFixture'));
  if (pubspec != null) {
    File(p.join(dir.path, 'pubspec.yaml')).writeAsStringSync(pubspec);
  }
  return dir;
}
