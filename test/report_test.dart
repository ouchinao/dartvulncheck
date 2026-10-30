import 'dart:convert';
import 'dart:io';

import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

import 'helpers.dart';

/// Golden tests. Run with `UPDATE_GOLDENS=1 dart test` to rewrite them after
/// an intended change, then review the diff.
void main() {
  final goldens = p.absolute('test', 'goldens');
  late Directory tmp;

  setUp(() {
    tmp = Directory.systemTemp.createTempSync('dvc');
    makeProject(tmp, 'app', 'app.lock');
    makeProject(tmp, p.join('packages', 'zeibun_core'), 'pure_dart.lock');
  });
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<String> render(List<String> extra) async {
    final out = StringBuffer();
    await Runner(
      client: FakeApi().client,
      processRunner: flutterInstalled(),
      environment: const {'GITHUB_TOKEN': 'tkn'},
      out: out,
      err: StringBuffer(),
      retryDelay: Duration.zero,
    ).run([
      p.join(tmp.path, 'app'),
      p.join(tmp.path, 'packages', 'zeibun_core'),
      ...extra,
    ]);
    // Not Directory.current = tmp: it is process-wide and breaks test files
    // that run in parallel.
    return '$out'.replaceAll('${tmp.path}/', '');
  }

  void expectGolden(String actual, String name) {
    final file = File(p.join(goldens, name));
    if (Platform.environment['UPDATE_GOLDENS'] == '1') {
      file
        ..createSync(recursive: true)
        ..writeAsStringSync(actual);
    }
    expect(actual, file.readAsStringSync(), reason: 'golden $name');
  }

  test('text report matches the golden', () async {
    expectGolden(await render([]), 'report.txt');
  });

  test('JSON report matches the golden', () async {
    expectGolden(await render(['--json']), 'report.json');
  });

  test('JSON keeps the version 1 shape', () async {
    final json = jsonDecode(await render(['--json'])) as Map<String, Object?>;
    expect(json['version'], 1);
    expect(json.keys, ['version', 'tool', 'sdk', 'projects', 'summary']);
    expect(
        (json['summary'] as Map).keys, ['findings', 'ignored', 'unverified']);
    final project = (json['projects'] as List).first as Map;
    expect(project.keys, ['path', 'packages', 'findings']);
    expect((project['packages'] as Map).keys, ['total', 'queried', 'skipped']);
    final finding = (project['findings'] as List).first as Map;
    expect(finding.keys, [
      'id',
      'aliases',
      'kind',
      'subject',
      'current',
      'fixed',
      'alsoFixedIn',
      'dependency',
      'severity',
      'summary',
      'url',
      'ignored',
    ]);
  });

  test('SDK findings come first, then packages by severity', () async {
    final json = jsonDecode(await render(['--json'])) as Map<String, Object?>;
    final findings =
        ((json['projects'] as List).first as Map)['findings'] as List<Object?>;
    final kinds = [for (final f in findings) (f as Map)['kind']];
    expect(kinds, [
      'sdk',
      'sdkUnverified',
      'package',
      'package',
      'package',
      'packageUnverified',
    ]);
  });

  test('an SDK finding shared by two projects counts once', () async {
    final json = jsonDecode(await render(['--json'])) as Map<String, Object?>;
    expect(json['summary'], {'findings': 4, 'ignored': 0, 'unverified': 2});
  });
}
