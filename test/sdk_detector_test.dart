import 'dart:io';

import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:path/path.dart' as p;
import 'package:pub_semver/pub_semver.dart';
import 'package:test/test.dart';

import 'helpers.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('dvc'));
  tearDown(() => tmp.deleteSync(recursive: true));

  test('flutter --version --machine gives Flutter, Dart and channel', () async {
    final d =
        await SdkDetector(flutterInstalled()).detect(projectDirs: [tmp.path]);
    expect(d.info!.flutter, Version.parse('3.47.6'));
    expect(d.info!.dart, Version.parse('3.13.5'));
    expect(d.info!.channel, 'stable');
    expect(d.info!.origin, SdkOrigin.flutterCommand);
  });

  test('"3.13.5 (build 3.13.5)" keeps only the first token', () {
    final info = SdkDetector.parseFlutterMachineVersion(
        fixture('sdk/flutter_version_machine.txt'));
    expect(info!.dart, Version.parse('3.13.5'));
  });

  test('an upgrade banner before the JSON is skipped', () {
    final info = SdkDetector.parseFlutterMachineVersion(
        fixture('sdk/flutter_version_banner_prefix.txt'));
    expect(info!.flutter, Version.parse('3.47.6'));
  });

  test('.fvmrc wins over flutter on PATH', () async {
    File(p.join(tmp.path, '.fvmrc')).writeAsStringSync('{"flutter": "3.47.8"}');
    final runner = flutterInstalled();
    final d = await SdkDetector(runner).detect(projectDirs: [tmp.path]);
    expect(d.info!.flutter, Version.parse('3.47.8'));
    expect(d.info!.origin, SdkOrigin.fvmrc);
    expect(runner.calls, isEmpty);
  });

  test('.fvmrc with a channel name instead of a version is ignored', () async {
    File(p.join(tmp.path, '.fvmrc')).writeAsStringSync('{"flutter": "stable"}');
    final d =
        await SdkDetector(flutterInstalled()).detect(projectDirs: [tmp.path]);
    expect(d.info!.origin, SdkOrigin.flutterCommand);
  });

  test('an unreadable .fvmrc warns instead of being skipped silently',
      () async {
    File(p.join(tmp.path, '.fvmrc')).writeAsStringSync('{not json');
    final d =
        await SdkDetector(flutterInstalled()).detect(projectDirs: [tmp.path]);
    expect(d.info!.origin, SdkOrigin.flutterCommand);
    expect(d.warnings.single, isA<FvmConfigUnreadable>());
  });

  test('--sdk-version wins over everything', () async {
    File(p.join(tmp.path, '.fvmrc')).writeAsStringSync('{"flutter": "3.47.8"}');
    final d = await SdkDetector(flutterInstalled())
        .detect(flutterOverride: '3.40.0', projectDirs: [tmp.path]);
    expect(d.info!.flutter, Version.parse('3.40.0'));
    expect(d.info!.dart, isNull);
    expect(d.info!.origin, SdkOrigin.override);
  });

  test('dart --version on stderr is used without Flutter', () async {
    final runner = FakeProcessRunner({
      'dart': ProcessOutput(0, '', fixture('sdk/dart_version.txt')),
    });
    final d = await SdkDetector(runner).detect(projectDirs: [tmp.path]);
    expect(d.info!.flutter, isNull);
    expect(d.info!.dart, Version.parse('3.13.7'));
    expect(d.info!.origin, SdkOrigin.dartCommand);
  });

  test('nothing found: no SDK info and one warning, not an error', () async {
    final d =
        await SdkDetector(nothingInstalled()).detect(projectDirs: [tmp.path]);
    expect(d.info, isNull);
    expect(d.warnings.single, isA<SdkNotDetected>());
  });
}
