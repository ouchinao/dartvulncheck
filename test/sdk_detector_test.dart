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

  test('"3.13.5 (build 3.13.5)" reads as 3.13.5', () {
    final info = SdkDetector.parseFlutterMachineVersion(
        fixture('sdk/flutter_version_machine.txt'));
    expect(info!.dart, Version.parse('3.13.5'));
  });

  test('"3.14.0 (build 3.14.0-315.1.beta)" reads as the build, a pre-release',
      () {
    expect(parseSdkVersionText('3.14.0 (build 3.14.0-315.1.beta)'),
        Version.parse('3.14.0-315.1.beta'));
    expect(parseSdkVersionText('3.13.7'), Version.parse('3.13.7'));
    expect(parseSdkVersionText(''), isNull);
    expect(parseSdkVersionText('stable'), isNull);
  });

  test('dart --version in the build form gives the build and the channel', () {
    final info = SdkDetector.parseDartVersion(
        'Dart SDK version: 3.14.0 (build 3.14.0-315.3.beta) (beta) '
        '(Wed Oct 29 2026) on "linux_x64"');
    expect(info!.dart, Version.parse('3.14.0-315.3.beta'));
    expect(info.channel, 'beta');
  });

  test('an upgrade banner before the JSON is skipped', () {
    final info = SdkDetector.parseFlutterMachineVersion(
        fixture('sdk/flutter_version_banner_prefix.txt'));
    expect(info!.flutter, Version.parse('3.47.6'));
  });

  test('.fvmrc wins over flutter on PATH, and a difference is reported',
      () async {
    File(p.join(tmp.path, '.fvmrc')).writeAsStringSync('{"flutter": "3.47.8"}');
    final d =
        await SdkDetector(flutterInstalled()).detect(projectDirs: [tmp.path]);
    expect(d.info!.flutter, Version.parse('3.47.8'));
    expect(d.info!.origin, SdkOrigin.fvmrc);
    expect(d.info!.dart, isNull);
    expect(d.info!.dartOrigin, SdkOrigin.fvmrc);
    expect(
        d.warnings.single,
        isA<SdkVersionMismatch>()
            .having((w) => w.onPath, 'onPath', Version.parse('3.47.6')));
  });

  test(
      '.fvmrc that agrees with flutter on PATH takes its Dart version and '
      'channel, and raises no warning', () async {
    File(p.join(tmp.path, '.fvmrc')).writeAsStringSync('{"flutter": "3.47.6"}');
    final d =
        await SdkDetector(flutterInstalled()).detect(projectDirs: [tmp.path]);
    expect(d.info!.origin, SdkOrigin.fvmrc);
    expect(d.info!.dart, Version.parse('3.13.5'));
    expect(d.info!.dartOrigin, SdkOrigin.flutterCommand);
    expect(d.info!.channel, 'stable');
    expect(d.warnings, isEmpty);
  });

  test('--sdk-version that agrees with flutter on PATH takes its Dart version',
      () async {
    final d = await SdkDetector(flutterInstalled())
        .detect(flutterOverride: '3.47.6', projectDirs: [tmp.path]);
    expect(d.info!.origin, SdkOrigin.override);
    expect(d.info!.dart, Version.parse('3.13.5'));
    expect(d.info!.dartOrigin, SdkOrigin.flutterCommand);
    expect(d.warnings, isEmpty);
  });

  test('a flutter on PATH that reports no Dart version leaves the pin as it is',
      () async {
    File(p.join(tmp.path, '.fvmrc')).writeAsStringSync('{"flutter": "3.47.6"}');
    final runner = FakeProcessRunner({
      'flutter': ProcessOutput(
          0, '{"frameworkVersion": "3.47.6", "channel": "stable"}', ''),
    });
    final d = await SdkDetector(runner).detect(projectDirs: [tmp.path]);
    expect(d.info!.dart, isNull);
    expect(d.info!.dartOrigin, SdkOrigin.fvmrc);
    expect(d.warnings, isEmpty);
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
    expect(d.warnings.single, isA<SdkVersionMismatch>());
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
