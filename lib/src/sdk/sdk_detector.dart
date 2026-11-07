import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../model/notices.dart';
import '../model/sdk_info.dart';
import 'process_runner.dart';

class SdkDetection {
  final SdkInfo? info;
  final List<Warning> warnings;
  const SdkDetection(this.info, [this.warnings = const []]);
}

// Neither the lockfile's `sdks:` (a lower bound, not the real version) nor
// Platform.version (the Dart running this tool may not build the project).
class SdkDetector {
  final ProcessRunner runner;
  const SdkDetector(this.runner);

  Future<SdkDetection> detect({
    String? flutterOverride,
    List<String> projectDirs = const ['.'],
  }) async {
    final warnings = <Warning>[];

    if (flutterOverride != null) {
      final v = parseSdkVersionText(flutterOverride);
      if (v == null) {
        warnings.add(SdkVersionOverrideInvalid(flutterOverride));
      } else {
        return _chosenElsewhere(
            SdkInfo(flutter: v, origin: SdkOrigin.override), warnings);
      }
    }

    for (final dir in projectDirs) {
      final (fvm, fvmWarnings) = readFvmConfig(dir);
      warnings.addAll(fvmWarnings);
      if (fvm != null) return _chosenElsewhere(fvm, warnings);
    }

    final flutter = await runner.run('flutter', ['--version', '--machine']);
    if (flutter != null && flutter.exitCode == 0) {
      final info = parseFlutterMachineVersion(flutter.stdout);
      if (info != null) return SdkDetection(info, warnings);
      warnings.add(const FlutterVersionUnreadable());
    }

    final dart = await runner.run('dart', ['--version']);
    if (dart != null && dart.exitCode == 0) {
      // Both streams, not only stderr: newer SDKs print to stdout.
      final info =
          parseDartVersion(dart.stderr) ?? parseDartVersion(dart.stdout);
      if (info != null) return SdkDetection(info, warnings);
    }

    warnings.add(const SdkNotDetected());
    return SdkDetection(null, warnings);
  }

  // `flutter` on PATH is still asked when the version came from elsewhere,
  // not skipped: a .fvmrc left in a checkout that flutter-action builds, or a
  // forged one, names a version nothing builds with, and the difference is
  // the only sign of it. When PATH has the same release, its Dart version
  // and channel are the pin's too (one Flutter release bundles one Dart
  // SDK). From a different release nothing is taken: with FVM the pin is
  // what builds, and PATH only confirms it (S3).
  Future<SdkDetection> _chosenElsewhere(
      SdkInfo chosen, List<Warning> warnings) async {
    final onPath = await _flutterOnPath();
    if (onPath == null || onPath.flutter == null) {
      return SdkDetection(chosen, warnings);
    }
    if (onPath.flutter != chosen.flutter) {
      return SdkDetection(chosen, [
        ...warnings,
        SdkVersionMismatch(
            chosen: chosen.flutter!,
            onPath: onPath.flutter!,
            origin: chosen.origin),
      ]);
    }
    final dart = onPath.dart;
    if (dart == null) return SdkDetection(chosen, warnings);
    return SdkDetection(
        chosen.withDart(dart,
            from: SdkOrigin.flutterCommand, channel: onPath.channel),
        warnings);
  }

  Future<SdkInfo?> _flutterOnPath() async {
    final output = await runner.run('flutter', ['--version', '--machine']);
    if (output == null || output.exitCode != 0) return null;
    return parseFlutterMachineVersion(output.stdout);
  }

  // FVM's pin before `flutter` on PATH: with FVM the pin is what builds.
  // A file that cannot be read is not skipped silently: falling through to
  // `flutter` on PATH may then report a version FVM never builds with.
  static (SdkInfo?, List<Warning>) readFvmConfig(String dir) {
    final warnings = <Warning>[];
    for (final (file, key, origin) in [
      ('.fvmrc', 'flutter', SdkOrigin.fvmrc),
      (
        p.join('.fvm', 'fvm_config.json'),
        'flutterSdkVersion',
        SdkOrigin.fvmConfig
      ),
    ]) {
      final f = File(p.join(dir, file));
      if (!f.existsSync()) continue;
      final Object? json;
      try {
        json = jsonDecode(f.readAsStringSync());
      } on FormatException {
        warnings.add(FvmConfigUnreadable(f.path));
        continue;
      }
      if (json is! Map) {
        warnings.add(FvmConfigUnreadable(f.path));
        continue;
      }
      final v = parseSdkVersionText('${json[key]}');
      if (v != null) return (SdkInfo(flutter: v, origin: origin), warnings);
    }
    return (null, warnings);
  }

  // Not jsonDecode on the whole output: Flutter may print an upgrade banner
  // before the JSON.
  static SdkInfo? parseFlutterMachineVersion(String output) {
    final start = output.indexOf('{');
    final end = output.lastIndexOf('}');
    if (start < 0 || end < start) return null;
    final Object? json;
    try {
      json = jsonDecode(output.substring(start, end + 1));
    } on FormatException {
      return null;
    }
    if (json is! Map) return null;
    final flutter = parseSdkVersionText('${json['frameworkVersion']}');
    final dart = parseSdkVersionText('${json['dartSdkVersion']}');
    if (flutter == null && dart == null) return null;
    final channel = json['channel'];
    return SdkInfo(
      flutter: flutter,
      dart: dart,
      channel: channel is String && channel.isNotEmpty ? channel : null,
      origin: SdkOrigin.flutterCommand,
    );
  }

  // The "(build ...)" group is captured with the version, not cut off at
  // the first space: Flutter's bundled dart prints
  // "3.14.0 (build 3.14.0-315.3.beta) (beta)", and the build is the version.
  static SdkInfo? parseDartVersion(String output) {
    final m = RegExp(r'Dart SDK version:\s*(\S+(?:\s*\(build [^)]*\))?)'
            r'(?:\s*\((\w+)\))?')
        .firstMatch(output);
    if (m == null) return null;
    final v = parseSdkVersionText(m.group(1)!);
    if (v == null) return null;
    return SdkInfo(dart: v, channel: m.group(2), origin: SdkOrigin.dartCommand);
  }
}
