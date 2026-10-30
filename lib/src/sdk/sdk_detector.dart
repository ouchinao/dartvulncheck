import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:pub_semver/pub_semver.dart';

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
      final v = _parseVersion(flutterOverride);
      if (v == null) {
        warnings.add(SdkVersionOverrideInvalid(flutterOverride));
      } else {
        return SdkDetection(
            SdkInfo(flutter: v, origin: SdkOrigin.override), warnings);
      }
    }

    for (final dir in projectDirs) {
      final (fvm, fvmWarnings) = readFvmConfig(dir);
      warnings.addAll(fvmWarnings);
      if (fvm != null) return SdkDetection(fvm, warnings);
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
      final v = _parseVersion('${json[key]}');
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
    final flutter = _parseVersion('${json['frameworkVersion']}');
    final dart = _parseVersion('${json['dartSdkVersion']}');
    if (flutter == null && dart == null) return null;
    final channel = json['channel'];
    return SdkInfo(
      flutter: flutter,
      dart: dart,
      channel: channel is String && channel.isNotEmpty ? channel : null,
      origin: SdkOrigin.flutterCommand,
    );
  }

  static SdkInfo? parseDartVersion(String output) {
    final m = RegExp(r'Dart SDK version:\s*(\S+)(?:\s*\((\w+)\))?')
        .firstMatch(output);
    if (m == null) return null;
    final v = _parseVersion(m.group(1)!);
    if (v == null) return null;
    return SdkInfo(dart: v, channel: m.group(2), origin: SdkOrigin.dartCommand);
  }

  static Version? _parseVersion(String text) {
    final token = text.trim().split(RegExp(r'\s+')).first;
    try {
      return Version.parse(token);
    } on FormatException {
      return null;
    }
  }
}
