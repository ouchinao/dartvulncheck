import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:pub_semver/pub_semver.dart';

import '../model/sdk_info.dart';
import 'process_runner.dart';

class SdkDetection {
  final SdkInfo? info;
  final List<String> warnings;
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
    final warnings = <String>[];

    if (flutterOverride != null) {
      final v = _parseVersion(flutterOverride);
      if (v == null) {
        warnings.add('--sdk-version "$flutterOverride" is not a version');
      } else {
        return SdkDetection(
            SdkInfo(flutter: v, origin: '--sdk-version'), warnings);
      }
    }

    for (final dir in projectDirs) {
      final fvm = readFvmConfig(dir);
      if (fvm != null) return SdkDetection(fvm, warnings);
    }

    final flutter = await runner.run('flutter', ['--version', '--machine']);
    if (flutter != null && flutter.exitCode == 0) {
      final info = parseFlutterMachineVersion(flutter.stdout);
      if (info != null) return SdkDetection(info, warnings);
      warnings.add('cannot read the output of `flutter --version --machine`');
    }

    final dart = await runner.run('dart', ['--version']);
    if (dart != null && dart.exitCode == 0) {
      // Older SDKs print to stderr, newer ones to stdout.
      final info =
          parseDartVersion(dart.stderr) ?? parseDartVersion(dart.stdout);
      if (info != null) return SdkDetection(info, warnings);
    }

    warnings.add('the Flutter/Dart SDK version is unknown, so the SDK was '
        'not checked. Without `flutter` on PATH, pass it with --sdk-version');
    return SdkDetection(null, warnings);
  }

  // FVM's pin before `flutter` on PATH: with FVM the pin is what builds.
  static SdkInfo? readFvmConfig(String dir) {
    for (final (file, key) in [
      ('.fvmrc', 'flutter'),
      (p.join('.fvm', 'fvm_config.json'), 'flutterSdkVersion'),
    ]) {
      final f = File(p.join(dir, file));
      if (!f.existsSync()) continue;
      try {
        final json = jsonDecode(f.readAsStringSync());
        if (json is! Map) continue;
        final v = _parseVersion('${json[key]}');
        if (v != null) {
          return SdkInfo(flutter: v, origin: p.basename(file));
        }
      } on FormatException {
        continue;
      }
    }
    return null;
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
      origin: 'flutter --version',
    );
  }

  static SdkInfo? parseDartVersion(String output) {
    final m = RegExp(r'Dart SDK version:\s*(\S+)(?:\s*\((\w+)\))?')
        .firstMatch(output);
    if (m == null) return null;
    final v = _parseVersion(m.group(1)!);
    if (v == null) return null;
    return SdkInfo(dart: v, channel: m.group(2), origin: 'dart --version');
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
