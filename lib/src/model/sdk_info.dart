import 'package:pub_semver/pub_semver.dart';

enum SdkOrigin { override, fvmrc, fvmConfig, flutterCommand, dartCommand }

class SdkInfo {
  final Version? flutter;
  final Version? dart;
  final String? channel;
  final SdkOrigin origin;

  const SdkInfo({this.flutter, this.dart, this.channel, required this.origin});
}
