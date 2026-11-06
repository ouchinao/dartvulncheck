import 'package:pub_semver/pub_semver.dart';

enum SdkOrigin { override, fvmrc, fvmConfig, flutterCommand, dartCommand }

class SdkInfo {
  final Version? flutter;
  final Version? dart;
  final String? channel;
  final SdkOrigin origin;

  // Its own origin, not `origin` for both: a pin names only Flutter, and
  // the Dart version then comes from elsewhere, which the report must say
  // (S3, R1). Not nullable: null would mean both "the same as origin" and
  // "no Dart version".
  final SdkOrigin dartOrigin;

  const SdkInfo({
    this.flutter,
    this.dart,
    this.channel,
    required this.origin,
    SdkOrigin? dartOrigin,
  }) : dartOrigin = dartOrigin ?? origin;

  // A copy, not a mutable field: an SdkInfo is passed around as a fact.
  // The channel is taken only when none is known: a pin that names one is
  // not second-guessed.
  SdkInfo withDart(Version dart, {required SdkOrigin from, String? channel}) =>
      SdkInfo(
        flutter: flutter,
        dart: dart,
        channel: this.channel ?? channel,
        origin: origin,
        dartOrigin: from,
      );
}

// The build token, not the first one: Flutter's beta and dev builds write
// their Dart SDK as "3.14.0 (build 3.14.0-315.1.beta)", and 3.14.0 is above
// every 3.14.0-... pre-release, so it would compare as fixed against a bound
// such as "< 3.14.0-315.3.beta (beta)" that the real version is inside.
Version? parseSdkVersionText(String text) {
  final build = RegExp(r'\(build\s+([^\s)]+)\)').firstMatch(text);
  final token =
      build?.group(1) ?? text.trim().split(RegExp(r'\s+')).firstOrNull;
  if (token == null || token.isEmpty) return null;
  try {
    return Version.parse(token);
  } on FormatException {
    return null;
  }
}
