import 'package:pub_semver/pub_semver.dart';

import '../model/bundled_dart.dart';
import '../model/errors.dart';
import '../model/sdk_info.dart';
import 'http_fetcher.dart';

// Not an AdvisorySource: Flutter's release manifest answers one fact only,
// which Dart SDK a Flutter release bundles, and nothing stands in for it.
// It is asked when a pin names the Flutter version and nothing on PATH can
// say the Dart one.
class FlutterReleases {
  final HttpFetcher fetcher;
  final Uri base;
  FlutterReleases(this.fetcher, {required this.base});

  static const sourceName = 'the Flutter release manifest';

  // The Linux file on every OS, not the one for the OS the tool runs on:
  // the version-to-Dart map is the same in the macOS file and a superset of
  // the Windows one, and one recorded fixture is enough.
  static const manifestFile = 'releases_linux.json';

  // Returned, not thrown: an unknown Dart version is a warning, and this
  // lookup must never reach the exit code (D4).
  Future<BundledDart> bundledDart(Version flutter) async {
    final url = base.replace(path: '${_trim(base.path)}/$manifestFile');
    try {
      // Through the fetcher alone, not the GitHub client: its headers carry
      // the token, which has no business here (A2). Nothing from the
      // project is in the URL either: the pin is matched against the
      // document, never sent (B1).
      final response = await fetcher.get(url, sourceName: sourceName);
      if (response.statusCode != 200) {
        throw UnexpectedResponse(sourceName, 'HTTP ${response.statusCode}');
      }
      return parse(decodeJson(response, sourceName), flutter);
    } on VulncheckException catch (e) {
      return BundledDartUnavailable(e);
    }
  }

  static BundledDart parse(Object? json, Version flutter) {
    final releases = json is Map ? json['releases'] : null;
    if (releases is! List) {
      return const BundledDartUnavailable(
          UnexpectedResponse(sourceName, 'no releases list'));
    }
    final listed = [
      for (final r in releases)
        if (r is Map && _version(r['version']) == flutter) r,
    ];
    if (listed.isEmpty) return BundledDartNotListed(flutter);
    // Every entry for the version, not the ones on a channel: nothing that
    // reaches this lookup carries a channel except a `flutter` on PATH that
    // printed no Dart version, and a version listed on two channels (2.0.0
    // on beta and on stable) bundles one Dart SDK either way.
    final darts = {
      for (final r in listed)
        if (r['dart_sdk_version'] case final String text)
          if (parseSdkVersionText(text) case final v?) v,
    };
    if (darts.isEmpty) return BundledDartNotRecorded(flutter);
    // Given up, not guessed: entries that disagree are a malformed manifest
    // from this tool's point of view, and an auditor should see that.
    if (darts.length > 1) {
      return BundledDartUnavailable(UnexpectedResponse(sourceName,
          'Flutter $flutter is listed with several Dart SDK versions'));
    }
    return BundledDartFound(darts.single);
  }

  // Skipped, not an error: the oldest entries read "v1.12.13+hotfix.9",
  // which is not a version, and they can never be the one asked for.
  static Version? _version(Object? text) {
    if (text is! String) return null;
    try {
      return Version.parse(text);
    } on FormatException {
      return null;
    }
  }

  static String _trim(String path) =>
      path.endsWith('/') ? path.substring(0, path.length - 1) : path;
}
