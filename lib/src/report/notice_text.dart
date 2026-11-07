import '../model/bundled_dart.dart';
import '../model/notices.dart';
import '../model/release.dart';
import 'labels.dart';

String describeWarning(Warning w) => switch (w) {
      SdkVersionOverrideInvalid(:final value) =>
        '--sdk-version "$value" is not a version',
      FlutterVersionUnreadable() =>
        'cannot read the output of `flutter --version --machine`',
      FvmConfigUnreadable(:final path) =>
        '$path cannot be read, so the FVM pin was ignored',
      SdkNotDetected() =>
        'the Flutter/Dart SDK version is unknown, so the SDK was not '
            'checked. Without `flutter` on PATH, pass it with --sdk-version',
      DartVersionUnknown(:final why) =>
        'the Dart SDK version is unknown, so Dart-only SDK advisories were '
            'not checked${_whyUnknown(why)}',
      NoGitHubToken() =>
        'GITHUB_TOKEN is not set, so repository advisories (published '
            'before GitHub review) were not checked',
      FellBackToOsv(:final cause) => '${cause.message}; using OSV.dev instead',
      RepositoryLookupsFailed(:final count) =>
        '$count repository advisory lookups failed (--verbose lists them)',
      SdkVersionMismatch(:final chosen, :final onPath, :final origin) =>
        'Flutter $chosen (${sdkOriginLabel(origin)}) was checked, but '
            '`flutter` on PATH is $onPath',
      ThirdPartyHostedChecked(:final count) =>
        '$count package(s) from a registry other than pub.dev were checked '
            'against pub.dev advisories of the same name (--verbose lists them)',
      NewerReleaseAvailable(:final current, :final latest) =>
        'dartvulncheck $latest is available; this run used $current '
            '(https://pub.dev/packages/dartvulncheck/changelog)',
      EndpointOverridden(:final variable, :final url, :final carriesToken) =>
        '$variable is set: requests'
            '${carriesToken ? ', and the token with them,' : ''} go to $url',
    };

String describeNote(LookupNote n) => switch (n) {
      HostedOutsidePubDev() =>
        'hosted outside pub.dev, repository advisories not checked',
      NoGitHubRepository() =>
        'no known GitHub repository, repository advisories not checked',
      RepositoryUnreadable() => 'advisories could not be read',
      LookupFailed(:final error) => error.message,
      // The origin and path, not the URL as answered: this line ends up in
      // a CI log (I3), and the query only repeats the request's own.
      RepositoryMoved(:final readFrom) =>
        'renamed or transferred; advisories were read from '
            '${_originAndPath(readFrom)}',
    };

// Uri(...) with the parts wanted, not replace(query: ''): that leaves a
// trailing '?'. The port is kept only when the URL named one.
String _originAndPath(Uri url) => Uri(
        scheme: url.scheme,
        host: url.host,
        port: url.hasPort ? url.port : null,
        path: url.path)
    .toString();

String describeReleaseUnknown(ReleaseUnknown s) =>
    'release check skipped: ${s.cause.message}';

// Appended to the line, not a line of its own: a CI grep for the leading
// phrase keeps matching, and the reason is what changes from run to run.
String _whyUnknown(BundledDartMissing why) => switch (why) {
      BundledDartNotLookedUp() => '',
      BundledDartNotListed(:final flutter) =>
        ': Flutter $flutter is not in the Flutter release manifest',
      BundledDartNotRecorded(:final flutter) =>
        ': the Flutter release manifest records no Dart SDK version for '
            'Flutter $flutter',
      BundledDartUnavailable(:final cause) => ': ${cause.message}',
    };
