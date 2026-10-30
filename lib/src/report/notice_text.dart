import '../model/notices.dart';
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
      DartVersionUnknown() =>
        'the Dart SDK version is unknown, so Dart-only SDK advisories were '
            'not checked',
      NoGitHubToken() =>
        'GITHUB_TOKEN is not set, so repository advisories (published '
            'before GitHub review) were not checked',
      FellBackToOsv(:final cause) => '${cause.message}; using OSV.dev instead',
      RepositoryLookupsFailed(:final count) =>
        '$count repository advisory lookups failed (--verbose lists them)',
      SdkVersionMismatch(:final chosen, :final onPath, :final origin) =>
        'Flutter $chosen (${sdkOriginLabel(origin)}) was checked, but '
            '`flutter` on PATH is $onPath',
      EndpointOverridden(:final variable, :final url) =>
        '$variable is set: requests, and the token with them, go to $url',
    };

String describeNote(LookupNote n) => switch (n) {
      HostedOutsidePubDev() =>
        'hosted outside pub.dev, repository advisories not checked',
      NoGitHubRepository() =>
        'no known GitHub repository, repository advisories not checked',
      RepositoryUnreadable() => 'advisories could not be read',
      LookupFailed(:final error) => error.message,
    };
