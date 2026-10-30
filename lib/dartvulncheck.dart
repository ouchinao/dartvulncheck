/// Checks pubspec.lock and the Flutter/Dart SDK against known
/// vulnerabilities.
///
/// Use [Runner] for the command-line behaviour, or the lower layers
/// directly: [readLockfile] → an [AdvisorySource] → [matchPackages] /
/// [matchSdk] → [renderText] / [renderJson].
library;

export 'src/cli/exit_codes.dart';
export 'src/cli/options.dart';
export 'src/cli/runner.dart';
export 'src/lockfile/lockfile.dart';
export 'src/match/matcher.dart';
export 'src/match/range.dart';
export 'src/model/advisory.dart';
export 'src/model/errors.dart';
export 'src/model/finding.dart';
export 'src/model/package_ref.dart';
export 'src/model/sdk_info.dart';
export 'src/model/severity.dart';
export 'src/report/json_report.dart';
export 'src/report/result.dart';
export 'src/report/text_report.dart';
export 'src/sdk/process_runner.dart';
export 'src/sdk/sdk_detector.dart';
export 'src/sources/advisory_source.dart';
export 'src/sources/fallback.dart';
export 'src/sources/github_client.dart';
export 'src/sources/github_global.dart';
export 'src/sources/github_repository.dart';
export 'src/sources/http_fetcher.dart';
export 'src/sources/osv.dart';
export 'src/sources/pub_dev.dart';
export 'src/version.dart';
