import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;

import '../lockfile/lockfile.dart';
import '../match/matcher.dart';
import '../model/advisory.dart';
import '../model/errors.dart';
import '../model/finding.dart';
import '../model/sdk_info.dart';
import '../report/json_report.dart';
import '../report/result.dart';
import '../report/text_report.dart';
import '../sdk/process_runner.dart';
import '../sdk/sdk_detector.dart';
import '../sources/advisory_source.dart';
import '../sources/fallback.dart';
import '../sources/github_client.dart';
import '../sources/github_global.dart';
import '../sources/github_repository.dart';
import '../sources/http_fetcher.dart';
import '../sources/osv.dart';
import '../sources/pub_dev.dart';
import '../version.dart';
import 'exit_codes.dart';
import 'options.dart';

class Runner {
  final http.Client client;
  final ProcessRunner processRunner;
  final Map<String, String> environment;
  final StringSink out;
  final StringSink err;
  final Duration retryDelay;

  Runner({
    required this.client,
    this.processRunner = const SystemProcessRunner(),
    required this.environment,
    required this.out,
    required this.err,
    this.retryDelay = const Duration(seconds: 1),
  });

  Future<int> run(List<String> args) async {
    final Options options;
    try {
      options = Options.parse(args);
    } on UsageException catch (e) {
      err
        ..writeln('dartvulncheck: ${e.message}')
        ..writeln()
        ..writeln(Options.usage);
      return ExitCodes.error;
    }
    if (options.help) {
      out.writeln(Options.usage);
      return ExitCodes.ok;
    }
    if (options.version) {
      out.writeln('dartvulncheck $packageVersion');
      return ExitCodes.ok;
    }

    final result = await check(options);
    out.write(options.json ? renderJson(result) : renderText(result));
    for (final project in result.projects) {
      if (project.error != null) {
        err.writeln('dartvulncheck: ${project.dir}: ${project.error!.message}');
      }
    }
    return result.exitCode(failOn: options.failOn, strict: options.strict);
  }

  void _warn(String message) => err.writeln('dartvulncheck: 注意: $message');

  Future<CheckResult> check(Options options) async {
    final endpoints = Endpoints.fromEnvironment(environment);
    final fetcher = HttpFetcher(client, retryDelay: retryDelay);
    final token = environment['GITHUB_TOKEN'];
    final github =
        GitHubClient(fetcher, apiBase: endpoints.githubApi, token: token);
    final repoFetcher = RepositoryAdvisoryFetcher(github);
    final AdvisorySource primary = FallbackSource(
      GitHubGlobalSource(github),
      OsvSource(fetcher, base: endpoints.osvApi),
      onFallback: (e) => _warn('${e.message}。OSV.dev に切り替えて照会します'),
    );

    RepositoryPackageSource? repoSource;
    if (options.repoAdvisories) {
      if (github.hasToken) {
        repoSource = RepositoryPackageSource(
            PubDevClient(fetcher, base: endpoints.pubDev), repoFetcher);
      } else {
        _warn('GITHUB_TOKEN が無いので、リポジトリアドバイザリ（レビュー前の速報）は'
            '見ていません');
      }
    }

    SdkInfo? sdk;
    List<Advisory>? sdkAdvisories;
    VulncheckException? sdkError;
    if (options.checkSdk) {
      final detection = await SdkDetector(processRunner).detect(
          flutterOverride: options.sdkVersion,
          projectDirs: [...options.directories, '.']);
      detection.warnings.forEach(_warn);
      sdk = detection.info;
      if (sdk != null) {
        try {
          sdkAdvisories = await SdkAdvisorySource(repoFetcher).fetchAll();
        } on VulncheckException catch (e) {
          sdkError = e;
        }
      }
    }

    var dartUnknownWarned = false;
    final projects = <ProjectResult>[];
    for (final dir in options.directories) {
      final lockPath = p.normalize(p.join(dir, 'pubspec.lock'));
      Lockfile? lock;
      try {
        if (sdkError != null) throw sdkError;
        lock = readLockfile(lockPath);
        final ignored = {
          ...readIgnoredAdvisories(p.join(dir, 'pubspec.yaml')),
          ...options.ignore,
        };
        final targets = lock.hosted
            .where((pkg) => options.transitive || pkg.dependency.isDirect)
            .toList();

        final advisories = <Advisory>[
          if (targets.isNotEmpty) ...await primary.query(targets),
        ];
        if (repoSource != null && targets.isNotEmpty) {
          repoSource.notes.clear();
          advisories.addAll(await repoSource.query(targets));
          if (repoSource.failures > 0) {
            _warn('$dir: リポジトリアドバイザリを ${repoSource.failures} 件取れませんでした'
                '${options.verbose ? '' : '（--verbose で一覧）'}');
          }
        }

        final findings = <Finding>[
          ...matchPackages(targets, advisories, ignored: ignored),
        ];
        if (sdk != null && sdkAdvisories != null) {
          final m = matchSdk(sdk, sdkAdvisories,
              includeFlutter: lock.usesFlutter, ignored: ignored);
          findings.addAll(m.findings);
          if (m.dartVersionUnknown && !dartUnknownWarned) {
            dartUnknownWarned = true;
            _warn('Dart SDK の版が分からないので、Dart SDK だけのアドバイザリは'
                '照合していません');
          }
        }

        final project = ProjectResult(
          dir: dir,
          lockPath: lockPath,
          lockfile: lock,
          findings: sortFindings(findings),
          queried: targets.length,
        );
        projects.add(project);
        if (options.verbose) {
          _verbose(project, repoSource?.notes ?? const [],
              skippedTransitive: lock.hosted.length - targets.length);
        }
      } on VulncheckException catch (e) {
        projects.add(ProjectResult(
            dir: dir, lockPath: lockPath, lockfile: lock, error: e));
      }
    }

    return CheckResult(sdk: sdk, projects: projects);
  }

  void _verbose(ProjectResult project, List<String> notes,
      {required int skippedTransitive}) {
    final lock = project.lockfile!;
    final ignored = project.findings.where((f) => f.ignored).toList();
    err.writeln('${project.dir}: 照会 ${project.queried} 件、'
        '無視 ${ignored.length} 件');
    if (skippedTransitive > 0) {
      err.writeln('  --no-transitive で飛ばした推移的依存: $skippedTransitive 件');
    }
    if (lock.skipped.isNotEmpty) {
      err.writeln('  照会できなかったパッケージ: ${lock.skipped.join(', ')}');
    }
    for (final pkg in lock.hosted.where((h) => h.isThirdPartyHosted)) {
      err.writeln('  ${pkg.name}: ${pkg.hostedUrl} でホストされています。'
          'pub.dev の同名パッケージのアドバイザリと照合しています');
    }
    for (final f in ignored) {
      err.writeln('  無視: ${f.id} ${f.subject} ${f.current}');
    }
    for (final note in notes) {
      err.writeln('  $note');
    }
  }
}
