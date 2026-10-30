import 'package:http/http.dart' as http;

import '../check/checker.dart';
import '../check/result.dart';
import '../model/errors.dart';
import '../model/notices.dart';
import '../report/json_report.dart';
import '../report/notice_text.dart';
import '../report/text_report.dart';
import '../report/verbose_report.dart';
import '../sdk/process_runner.dart';
import '../sdk/sdk_detector.dart';
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
    final Command command;
    try {
      command = Command.parse(args);
    } on UsageException catch (e) {
      err
        ..writeln('dartvulncheck: ${e.message}')
        ..writeln()
        ..writeln(Command.usage);
      return ExitCodes.error;
    }

    switch (command) {
      case ShowHelp():
        out.writeln(Command.usage);
        return ExitCodes.ok;
      case ShowVersion():
        out.writeln('dartvulncheck $packageVersion');
        return ExitCodes.ok;
      case RunCheck():
        return _runCheck(command);
    }
  }

  Future<int> _runCheck(RunCheck command) async {
    final result = await _buildChecker(command).check(command.check);
    out.write(switch (command.format) {
      OutputFormat.text => renderText(result),
      OutputFormat.json => renderJson(result),
    });
    if (command.verbose) err.write(renderVerbose(result));
    _reportErrors(result);
    return exitCodeFor(result, failOn: command.failOn, strict: command.strict);
  }

  Checker _buildChecker(RunCheck command) {
    final endpoints = Endpoints.fromEnvironment(environment);
    final fetcher = HttpFetcher(client, retryDelay: retryDelay);
    final github = GitHubClient(fetcher,
        apiBase: endpoints.githubApi, token: environment['GITHUB_TOKEN']);
    final repoFetcher = RepositoryAdvisoryFetcher(github);

    RepositoryPackageSource? repository;
    if (command.repoAdvisories && github.hasToken) {
      repository = RepositoryPackageSource(
          PubDevClient(fetcher, base: endpoints.pubDev), repoFetcher);
    } else if (command.repoAdvisories) {
      _warn(const NoGitHubToken());
    }

    return Checker(
      packages: FallbackSource(
        GitHubGlobalSource(github),
        OsvSource(fetcher, base: endpoints.osvApi),
        onFallback: (e) => _warn(FellBackToOsv(e)),
      ),
      repository: repository,
      sdkAdvisories: SdkAdvisorySource(repoFetcher),
      sdkDetector: SdkDetector(processRunner),
      onWarning: _warn,
    );
  }

  void _reportErrors(CheckResult result) {
    if (result.sdk case SdkFailed(:final error)) {
      err.writeln('dartvulncheck: SDK: ${error.message}');
    }
    for (final project in result.projects.whereType<FailedProject>()) {
      err.writeln('dartvulncheck: ${project.dir}: ${project.error.message}');
    }
  }

  void _warn(Warning w) =>
      err.writeln('dartvulncheck: warning: ${describeWarning(w)}');
}
