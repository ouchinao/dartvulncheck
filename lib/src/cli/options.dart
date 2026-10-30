import 'package:args/args.dart';

import '../check/checker.dart';
import '../model/errors.dart';
import '../model/severity.dart';

enum OutputFormat { text, json }

// A sealed command, not `help` / `version` bools next to the check options:
// with bools, "--help --json" is a state that means nothing.
sealed class Command {
  const Command();

  static Command parse(List<String> args) {
    final ArgResults r;
    try {
      r = _parser.parse(args);
    } on FormatException catch (e) {
      throw UsageException(e.message);
    }
    if (r.flag('help')) return const ShowHelp();
    if (r.flag('version')) return const ShowVersion();
    return RunCheck(
      check: CheckOptions(
        directories: r.rest.isEmpty ? const ['.'] : r.rest,
        ignore: {
          for (final v in r.multiOption('ignore'))
            for (final id in v.split(','))
              if (id.trim().isNotEmpty) id.trim().toUpperCase(),
        },
        sdk: r.flag('sdk')
            ? SdkCheck(flutterVersion: r.option('sdk-version'))
            : null,
        transitive: r.flag('transitive'),
      ),
      format: r.flag('json') ? OutputFormat.json : OutputFormat.text,
      failOn: Severity.parse(r.option('fail-on')),
      strict: r.flag('strict'),
      repoAdvisories: r.flag('repo-advisories'),
      verbose: r.flag('verbose'),
    );
  }

  static String get usage =>
      'Usage: dartvulncheck [options] [directory ...]\n\n'
      'Checks pubspec.lock and the Flutter/Dart SDK against known '
      'vulnerabilities.\n'
      'Exit codes: 0 no problems / 1 could not check / 3 vulnerabilities found'
      '\n\n'
      '${_parser.usage}';

  static final ArgParser _parser = ArgParser()
    ..addFlag('json', negatable: false, help: 'Print JSON.')
    ..addOption('fail-on',
        valueHelp: 'level',
        allowed: [
          for (final s in Severity.values)
            if (s != Severity.unknown) s.name,
        ],
        defaultsTo: 'low',
        help: 'Exit 3 if anything at this severity or above is found.')
    ..addMultiOption('ignore',
        valueHelp: 'id',
        help: 'Advisory ID to ignore (GHSA or CVE). Added to '
            'ignored_advisories in pubspec.yaml.')
    ..addFlag('strict',
        negatable: false,
        help: 'Also count unverified advisories (affected range unreadable).')
    ..addFlag('repo-advisories',
        defaultsTo: true,
        help: 'Also read repository advisories (published before GitHub '
            'review). Skipped without GITHUB_TOKEN.')
    ..addOption('sdk-version',
        valueHelp: 'ver',
        help: 'Flutter version to check, for CI without flutter on PATH.')
    ..addFlag('sdk', defaultsTo: true, help: 'Also check the Flutter/Dart SDK.')
    ..addFlag('transitive',
        defaultsTo: true, help: 'Also check transitive dependencies.')
    ..addFlag('verbose',
        abbr: 'v',
        negatable: false,
        help:
            'Show queried and ignored counts, and packages that could not be looked up.')
    ..addFlag('version', negatable: false, help: 'Print the version.')
    ..addFlag('help', abbr: 'h', negatable: false, help: 'Print this usage.');
}

class ShowHelp extends Command {
  const ShowHelp();
}

class ShowVersion extends Command {
  const ShowVersion();
}

class RunCheck extends Command {
  final CheckOptions check;
  final OutputFormat format;
  final Severity failOn;
  final bool strict;
  final bool repoAdvisories;
  final bool verbose;

  const RunCheck({
    required this.check,
    this.format = OutputFormat.text,
    this.failOn = Severity.low,
    this.strict = false,
    this.repoAdvisories = true,
    this.verbose = false,
  });
}
