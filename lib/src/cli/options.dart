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

  static String get usage => '使い方: dartvulncheck [options] [directory ...]\n\n'
      'pubspec.lock と Flutter/Dart SDK を既知の脆弱性と照合します。\n'
      '終了コード: 0 問題なし / 1 実行できなかった / 3 脆弱性あり\n\n'
      '${_parser.usage}';

  static final ArgParser _parser = ArgParser()
    ..addFlag('json', negatable: false, help: 'JSON で出力する')
    ..addOption('fail-on',
        valueHelp: 'level',
        allowed: Severity.failOnValues,
        defaultsTo: 'low',
        help: 'この深刻度以上があれば終了コード 3')
    ..addMultiOption('ignore',
        valueHelp: 'id',
        help: '無視するアドバイザリ ID（GHSA / CVE）。pubspec.yaml の '
            'ignored_advisories に加算')
    ..addFlag('strict', negatable: false, help: '範囲が読めず「要確認」になった件も脆弱性として数える')
    ..addFlag('repo-advisories',
        defaultsTo: true,
        help: 'リポジトリアドバイザリ（レビュー前の速報）も見る。'
            'GITHUB_TOKEN が無ければ自動で省く')
    ..addOption('sdk-version',
        valueHelp: 'ver', help: 'Flutter のバージョンを手で渡す（flutter が PATH に無い CI 向け）')
    ..addFlag('sdk', defaultsTo: true, help: 'Flutter/Dart SDK も照合する')
    ..addFlag('transitive', defaultsTo: true, help: '推移的依存も見る')
    ..addFlag('verbose',
        abbr: 'v', negatable: false, help: '照会した件数、無視した件数、照会できなかったパッケージを出す')
    ..addFlag('version', negatable: false, help: 'バージョンを出す')
    ..addFlag('help', abbr: 'h', negatable: false, help: '使い方を出す');
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
