import 'package:args/args.dart';

import '../model/errors.dart';
import '../model/severity.dart';

class Options {
  final List<String> directories;
  final bool json;
  final Severity failOn;
  final Set<String> ignore;
  final bool strict;
  final bool repoAdvisories;
  final String? sdkVersion;
  final bool checkSdk;
  final bool transitive;
  final bool verbose;
  final bool help;
  final bool version;

  const Options({
    this.directories = const ['.'],
    this.json = false,
    this.failOn = Severity.low,
    this.ignore = const {},
    this.strict = false,
    this.repoAdvisories = true,
    this.sdkVersion,
    this.checkSdk = true,
    this.transitive = true,
    this.verbose = false,
    this.help = false,
    this.version = false,
  });

  static final ArgParser parser = ArgParser()
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

  static String get usage => '使い方: dartvulncheck [options] [directory ...]\n\n'
      'pubspec.lock と Flutter/Dart SDK を既知の脆弱性と照合します。\n'
      '終了コード: 0 問題なし / 1 実行できなかった / 3 脆弱性あり\n\n'
      '${parser.usage}';

  static Options parse(List<String> args) {
    final ArgResults r;
    try {
      r = parser.parse(args);
    } on FormatException catch (e) {
      throw UsageException(e.message);
    }
    final ignore = <String>{
      for (final v in r.multiOption('ignore'))
        for (final id in v.split(','))
          if (id.trim().isNotEmpty) id.trim().toUpperCase(),
    };
    return Options(
      directories: r.rest.isEmpty ? const ['.'] : r.rest,
      json: r.flag('json'),
      failOn: Severity.parse(r.option('fail-on')),
      ignore: ignore,
      strict: r.flag('strict'),
      repoAdvisories: r.flag('repo-advisories'),
      sdkVersion: r.option('sdk-version'),
      checkSdk: r.flag('sdk'),
      transitive: r.flag('transitive'),
      verbose: r.flag('verbose'),
      help: r.flag('help'),
      version: r.flag('version'),
    );
  }
}
