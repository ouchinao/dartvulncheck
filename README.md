# dartvulncheck

govulncheck の Dart/Flutter 版。`pubspec.lock` と、ビルドに使う Flutter/Dart SDK を既知の脆弱性と照合し、見つかったら CI を落とす純 Dart のコマンドラインツール。

`flutter pub get` の警告との違い:

| `flutter pub get` の警告 | dartvulncheck |
| --- | --- |
| 表示だけで CI は通る | 終了コードで CI を落とせる |
| pub パッケージだけ | Flutter/Dart SDK 本体の脆弱性も見る |
| GitHub のレビュー後にしか載らない | メンテナが公開した時点のリポジトリアドバイザリも見る |
| 人が読む文だけ | `--json` で機械が読める |

## インストール

```sh
dart pub global activate --source git https://github.com/ouchinao/dartvulncheck
```

## 使い方

```sh
dartvulncheck                         # カレントディレクトリ
dartvulncheck app packages/zeibun_core  # モノレポの複数ディレクトリ
```

`pubspec.lock` を読むので、先に `dart pub get`（または `flutter pub get`）が済んでいる必要があります。

| オプション | 意味 | 既定 |
| --- | --- | --- |
| `--json` | JSON で出力する | テキスト |
| `--fail-on <level>` | この深刻度以上があれば終了コード 3（`low` / `moderate` / `high` / `critical`） | `low` |
| `--ignore <id>` | 無視するアドバイザリ ID（GHSA / CVE）。複数可。`pubspec.yaml` の `ignored_advisories` に加算 | なし |
| `--strict` | 範囲が読めず「要確認」になった件も脆弱性として数える | 数えない |
| `--no-repo-advisories` | リポジトリアドバイザリ（速報）を省く | `GITHUB_TOKEN` が無ければ自動で省く |
| `--sdk-version <ver>` | Flutter のバージョンを手で渡す | `.fvmrc` → `flutter --version` → `dart --version` |
| `--no-sdk` | SDK の照合を省く | 照合する |
| `--no-transitive` | 推移的依存を見ない | 見る |
| `--verbose` | 照会した件数、無視した件数、照会できなかったパッケージを出す | 出さない |

### 終了コード

| コード | 意味 |
| --- | --- |
| 0 | 問題なし（無視した件だけの場合も 0） |
| 1 | 実行できなかった（`pubspec.lock` が無い、ネットワーク失敗、引数の誤り） |
| 3 | 脆弱性が見つかった（govulncheck と同じ値） |

### 無視する

`pubspec.yaml` に pub 公式のキーで書きます。`flutter pub get` の警告も同じリストで止まります。

```yaml
ignored_advisories:
  - GHSA-xxxx-xxxx-xxxx  # iOS だけの問題。Android アプリなので該当しない
```

## GitHub Actions

```yaml
vulncheck:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: subosito/flutter-action@v2
      with:
        channel: stable
    - run: dart pub global activate --source git https://github.com/ouchinao/dartvulncheck
    - run: dart pub global run dartvulncheck app packages/zeibun_core
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- `pub get` は要りません。読むのはコミットされた `pubspec.lock` だけです。
- `GITHUB_TOKEN` はリポジトリアドバイザリの段に数十回の問い合わせが要るため（未認証は 60 回/時）。Actions の既定トークンで足ります。
- PR 毎に加えて `schedule` で週 1 回回すのがおすすめです。コードが変わらなくてもアドバイザリは増えます。
- Dependabot アラートの代わりではなく併用です。

## 取得元

| 段 | 元 | 対象 |
| --- | --- | --- |
| 主 | GitHub Advisory Database（`GET /advisories?ecosystem=pub&affects=…`） | hosted パッケージ |
| 速報 | リポジトリアドバイザリ（`GET /repos/{owner}/{repo}/security-advisories`） | GitHub にリポジトリがあるパッケージと、`dart-lang/sdk`・`flutter/flutter` |
| 予備 | OSV.dev（`POST /v1/querybatch`） | GitHub が落ちているときの切り替え先 |

接続先は環境変数 `DARTVULNCHECK_GITHUB_API_URL` / `DARTVULNCHECK_OSV_API_URL` / `DARTVULNCHECK_PUB_URL` で差し替えられます（テストや GitHub Enterprise 向け）。

## 開発

```sh
dart pub get
dart analyze
dart test
UPDATE_GOLDENS=1 dart test test/report_test.dart  # 出力の形を意図して変えたとき
```

構成は `lib/src/` の下に `lockfile/`（入力）→ `sources/`（照会）→ `match/`（照合）→ `report/`（報告）、それらを順に呼ぶ `check/`、引数と終了コードの `cli/`、共有の型は `model/`。通信するのは `sources/` だけなので、テストは全てオフラインで動きます。
