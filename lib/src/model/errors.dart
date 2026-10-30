// Only the Runner catches these. Layers do not turn errors into strings
// themselves, so all the wording lives in one place.
sealed class VulncheckException implements Exception {
  const VulncheckException();

  String get message;

  @override
  String toString() => message;
}

class UsageException extends VulncheckException {
  @override
  final String message;
  const UsageException(this.message);
}

class LockfileNotFound extends VulncheckException {
  final String path;
  const LockfileNotFound(this.path);

  @override
  String get message =>
      '$path がありません。先に `dart pub get`（Flutter なら `flutter pub get`）を実行してください';
}

class LockfileUnreadable extends VulncheckException {
  final String path;
  final int? line;
  final String reason;
  const LockfileUnreadable(this.path, this.reason, {this.line});

  @override
  String get message =>
      '${line == null ? path : '$path:$line'} を読めません: $reason';
}

class SourceUnreachable extends VulncheckException {
  final String source;
  final String reason;
  const SourceUnreachable(this.source, this.reason);

  @override
  String get message => '$source に接続できません: $reason';
}

class RateLimited extends VulncheckException {
  final String source;
  final bool hasToken;
  const RateLimited(this.source, {required this.hasToken});

  @override
  String get message => hasToken
      ? '$source のレート制限に達しました。しばらく待ってから再実行してください'
      : '$source のレート制限に達しました（未認証は 60 回/時）。'
          '環境変数 GITHUB_TOKEN を設定すると 1,000 回/時になります';
}
