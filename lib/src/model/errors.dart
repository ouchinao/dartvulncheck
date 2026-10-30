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
      '$path not found. Run `dart pub get` (or `flutter pub get`) first';
}

class LockfileUnreadable extends VulncheckException {
  final String path;
  final int? line;
  final String reason;
  const LockfileUnreadable(this.path, this.reason, {this.line});

  @override
  String get message =>
      'cannot read ${line == null ? path : '$path:$line'}: $reason';
}

class SourceUnreachable extends VulncheckException {
  final String source;
  final String reason;
  const SourceUnreachable(this.source, this.reason);

  @override
  String get message => 'cannot reach $source: $reason';
}

class RateLimited extends VulncheckException {
  final String source;
  final bool hasToken;
  const RateLimited(this.source, {required this.hasToken});

  @override
  String get message => hasToken
      ? '$source rate limit reached. Wait a while and run again'
      : '$source rate limit reached (60 requests/hour without a token). '
          'Set GITHUB_TOKEN to raise it to 1,000/hour';
}
