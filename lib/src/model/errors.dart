// Typed exceptions, not error strings: the layers that catch them (Checker,
// the repository stage) must tell the cases apart, and the wording is decided
// only where they are shown.
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

// Not folded into RateLimited: a 401 or a 403 without rate-limit signs
// means the token is bad or lacks access, and telling the user to wait
// would not help.
class AccessDenied extends VulncheckException {
  final String source;
  final int statusCode;
  const AccessDenied(this.source, this.statusCode);

  @override
  String get message => statusCode == 401
      ? '$source rejected the token (HTTP 401). Check GITHUB_TOKEN'
      : '$source refused access (HTTP $statusCode). '
          'Check GITHUB_TOKEN and what it is allowed to read';
}

// Not SourceUnreachable: the server answered, so retrying the same request
// is not the fix, though falling back to another source still is.
class UnexpectedResponse extends VulncheckException {
  final String source;
  final String reason;
  const UnexpectedResponse(this.source, this.reason);

  @override
  String get message => 'unexpected response from $source: $reason';
}
