import '../model/errors.dart';
import 'http_fetcher.dart';

class PubDevClient {
  final HttpFetcher fetcher;
  final Uri base;
  PubDevClient(this.fetcher, {required this.base});

  static const sourceName = 'pub.dev';

  Future<String?> repositoryUrl(String package) async {
    final url = base.replace(
        path:
            '${_trim(base.path)}/api/packages/${Uri.encodeComponent(package)}');
    final response = await fetcher.get(url,
        headers: const {'Accept': 'application/json'}, sourceName: sourceName);
    // Only 404 is folded into null: any other error would then read as "no
    // repository", hiding a rate-limited pub.dev.
    if (response.statusCode == 404) return null;
    if (response.statusCode != 200) {
      throw UnexpectedResponse(sourceName, 'HTTP ${response.statusCode}');
    }
    final json = decodeJson(response, sourceName);
    if (json is! Map) return null;
    final latest = json['latest'];
    final pubspec = latest is Map ? latest['pubspec'] : null;
    if (pubspec is! Map) return null;
    for (final key in ['repository', 'homepage']) {
      final v = pubspec[key];
      if (v is String && v.trim().isNotEmpty) return v.trim();
    }
    return null;
  }

  static String _trim(String path) =>
      path.endsWith('/') ? path.substring(0, path.length - 1) : path;
}

// Only the first two path segments, not the whole path: monorepos such as
// flutter/packages publish URLs with sub-paths.
String? githubRepoFromUrl(String url) {
  var text = url.trim();
  final ssh = RegExp(r'^git@github\.com:(.+)$').firstMatch(text);
  if (ssh != null) text = 'https://github.com/${ssh.group(1)}';
  if (!text.contains('://')) text = 'https://$text';
  final uri = Uri.tryParse(text);
  if (uri == null) return null;
  final host = uri.host.toLowerCase();
  if (host != 'github.com' && host != 'www.github.com') return null;
  final segments = uri.pathSegments.where((s) => s.isNotEmpty).toList();
  if (segments.length < 2) return null;
  var repo = segments[1];
  if (repo.endsWith('.git')) repo = repo.substring(0, repo.length - 4);
  // Checked against GitHub's own name rules, not only split: the two
  // segments become part of an API path, and pub.dev lets a package point
  // at any URL, so "a%2F..%2Fx" would otherwise walk into another endpoint.
  if (!_githubName.hasMatch(segments[0]) || !_githubName.hasMatch(repo)) {
    return null;
  }
  return '${segments[0]}/$repo';
}

final _githubName = RegExp(r'^(?!\.\.?$)[A-Za-z0-9_.-]+$');
