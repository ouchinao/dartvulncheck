import 'package:http/http.dart' as http;

import '../model/errors.dart';
import 'http_fetcher.dart';

class GitHubClient {
  final HttpFetcher fetcher;
  final Uri apiBase;
  final String? token;

  GitHubClient(this.fetcher, {required this.apiBase, this.token});

  static const sourceName = 'GitHub';

  bool get hasToken => token != null && token!.isNotEmpty;

  Map<String, String> get _headers => {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        if (hasToken) 'Authorization': 'Bearer $token',
      };

  Uri endpoint(String path, [Map<String, String>? query]) {
    final basePath = apiBase.path.endsWith('/')
        ? apiBase.path.substring(0, apiBase.path.length - 1)
        : apiBase.path;
    return apiBase.replace(
        path: '$basePath$path',
        queryParameters: query == null || query.isEmpty ? null : query);
  }

  static const maxPages = 50;

  Future<List<Object?>?> getAllPages(Uri first) async {
    final items = <Object?>[];
    Uri? url = first;
    var pages = 0;
    while (url != null) {
      if (++pages > maxPages) {
        throw UnexpectedResponse(sourceName, 'more than $maxPages pages');
      }
      final response =
          await fetcher.get(url, headers: _headers, sourceName: sourceName);
      if (response.statusCode == 404) return null;
      _throwIfRateLimited(response);
      if (response.statusCode == 401 || response.statusCode == 403) {
        throw AccessDenied(sourceName, response.statusCode);
      }
      if (response.statusCode != 200) {
        throw UnexpectedResponse(sourceName, 'HTTP ${response.statusCode}');
      }
      final body = decodeJson(response, sourceName);
      if (body is! List) {
        throw const UnexpectedResponse(
            sourceName, 'the response is not a list');
      }
      items.addAll(body);
      url = nextPage(response.headers['link']);
      // The token goes only where apiBase points. A `next` link to another
      // origin is not followed, however it got into the header.
      if (url != null && !_sameOrigin(url)) {
        throw UnexpectedResponse(
            sourceName, 'a page link points away from ${apiBase.host}');
      }
    }
    return items;
  }

  bool _sameOrigin(Uri url) =>
      url.scheme == apiBase.scheme &&
      url.host == apiBase.host &&
      url.port == apiBase.port;

  void _throwIfRateLimited(http.Response response) {
    final status = response.statusCode;
    final remaining = response.headers['x-ratelimit-remaining'];
    final looksLimited = status == 429 ||
        (status == 403 &&
            (remaining == '0' ||
                response.body.toLowerCase().contains('rate limit')));
    if (looksLimited) throw RateLimited(sourceName, hasToken: hasToken);
  }

  static Uri? nextPage(String? link) {
    if (link == null) return null;
    for (final part in link.split(',')) {
      final m = RegExp(r'<([^>]+)>\s*;\s*rel="?next"?').firstMatch(part);
      if (m != null) return Uri.parse(m.group(1)!);
    }
    return null;
  }
}
