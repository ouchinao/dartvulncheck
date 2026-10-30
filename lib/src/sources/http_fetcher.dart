import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import '../model/errors.dart';
import '../version.dart';

// Environment variables, not CLI flags: only tests and GitHub Enterprise
// need them, so they stay out of --help.
class Endpoints {
  final Uri githubApi;
  final Uri osvApi;
  final Uri pubDev;

  const Endpoints({
    required this.githubApi,
    required this.osvApi,
    required this.pubDev,
  });

  static final defaults = Endpoints(
    githubApi: Uri.parse('https://api.github.com'),
    osvApi: Uri.parse('https://api.osv.dev'),
    pubDev: Uri.parse('https://pub.dev'),
  );

  factory Endpoints.fromEnvironment(Map<String, String> env) {
    Uri pick(String key, Uri fallback) {
      final v = env[key];
      return v == null || v.isEmpty ? fallback : Uri.parse(v);
    }

    return Endpoints(
      githubApi: pick('DARTVULNCHECK_GITHUB_API_URL', defaults.githubApi),
      osvApi: pick('DARTVULNCHECK_OSV_API_URL', defaults.osvApi),
      pubDev: pick('DARTVULNCHECK_PUB_URL', defaults.pubDev),
    );
  }
}

class HttpFetcher {
  final http.Client client;
  final Duration timeout;
  final Duration retryDelay;

  HttpFetcher(
    this.client, {
    this.timeout = const Duration(seconds: 30),
    this.retryDelay = const Duration(seconds: 1),
  });

  static const userAgent = 'dartvulncheck/$packageVersion';

  Future<http.Response> get(Uri url,
          {Map<String, String> headers = const {},
          required String sourceName}) =>
      _send(() => _request('GET', url, headers), sourceName);

  Future<http.Response> postJson(Uri url, Object body,
          {Map<String, String> headers = const {},
          required String sourceName}) =>
      _send(
          () => _request(
              'POST', url, {'Content-Type': 'application/json', ...headers},
              body: jsonEncode(body)),
          sourceName);

  static const _baseHeaders = {'User-Agent': userAgent};

  // Redirects are not followed: dart:io copies every header, Authorization
  // included, onto the redirected request whatever host it names, and none
  // of the APIs used here redirect a correct request.
  http.Request _request(String method, Uri url, Map<String, String> headers,
      {String? body}) {
    final request = http.Request(method, url)
      ..headers.addAll({..._baseHeaders, ...headers})
      ..followRedirects = false;
    if (body != null) request.body = body;
    return request;
  }

  // A new Request per attempt, not one reused: a sent request's body stream
  // is spent.
  Future<http.Response> _send(
      http.Request Function() build, String sourceName) async {
    Object? lastError;
    for (var attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) await Future<void>.delayed(retryDelay);
      try {
        final response = await _read(build(), sourceName).timeout(timeout);
        if (response.statusCode >= 500) {
          lastError = 'HTTP ${response.statusCode}';
          continue;
        }
        return response;
      } on TimeoutException {
        lastError = 'timed out after ${timeout.inSeconds} s';
      } on SocketException catch (e) {
        lastError = e.message;
      } on http.ClientException catch (e) {
        lastError = e.message;
      } on HandshakeException catch (e) {
        lastError = e.message;
      }
    }
    throw SourceUnreachable(sourceName, '$lastError');
  }

  Future<http.Response> _read(http.Request request, String sourceName) async {
    final streamed = await client.send(request);
    // The status code, not BaseResponse.isRedirect: that flag is left to the
    // client implementation, and a mock never sets it.
    if (const {301, 302, 303, 307, 308}.contains(streamed.statusCode)) {
      final to = Uri.tryParse(streamed.headers['location'] ?? '')?.host;
      throw UnexpectedResponse(
          sourceName,
          'redirected (HTTP ${streamed.statusCode}'
          '${to == null || to.isEmpty ? '' : ' to $to'}), '
          'which is not followed');
    }
    return http.Response.fromStream(streamed);
  }
}

Object? decodeJson(http.Response response, String sourceName) {
  try {
    return jsonDecode(utf8.decode(response.bodyBytes));
  } on FormatException {
    throw UnexpectedResponse(sourceName, 'the response is not JSON');
  }
}
