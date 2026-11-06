import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../model/errors.dart';
import '../version.dart';

// Environment variables, not CLI flags: only tests and GitHub Enterprise
// need them, so they stay out of --help.
class Endpoints {
  final Uri githubApi;
  final Uri osvApi;
  final Uri pubDev;

  // Not forgotten once picked: the run says on stderr where its requests
  // went, and a reader of a CI log should not have to guess.
  final Map<String, Uri> overrides;

  const Endpoints({
    required this.githubApi,
    required this.osvApi,
    required this.pubDev,
    this.overrides = const {},
  });

  static final defaults = Endpoints(
    githubApi: Uri.parse('https://api.github.com'),
    osvApi: Uri.parse('https://api.osv.dev'),
    pubDev: Uri.parse('https://pub.dev'),
  );

  factory Endpoints.fromEnvironment(Map<String, String> env) {
    final overrides = <String, Uri>{};
    Uri pick(String key, Uri fallback) {
      final v = env[key];
      if (v == null || v.isEmpty) return fallback;
      final url = Uri.tryParse(v);
      if (url == null || url.host.isEmpty) {
        throw InvalidEndpoint(key, v, 'not a URL');
      }
      // Plain http only to this machine: anywhere else the token and the
      // answers would travel in the clear.
      if (url.scheme != 'https' && !(url.scheme == 'http' && _loopback(url))) {
        throw InvalidEndpoint(
            key, v, 'not https (http is allowed for localhost only)');
      }
      overrides[key] = url;
      return url;
    }

    return Endpoints(
      githubApi: pick('DARTVULNCHECK_GITHUB_API_URL', defaults.githubApi),
      osvApi: pick('DARTVULNCHECK_OSV_API_URL', defaults.osvApi),
      pubDev: pick('DARTVULNCHECK_PUB_URL', defaults.pubDev),
      overrides: overrides,
    );
  }

  static bool _loopback(Uri url) =>
      url.host == 'localhost' || url.host == '127.0.0.1' || url.host == '::1';
}

class HttpFetcher {
  final http.Client client;
  final Duration timeout;
  final Duration retryDelay;
  final int maxBodyBytes;

  HttpFetcher(
    this.client, {
    this.timeout = const Duration(seconds: 30),
    this.retryDelay = const Duration(seconds: 1),
    this.maxBodyBytes = 16 << 20,
  });

  static const userAgent = 'dartvulncheck/$packageVersion';

  // 3, not dart:io's 5: GitHub needs one hop for a renamed repository, and
  // every hop a chain may take is a request the rate limit pays for.
  static const maxRedirects = 3;

  Future<http.Response> get(Uri url,
          {Map<String, String> headers = const {},
          required String sourceName}) =>
      _send('GET', url, headers, sourceName: sourceName);

  Future<http.Response> postJson(Uri url, Object body,
          {Map<String, String> headers = const {},
          required String sourceName}) =>
      _send('POST', url, {'Content-Type': 'application/json', ...headers},
          body: jsonEncode(body), sourceName: sourceName);

  static const _baseHeaders = {'User-Agent': userAgent};

  // Redirects are followed by the loop in _read, not by dart:io: a GET only,
  // to the same origin only (scheme, host and port of the URL the request
  // was sent to, and no credentials in the target), for at most maxRedirects
  // hops, re-sending the same headers. GitHub does redirect a correct
  // request: a renamed or transferred repository answers
  // /repos/{owner}/{repo}/... with a 301 to /repositories/{id}/... on the
  // same host, and refusing every redirect lost exactly those advisories
  // (#10).
  //
  // Not followRedirects = true: dart:io follows across origins, so a host
  // the configuration does not name could answer the query, and on Dart 3.5
  // it keeps Authorization on a hop to any subdomain of the host (newer SDKs
  // keep it for the same origin only); it also replaces the User-Agent on
  // the hop, and turns a loop or an over-long chain into a ClientException
  // that _send would retry and report as unreachable. And MockClient never
  // follows, so only a loop of our own is testable offline.
  //
  // Not for a POST: 301, 302 and 303 change the method, a 307 or 308 would
  // re-send the query body to a URL the server chose, and no API used here
  // redirects a POST.
  http.Request _request(String method, Uri url, Map<String, String> headers,
      {String? body}) {
    final request = http.Request(method, url)
      ..headers.addAll({..._baseHeaders, ...headers})
      ..followRedirects = false;
    if (body != null) request.body = body;
    return request;
  }

  // Method, URL and headers, not a built Request: a sent request's body
  // stream is spent, so each attempt and each redirect hop builds its own.
  // One timeout covers a whole chain, and a 5xx on any hop retries the
  // chain once from the original URL.
  Future<http.Response> _send(
      String method, Uri url, Map<String, String> headers,
      {String? body, required String sourceName}) async {
    Object? lastError;
    for (var attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) await Future<void>.delayed(retryDelay);
      try {
        final response = await _read(method, url, headers,
                body: body, sourceName: sourceName)
            .timeout(timeout);
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

  // The redirect check reads the status code, not BaseResponse.isRedirect:
  // that flag is left to the client implementation, and a mock never sets
  // it.
  Future<http.Response> _read(
      String method, Uri url, Map<String, String> headers,
      {String? body, required String sourceName}) async {
    final original = url;
    var hopUrl = url;
    for (var hops = 0;; hops++) {
      final request = _request(method, hopUrl, headers, body: body);
      final streamed = await client.send(request);
      if (const {301, 302, 303, 307, 308}.contains(streamed.statusCode)) {
        // Drained under the same cap, not skipped: nothing in a 3xx body is
        // wanted, but a redirect must not be the one response the cap does
        // not cover (D2).
        await _bodyUnderCap(streamed, sourceName);
        hopUrl = _redirectTarget(
            original: original,
            from: hopUrl,
            response: streamed,
            method: method,
            hops: hops,
            sourceName: sourceName);
        continue;
      }
      final bytes = await _bodyUnderCap(streamed, sourceName);
      // The hop that answered, not the request _send was given: it is how a
      // caller learns where a followed redirect led.
      return http.Response.bytes(bytes, streamed.statusCode,
          headers: streamed.headers,
          request: request,
          reasonPhrase: streamed.reasonPhrase);
    }
  }

  // Read with a cap, not buffered whole by the client: a response of any
  // size would otherwise sit in memory before anything looked at it.
  Future<Uint8List> _bodyUnderCap(
      http.StreamedResponse streamed, String sourceName) async {
    final bytes = BytesBuilder(copy: false);
    await for (final chunk in streamed.stream) {
      bytes.add(chunk);
      if (bytes.length > maxBodyBytes) {
        throw UnexpectedResponse(
            sourceName, 'the response is larger than $maxBodyBytes bytes');
      }
    }
    return bytes.takeBytes();
  }

  // Judged against the ORIGINAL request URL, not only the previous hop: the
  // two are equivalent while every hop passes, and the original is the
  // property the threat model promises (T3, I1).
  Uri _redirectTarget({
    required Uri original,
    required Uri from,
    required http.StreamedResponse response,
    required String method,
    required int hops,
    required String sourceName,
  }) {
    final code = response.statusCode;
    final header = response.headers['location'];
    final location =
        header == null || header.isEmpty ? null : Uri.tryParse(header);
    if (method != 'GET') {
      final to =
          location == null ? '' : ' to ${_originOf(from.resolveUri(location))}';
      throw UnexpectedResponse(sourceName,
          'redirected (HTTP $code$to), which is not followed for a $method');
    }
    if (hops == maxRedirects) {
      throw UnexpectedResponse(sourceName, 'more than $maxRedirects redirects');
    }
    if (location == null) {
      throw UnexpectedResponse(
          sourceName, 'redirected (HTTP $code) without a Location');
    }
    final target = from.resolveUri(location);
    // Refused, not stripped and followed: dart:io would turn the userinfo
    // into Basic credentials on the hop, and no API used here names any.
    if (target.userInfo.isNotEmpty) {
      throw UnexpectedResponse(
          sourceName,
          'redirected (HTTP $code to a URL with credentials in it), '
          'which is not followed');
    }
    if (!sameOrigin(original, target)) {
      throw UnexpectedResponse(
          sourceName,
          'redirected (HTTP $code to ${_originOf(target)}), '
          'which is not followed away from ${_originOf(original)}');
    }
    return target;
  }
}

// Compared as Uri gives them, not normalised here: Uri already lowercases
// scheme and host and drops a default port, so https://api.github.com:443
// equals https://api.github.com.
bool sameOrigin(Uri a, Uri b) =>
    a.scheme == b.scheme && a.host == b.host && a.port == b.port;

// Not Uri.origin: it throws for a scheme other than http(s) and for an empty
// host, and this is called while building an error message.
String _originOf(Uri url) =>
    '${url.scheme}://${url.host}${url.hasPort ? ':${url.port}' : ''}';

Object? decodeJson(http.Response response, String sourceName) {
  try {
    return jsonDecode(utf8.decode(response.bodyBytes));
  } on FormatException {
    throw UnexpectedResponse(sourceName, 'the response is not JSON');
  }
}
