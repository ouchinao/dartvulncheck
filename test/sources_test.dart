import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:pub_semver/pub_semver.dart';
import 'package:test/test.dart';

import 'helpers.dart';

PackageRef pkg(String name, String version) => PackageRef(
    name: name,
    version: Version.parse(version),
    source: PackageSource.hosted,
    dependency: Dependency.directMain,
    hostedUrl: Uri.parse('https://pub.dev'));

HttpFetcher fetcherFor(http.Client c) =>
    HttpFetcher(c, retryDelay: Duration.zero);

GitHubClient githubFor(FakeApi api, {String? token = 'tkn'}) =>
    GitHubClient(fetcherFor(api.client),
        apiBase: Endpoints.defaults.githubApi, token: token);

void main() {
  group('GitHub global', () {
    test('sends affects=name@version and the required headers', () async {
      final api = FakeApi();
      await GitHubGlobalSource(githubFor(api))
          .query([pkg('dio', '4.0.6'), pkg('http', '0.13.2')]);
      final r = api.requests.single;
      expect(r.url.path, '/advisories');
      expect(r.url.queryParameters['ecosystem'], 'pub');
      expect(r.url.queryParameters['affects'], 'dio@4.0.6,http@0.13.2');
      expect(r.headers['Accept'], 'application/vnd.github+json');
      expect(r.headers['X-GitHub-Api-Version'], isNotNull);
      expect(r.headers['Authorization'], 'Bearer tkn');
      expect(r.headers['User-Agent'], 'dartvulncheck/$packageVersion');
    });

    test('splits more than chunkSize packages into several requests', () async {
      final api = FakeApi();
      await GitHubGlobalSource(githubFor(api), chunkSize: 2)
          .query([pkg('a', '1.0.0'), pkg('b', '1.0.0'), pkg('c', '1.0.0')]);
      expect(api.requests.map((r) => r.url.queryParameters['affects']),
          ['a@1.0.0,b@1.0.0', 'c@1.0.0']);
    });

    test('parses id, aliases, severity (medium → moderate) and ranges',
        () async {
      final api = FakeApi();
      final advisories = await GitHubGlobalSource(githubFor(api))
          .query([pkg('http', '0.13.2')]);
      final http = advisories.firstWhere((a) => a.id == 'GHSA-4rgh-jx4f-qfcq');
      expect(http.aliases, ['CVE-2020-35669']);
      expect(http.severity, Severity.moderate);
      expect(http.affected.first.ranges, ['< 0.13.3']);
      expect(http.affected.first.patched, '0.13.3');
      expect(http.origin, AdvisoryOrigin.global);
    });

    test('follows Link rel="next"', () async {
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        if (req.url.queryParameters['after'] == null) {
          return http.Response('[]', 200, headers: {
            'link': '<https://api.github.com/advisories?after=X>; rel="next", '
                '<https://api.github.com/advisories>; rel="first"',
          });
        }
        return http.Response('[]', 200);
      });
      await GitHubGlobalSource(GitHubClient(fetcherFor(client),
              apiBase: Endpoints.defaults.githubApi))
          .query([pkg('dio', '1.0.0')]);
      expect(calls, 2);
    });

    test('403 is rate limiting and mentions GITHUB_TOKEN without a token',
        () async {
      final api = FakeApi()
        ..githubStatus = 403
        ..githubHeaders = {'x-ratelimit-remaining': '0'};
      expect(
        GitHubGlobalSource(githubFor(api, token: null))
            .query([pkg('dio', '1.0.0')]),
        throwsA(isA<RateLimited>()
            .having((e) => e.message, 'message', contains('GITHUB_TOKEN'))),
      );
    });

    test('5xx is retried once, then unreachable', () async {
      final api = FakeApi()..githubStatus = 502;
      await expectLater(
        GitHubGlobalSource(githubFor(api)).query([pkg('dio', '1.0.0')]),
        throwsA(isA<SourceUnreachable>()),
      );
      expect(api.requests, hasLength(2));
    });
  });

  group('where the token may go', () {
    test('a page link to another origin is not followed', () async {
      final seen = <Uri>[];
      final client = MockClient((req) async {
        seen.add(req.url);
        return http.Response('[]', 200, headers: {
          'link': '<https://evil.example/advisories?page=2>; rel="next"',
        });
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi, token: 'tkn'));
      await expectLater(source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>()));
      expect(seen.map((u) => u.host), ['api.github.com']);
    });

    test(
        'a same-origin 301 is followed with the same headers, and paging '
        'continues from the Link header of the page it leads to', () async {
      final seen = <http.Request>[];
      final client = MockClient((req) async {
        seen.add(req);
        if (req.url.path == '/repos/old/name/security-advisories') {
          return http.Response('', 301, headers: {
            'location': 'https://api.github.com/repositories/1/'
                'security-advisories?state=published&per_page=100',
          });
        }
        if (req.url.queryParameters['page'] == null) {
          return http.Response('[]', 200, headers: {
            'link': '<https://api.github.com/repositories/1/'
                'security-advisories?state=published&per_page=100&page=2>; '
                'rel="next"',
          });
        }
        return http.Response('[]', 200);
      });
      final github = GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi, token: 'tkn');
      final items = await github.getAllPages(github.endpoint(
          '/repos/old/name/security-advisories',
          {'state': 'published', 'per_page': '100'}));
      expect(items, isNotNull);
      expect(seen.map((r) => r.url.path), [
        '/repos/old/name/security-advisories',
        '/repositories/1/security-advisories',
        '/repositories/1/security-advisories',
      ]);
      expect(seen.last.url.queryParameters['page'], '2');
      for (final r in seen) {
        expect(r.url.host, 'api.github.com');
        expect(r.headers['Authorization'], 'Bearer tkn');
        expect(r.headers['Accept'], 'application/vnd.github+json');
        expect(r.headers['X-GitHub-Api-Version'], isNotNull);
        expect(r.headers['User-Agent'], 'dartvulncheck/$packageVersion');
      }
    });

    test(
        'a relative Location is resolved against the URL the request went to '
        'and followed', () async {
      final seen = <Uri>[];
      final client = MockClient((req) async {
        seen.add(req.url);
        if (req.url.path.startsWith('/repos/')) {
          return http.Response('', 301, headers: {
            'location': '/repositories/1/security-advisories?state=published',
          });
        }
        return http.Response('[]', 200);
      });
      final github = GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi, token: 'tkn');
      await github
          .getAllPages(github.endpoint('/repos/old/name/security-advisories'));
      expect(seen, hasLength(2));
      expect(seen.last.toString(),
          'https://api.github.com/repositories/1/security-advisories?state=published');
    });

    test(
        'a redirect to another origin is not followed, and the message names '
        'both origins', () async {
      final seen = <Uri>[];
      final client = MockClient((req) async {
        seen.add(req.url);
        return http.Response('', 302,
            headers: {'location': 'https://evil.example/'});
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi, token: 'tkn'));
      await expectLater(
          source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>().having(
              (e) => e.message,
              'message',
              allOf(contains('redirected (HTTP 302 to https://evil.example)'),
                  contains('api.github.com')))));
      expect(seen, hasLength(1));
    });

    test(
        'a redirect to the same host on another scheme or port is not followed',
        () async {
      for (final location in [
        'http://api.github.com/advisories',
        'https://api.github.com:8443/advisories',
      ]) {
        final seen = <Uri>[];
        final client = MockClient((req) async {
          seen.add(req.url);
          return http.Response('', 301, headers: {'location': location});
        });
        final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
            apiBase: Endpoints.defaults.githubApi, token: 'tkn'));
        await expectLater(source.query([pkg('dio', '1.0.0')]),
            throwsA(isA<UnexpectedResponse>()),
            reason: location);
        expect(seen, hasLength(1), reason: location);
      }
    });

    test('a redirect to a URL with credentials in it is not followed',
        () async {
      final seen = <Uri>[];
      final client = MockClient((req) async {
        seen.add(req.url);
        return http.Response('', 301,
            headers: {'location': 'https://u:p@api.github.com/advisories'});
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi, token: 'tkn'));
      await expectLater(
          source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>().having((e) => e.message, 'message',
              allOf(contains('credentials'), isNot(contains('u:p'))))));
      expect(seen, hasLength(1));
    });

    test(
        'a redirect to another origin on the second hop is refused after a '
        'same-origin first hop', () async {
      final seen = <Uri>[];
      final client = MockClient((req) async {
        seen.add(req.url);
        return http.Response('', 301, headers: {
          'location': req.url.path == '/advisories'
              ? 'https://api.github.com/moved'
              : 'https://evil.example/advisories',
        });
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi, token: 'tkn'));
      await expectLater(source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>()));
      expect(seen.map((u) => u.host), ['api.github.com', 'api.github.com']);
    });

    test(
        'after a followed redirect, a page link away from the origin is still '
        'refused', () async {
      final seen = <Uri>[];
      final client = MockClient((req) async {
        seen.add(req.url);
        if (req.url.path == '/advisories') {
          return http.Response('', 301,
              headers: {'location': 'https://api.github.com/moved'});
        }
        return http.Response('[]', 200, headers: {
          'link': '<https://evil.example/moved?page=2>; rel="next"',
        });
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi, token: 'tkn'));
      await expectLater(
          source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>().having((e) => e.message, 'message',
              contains('a page link points away from api.github.com'))));
      expect(seen.map((u) => u.host).toSet(), {'api.github.com'});
    });

    test('an endpoint override must be https, except on localhost', () {
      expect(
          () => Endpoints.fromEnvironment(
              {'DARTVULNCHECK_GITHUB_API_URL': 'http://ghe.example/api/v3'}),
          throwsA(isA<InvalidEndpoint>()));
      expect(
          () => Endpoints.fromEnvironment(
              {'DARTVULNCHECK_GITHUB_API_URL': 'not a url'}),
          throwsA(isA<InvalidEndpoint>()));
      final local = Endpoints.fromEnvironment(
          {'DARTVULNCHECK_PUB_URL': 'http://127.0.0.1:8080/pub'});
      expect(local.pubDev.port, 8080);
      expect(local.overrides.keys, ['DARTVULNCHECK_PUB_URL']);
      expect(Endpoints.fromEnvironment(const {}).overrides, isEmpty);
    });
  });

  group('bounded responses', () {
    test('pagination stops after the page limit', () async {
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        return http.Response('[]', 200, headers: {
          'link': '<https://api.github.com/advisories?page=${calls + 1}>; '
              'rel="next"',
        });
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi));
      await expectLater(source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>()));
      expect(calls, GitHubClient.maxPages);
    });

    test('OSV paging stops after the page limit', () async {
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        return http.Response(
            '{"results":[{"vulns":[],"next_page_token":"again"}]}', 200);
      });
      await expectLater(
          OsvSource(fetcherFor(client), base: Endpoints.defaults.osvApi)
              .query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>()));
      expect(calls, OsvSource.maxPages);
    });

    test('a body over the size limit is refused', () async {
      final client =
          MockClient((req) async => http.Response('[${'1,' * 200}1]', 200));
      final fetcher = HttpFetcher(client, maxBodyBytes: 100);
      final source = GitHubGlobalSource(
          GitHubClient(fetcher, apiBase: Endpoints.defaults.githubApi));
      await expectLater(source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>()));
    });

    test('a redirect chain stops after the hop limit', () async {
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        return http.Response('', 301,
            headers: {'location': 'https://api.github.com/hop$calls'});
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi));
      await expectLater(
          source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>().having(
              (e) => e.message, 'message', contains('more than 3 redirects'))));
      expect(calls, HttpFetcher.maxRedirects + 1);
    });

    test('a redirect loop is an unexpected response, not an unreachable source',
        () async {
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        return http.Response('', 302, headers: {
          'location': req.url.path == '/advisories'
              ? 'https://api.github.com/b'
              : 'https://api.github.com/advisories',
        });
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi));
      await expectLater(source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>()));
      // Not retried: maxRedirects + 1 requests, not twice that.
      expect(calls, HttpFetcher.maxRedirects + 1);
    });

    test("a redirect's body is discarded under the size cap", () async {
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        return http.Response('x' * 200, 301,
            headers: {'location': 'https://api.github.com/moved'});
      });
      final fetcher =
          HttpFetcher(client, maxBodyBytes: 100, retryDelay: Duration.zero);
      final source = GitHubGlobalSource(
          GitHubClient(fetcher, apiBase: Endpoints.defaults.githubApi));
      await expectLater(
          source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>()
              .having((e) => e.message, 'message', contains('larger than'))));
      expect(calls, 1);
    });

    test(
        'a redirect of a POST is not followed, and the message says it is a POST',
        () async {
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        return http.Response('', 307,
            headers: {'location': 'https://api.osv.dev/v1/querybatch'});
      });
      await expectLater(
          OsvSource(fetcherFor(client), base: Endpoints.defaults.osvApi)
              .query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>().having((e) => e.message, 'message',
              contains('not followed for a POST'))));
      expect(calls, 1);
    });

    test(
        'a redirect without a Location header is an unexpected response, not '
        'a crash', () async {
      var calls = 0;
      final client = MockClient((req) async {
        calls++;
        return http.Response('', 301);
      });
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi));
      await expectLater(
          source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>().having(
              (e) => e.message, 'message', contains('without a Location'))));
      expect(calls, 1);
    });

    test(
        'a redirect whose Location is not a URL is an unexpected response '
        'that says so, not one that says the header is missing', () async {
      final client = MockClient((req) async =>
          http.Response('', 301, headers: {'location': 'http://[bad'}));
      final source = GitHubGlobalSource(GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi));
      await expectLater(
          source.query([pkg('dio', '1.0.0')]),
          throwsA(isA<UnexpectedResponse>().having((e) => e.message, 'message',
              contains('with a Location that is not a URL'))));
    });
  });

  group('Flutter release manifest', () {
    final manifest = fixtureJson('responses/flutter_releases_linux.json');
    BundledDart parse(String flutter) =>
        FlutterReleases.parse(manifest, Version.parse(flutter));

    test('a stable Flutter version maps to the Dart SDK it bundles', () {
      expect(
          parse('3.47.8'),
          isA<BundledDartFound>()
              .having((b) => b.dart, 'dart', Version.parse('3.13.7')));
      expect(
          parse('3.47.6'),
          isA<BundledDartFound>()
              .having((b) => b.dart, 'dart', Version.parse('3.13.5')));
    });

    test('a beta Flutter version maps to the pre-release Dart in its build',
        () {
      expect(
          parse('3.50.0-0.1.pre'),
          isA<BundledDartFound>().having(
              (b) => b.dart, 'dart', Version.parse('3.14.0-315.1.beta')));
    });

    test('a version released on two channels with one Dart version is found',
        () {
      expect(
          parse('2.0.0'),
          isA<BundledDartFound>()
              .having((b) => b.dart, 'dart', Version.parse('2.12.0')));
    });

    test('a version listed without a Dart SDK version is not recorded', () {
      expect(parse('1.22.6'), isA<BundledDartNotRecorded>());
    });

    test(
        'a version the manifest does not list is not listed, and entries '
        'that are not versions are skipped', () {
      expect(parse('9.9.9'), isA<BundledDartNotListed>());
      expect(
          (manifest as Map)['releases'],
          contains(
              predicate((e) => (e as Map)['version'] == 'v1.12.13+hotfix.9')));
    });

    test(
        'entries that disagree on the Dart version are not guessed from, '
        'whatever channels they sit on', () {
      final doubled = {
        'releases': [
          {'version': '3.47.8', 'channel': 'beta', 'dart_sdk_version': '9.0.0'},
          {
            'version': '3.47.8',
            'channel': 'stable',
            'dart_sdk_version': '3.13.7'
          },
        ],
      };
      expect(
          FlutterReleases.parse(doubled, Version.parse('3.47.8')),
          isA<BundledDartUnavailable>().having(
              (b) => b.cause.message, 'cause', contains('several Dart SDK')));
    });

    test('a manifest without a releases list is unavailable', () {
      expect(
          FlutterReleases.parse(
              {'current_release': {}}, Version.parse('3.47.8')),
          isA<BundledDartUnavailable>());
    });

    test(
        'an unreachable manifest, a bad status and a body that is not JSON '
        'are unavailable with their cause, never thrown', () async {
      for (final (status, body) in [(503, ''), (200, 'not json')]) {
        final client = MockClient((_) async => http.Response(body, status));
        final releases = FlutterReleases(
            HttpFetcher(client, retryDelay: Duration.zero),
            base: Endpoints.defaults.flutterReleases);
        expect(await releases.bundledDart(Version.parse('3.47.8')),
            isA<BundledDartUnavailable>(),
            reason: '$status $body');
      }
    });

    test(
        'the manifest is asked with a GET of releases_linux.json under the '
        'base, with no token and nothing of the pin in the URL', () async {
      final api = FakeApi();
      final releases = FlutterReleases(fetcherFor(api.client),
          base: Endpoints.defaults.flutterReleases);
      await releases.bundledDart(Version.parse('3.47.8'));
      final request = api.requests.single;
      expect(request.method, 'GET');
      expect(request.url.toString(),
          'https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json');
      expect(request.headers.keys.map((k) => k.toLowerCase()),
          isNot(contains('authorization')));
    });

    test('DARTVULNCHECK_FLUTTER_RELEASES_URL overrides the base', () {
      final endpoints = Endpoints.fromEnvironment({
        'DARTVULNCHECK_FLUTTER_RELEASES_URL': 'https://mirror.example/flutter'
      });
      expect(endpoints.flutterReleases,
          Uri.parse('https://mirror.example/flutter'));
      expect(endpoints.overrides.keys, ['DARTVULNCHECK_FLUTTER_RELEASES_URL']);
      expect(
          () => Endpoints.fromEnvironment(
              {'DARTVULNCHECK_FLUTTER_RELEASES_URL': 'http://mirror.example/'}),
          throwsA(isA<InvalidEndpoint>()));
    });
  });

  group('withdrawn advisories', () {
    test('a withdrawn advisory in the global database is dropped', () async {
      final api = FakeApi();
      final advisories =
          await GitHubGlobalSource(githubFor(api)).query([pkg('dio', '4.0.6')]);
      expect(
          advisories.map((a) => a.id), isNot(contains('GHSA-jwpw-q68h-r678')));
      expect(advisories.map((a) => a.id), contains('GHSA-9324-jv53-9cc8'));
    });

    test('a withdrawn OSV record is dropped', () async {
      final api = FakeApi();
      final advisories = await OsvSource(fetcherFor(api.client),
              base: Endpoints.defaults.osvApi)
          .query([pkg('dio', '4.0.6')]);
      expect(advisories.map((a) => a.id), ['GHSA-9324-jv53-9cc8']);
    });
  });

  group('GitHub errors', () {
    test('403 without rate-limit signs is access denied, not rate limiting',
        () async {
      final api = FakeApi()..githubStatus = 403;
      expect(
        GitHubGlobalSource(githubFor(api)).query([pkg('dio', '1.0.0')]),
        throwsA(isA<AccessDenied>()
            .having((e) => e.message, 'message', contains('GITHUB_TOKEN'))),
      );
    });

    test('a body that is not JSON is an unexpected response', () async {
      final client = MockClient((_) async => http.Response('<html>', 200));
      expect(
        GitHubGlobalSource(GitHubClient(fetcherFor(client),
                apiBase: Endpoints.defaults.githubApi))
            .query([pkg('dio', '1.0.0')]),
        throwsA(isA<UnexpectedResponse>()),
      );
    });
  });

  group('fallback', () {
    test('switches to OSV when GitHub answers with something other than JSON',
        () async {
      final api = FakeApi();
      final client = MockClient((req) async => req.url.host == 'api.github.com'
          ? http.Response('<html>proxy page</html>', 200)
          : api.handle(req));
      final fetcher = fetcherFor(client);
      final source = FallbackSource(
        GitHubGlobalSource(
            GitHubClient(fetcher, apiBase: Endpoints.defaults.githubApi)),
        OsvSource(fetcher, base: Endpoints.defaults.osvApi),
      );
      final advisories = await source.query([pkg('dio', '4.0.6')]);
      expect(advisories.map((a) => a.id), contains('GHSA-9324-jv53-9cc8'));
    });

    test('switches to OSV when GitHub returns 5xx', () async {
      final api = FakeApi()..githubStatus = 503;
      VulncheckException? seen;
      final source = FallbackSource(
        GitHubGlobalSource(githubFor(api)),
        OsvSource(fetcherFor(api.client), base: Endpoints.defaults.osvApi),
        onFallback: (e) => seen = e,
      );
      final advisories = await source.query([pkg('dio', '4.0.6')]);
      expect(seen, isNotNull);
      expect(advisories.map((a) => a.id), contains('GHSA-9324-jv53-9cc8'));
    });

    test('does not switch on rate limiting', () async {
      final api = FakeApi()..githubStatus = 429;
      final source = FallbackSource(
        GitHubGlobalSource(githubFor(api)),
        OsvSource(fetcherFor(api.client), base: Endpoints.defaults.osvApi),
      );
      expect(source.query([pkg('dio', '4.0.6')]), throwsA(isA<RateLimited>()));
    });

    test('fails when OSV is down too', () async {
      final api = FakeApi()
        ..githubStatus = 503
        ..osvStatus = 503;
      final source = FallbackSource(
        GitHubGlobalSource(githubFor(api)),
        OsvSource(fetcherFor(api.client), base: Endpoints.defaults.osvApi),
      );
      expect(source.query([pkg('dio', '4.0.6')]),
          throwsA(isA<SourceUnreachable>()));
    });
  });

  group('OSV', () {
    test('querybatch uses ecosystem Pub, then fetches each vuln', () async {
      final api = FakeApi();
      final advisories = await OsvSource(fetcherFor(api.client),
              base: Endpoints.defaults.osvApi)
          .query([pkg('http', '0.13.2')]);
      final batch = api.requests.first;
      expect(batch.method, 'POST');
      expect(batch.body, contains('"ecosystem":"Pub"'));
      final a = advisories.single;
      expect(a.id, 'GHSA-4rgh-jx4f-qfcq');
      expect(a.severity, Severity.moderate);
      expect(a.affected.single.ranges, ['< 0.13.3']);
      expect(a.affected.single.patched, '0.13.3');
      expect(a.url.toString(),
          'https://osv.dev/vulnerability/GHSA-4rgh-jx4f-qfcq');
    });

    test('follows next_page_token per query', () async {
      var batches = 0;
      final client = MockClient((req) async {
        if (req.url.path == '/v1/querybatch') {
          batches++;
          final token = req.body.contains('page_token');
          return http.Response(
              token
                  ? '{"results":[{"vulns":[{"id":"GHSA-B"}]}]}'
                  : '{"results":[{"vulns":[{"id":"GHSA-A"}],'
                      '"next_page_token":"p2"}]}',
              200);
        }
        final id = req.url.pathSegments.last;
        return http.Response('{"id":"$id","affected":[]}', 200);
      });
      final advisories =
          await OsvSource(fetcherFor(client), base: Endpoints.defaults.osvApi)
              .query([pkg('dio', '1.0.0')]);
      expect(batches, 2);
      expect(advisories.map((a) => a.id), ['GHSA-A', 'GHSA-B']);
    });

    test('introduced/fixed/last_affected events become GitHub-style ranges',
        () {
      final a = OsvSource.parseOsvVuln({
        'id': 'X',
        'affected': [
          {
            'package': {'ecosystem': 'Pub', 'name': 'p'},
            'ranges': [
              {
                'type': 'ECOSYSTEM',
                'events': [
                  {'introduced': '1.0.0'},
                  {'fixed': '1.2.0'},
                  {'introduced': '2.0.0'},
                  {'last_affected': '2.1.0'},
                  {'introduced': '3.0.0'},
                ],
              },
            ],
          },
        ],
      })!;
      expect(a.affected.single.ranges,
          ['>= 1.0.0, < 1.2.0', '>= 2.0.0, <= 2.1.0', '>= 3.0.0']);
    });
  });

  group('repository advisories', () {
    test('owner/repo comes from the first two path segments', () {
      expect(githubRepoFromUrl('https://github.com/cfug/dio/blob/main/dio'),
          'cfug/dio');
      expect(
          githubRepoFromUrl(
              'https://github.com/flutter/packages/tree/main/packages/go_router'),
          'flutter/packages');
      expect(githubRepoFromUrl('https://github.com/a/b.git'), 'a/b');
      expect(githubRepoFromUrl('github.com/a/b'), 'a/b');
      expect(githubRepoFromUrl('git@github.com:a/b.git'), 'a/b');
      expect(githubRepoFromUrl('https://gitlab.com/a/b'), isNull);
      expect(githubRepoFromUrl('https://github.com/a'), isNull);
    });

    test('an owner or repository that is not a GitHub name is rejected', () {
      expect(githubRepoFromUrl('https://github.com/a%2F..%2Fx/b'), isNull);
      expect(githubRepoFromUrl('https://github.com/a/..'), isNull);
      expect(githubRepoFromUrl('https://github.com/a/b?state=all'), 'a/b');
      expect(githubRepoFromUrl('https://github.com/dart-lang/sdk.git'),
          'dart-lang/sdk');
    });

    test(
        'a repository advisory cannot speak for a package from another '
        'repository', () async {
      final api = FakeApi()
        ..extraAdvisories['cfug/dio'] = [
          repositoryAdvisoryJson('GHSA-xxxx-xxxx-xxxx',
              repo: 'cfug/dio',
              summary: 'Names http, which pub.dev maps to dart-lang/http',
              vulnerabilities: [
                vulnerabilityJson(
                    ecosystem: 'pub', name: 'http', range: '< 99.0.0'),
              ]),
        ];
      final source = RepositoryPackageSource(
          PubDevClient(fetcherFor(api.client), base: Endpoints.defaults.pubDev),
          RepositoryAdvisoryFetcher(githubFor(api)));
      final result =
          await source.query([pkg('dio', '4.0.6'), pkg('http', '0.13.2')]);
      expect(result.advisories.map((a) => a.id),
          isNot(contains('GHSA-xxxx-xxxx-xxxx')));
    });

    test('the repository URL is latest.pubspec.repository on pub.dev',
        () async {
      final api = FakeApi();
      final url = await PubDevClient(fetcherFor(api.client),
              base: Endpoints.defaults.pubDev)
          .repositoryUrl('dio');
      expect(url, 'https://github.com/cfug/dio/blob/main/dio');
    });

    test('the latest release is latest.version on pub.dev', () async {
      final api = FakeApi();
      final client =
          PubDevClient(fetcherFor(api.client), base: Endpoints.defaults.pubDev);
      expect(await client.latestVersion('dio'), Version.parse('5.11.1'));
      expect(await client.latestVersion('no_such_package'), isNull);
    });

    test('a release check is newer, up to date, or unknown', () async {
      Future<ReleaseStatus> statusFor(String? released, {int? status}) {
        final api = FakeApi()
          ..releasedVersion = released
          ..pubDevStatus = status;
        return ReleaseCheck(
                PubDevClient(fetcherFor(api.client),
                    base: Endpoints.defaults.pubDev),
                current: Version.parse('0.2.3'))
            .status();
      }

      expect(
          await statusFor('0.3.0'),
          isA<NewerRelease>()
              .having((s) => s.latest, 'latest', Version.parse('0.3.0')));
      expect(await statusFor('0.2.3'), isA<UpToDate>());
      expect(await statusFor('0.2.0'), isA<UpToDate>());
      expect(await statusFor(null), isA<ReleaseUnknown>());
      expect(await statusFor('0.3.0', status: 503), isA<ReleaseUnknown>());
    });

    test(
        'matches lock packages by name and spreads package-less advisories '
        'over the repository\'s packages', () async {
      final api = FakeApi()
        ..extraAdvisories['cfug/dio'] = [
          repositoryAdvisoryJson('GHSA-qqqq-rrrr-ssss',
              repo: 'cfug/dio', summary: 'Advisory that names no package'),
        ];
      final github = githubFor(api);
      final source = RepositoryPackageSource(
          PubDevClient(fetcherFor(api.client), base: Endpoints.defaults.pubDev),
          RepositoryAdvisoryFetcher(github));
      final result = await source
          .query([pkg('dio', '4.0.6'), pkg('unknown_pkg', '1.0.0')]);
      // GHSA-cr65-55v9-xhvv names dio_http2_adapter, which is not locked.
      expect(result.advisories.map((a) => a.id), [
        'GHSA-9324-jv53-9cc8',
        'GHSA-qqqq-rrrr-ssss',
      ]);
      final unnamed = result.advisories.last;
      expect(unnamed.affected.single.name, 'dio');
      expect(unnamed.affected.single.ranges, isEmpty);
      expect(
          result.notes,
          anyElement(isA<NoGitHubRepository>()
              .having((n) => n.subject, 'subject', 'unknown_pkg')));
      expect(result.failures, 0);
    });

    test('a pub.dev error is a failed lookup, not "no repository"', () async {
      final api = FakeApi()..pubDevStatus = 429;
      final source = RepositoryPackageSource(
          PubDevClient(fetcherFor(api.client), base: Endpoints.defaults.pubDev),
          RepositoryAdvisoryFetcher(githubFor(api)));
      final result = await source.query([pkg('dio', '4.0.6')]);
      expect(result.notes.single,
          isA<LookupFailed>().having((n) => n.subject, 'subject', 'dio'));
      expect(result.failures, 1);
    });

    test(
        'an unnamed advisory in the SDK repository stays with the SDK, not '
        'with the packages published from it', () async {
      final api = FakeApi();
      final source = RepositoryPackageSource(
          PubDevClient(fetcherFor(api.client), base: Endpoints.defaults.pubDev),
          RepositoryAdvisoryFetcher(githubFor(api)));
      final result = await source.query([pkg('meta', '1.19.0')]);
      expect(result.advisories, isEmpty);
      expect(result.notes, isEmpty);
    });

    test('each repository is fetched once per run', () async {
      final api = FakeApi();
      final fetcher = RepositoryAdvisoryFetcher(githubFor(api));
      await fetcher.fetch('dart-lang/sdk');
      await fetcher.fetch('dart-lang/sdk');
      expect(api.requests, hasLength(1));
    });

    test('a 404 repository is skipped, not fatal', () async {
      final client = MockClient((_) async => http.Response('{}', 404));
      final github = GitHubClient(fetcherFor(client),
          apiBase: Endpoints.defaults.githubApi);
      expect(await RepositoryAdvisoryFetcher(github).fetch('no/such'),
          isA<RepositoryMissing>());
    });

    test(
        "a renamed repository's advisories are read from its new location "
        'and keep the old name', () async {
      final api = FakeApi()..movedRepos = {'cfug/dio': 42};
      final source = RepositoryPackageSource(
          PubDevClient(fetcherFor(api.client), base: Endpoints.defaults.pubDev),
          RepositoryAdvisoryFetcher(githubFor(api)));
      final result = await source.query([pkg('dio', '4.0.6')]);
      final found =
          result.advisories.singleWhere((a) => a.id == 'GHSA-9324-jv53-9cc8');
      expect(found.repository, 'cfug/dio');
      expect(
          result.notes.single,
          isA<RepositoryMoved>()
              .having((n) => n.subject, 'subject', 'cfug/dio')
              .having(
                  (n) => n.readFrom,
                  'readFrom',
                  Uri.parse('https://api.github.com/repositories/42/'
                      'security-advisories?state=published&per_page=100')));
      expect(result.failures, 0);
    });

    test('a moved repository is fetched once per run', () async {
      final api = FakeApi()..movedRepos = {'cfug/dio': 42};
      final fetcher = RepositoryAdvisoryFetcher(githubFor(api));
      await fetcher.fetch('cfug/dio');
      final again = await fetcher.fetch('cfug/dio');
      expect(again, isA<RepositoryRead>());
      expect(api.requests.map((r) => r.url.path), [
        '/repos/cfug/dio/security-advisories',
        '/repositories/42/security-advisories',
      ]);
    });

    test('a renamed SDK repository is still read', () async {
      final api = FakeApi()..movedRepos = {'dart-lang/sdk': 7};
      final advisories =
          await SdkAdvisorySource(RepositoryAdvisoryFetcher(githubFor(api)))
              .fetchAll();
      expect(advisories.map((a) => a.id), contains('GHSA-frr6-h895-5pxp'));
    });
  });
}
