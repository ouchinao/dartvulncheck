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
      expect(advisories.map((a) => a.id),
          containsAll(['GHSA-9324-jv53-9cc8', 'GHSA-jwpw-q68h-r678']));
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

    test('the repository URL is latest.pubspec.repository on pub.dev',
        () async {
      final api = FakeApi();
      final url = await PubDevClient(fetcherFor(api.client),
              base: Endpoints.defaults.pubDev)
          .repositoryUrl('dio');
      expect(url, 'https://github.com/cfug/dio/blob/main/dio');
    });

    test(
        'matches lock packages by name and spreads package-less advisories '
        'over the repository\'s packages', () async {
      final api = FakeApi();
      final github = githubFor(api);
      final source = RepositoryPackageSource(
          PubDevClient(fetcherFor(api.client), base: Endpoints.defaults.pubDev),
          RepositoryAdvisoryFetcher(github));
      final result = await source
          .query([pkg('dio', '4.0.6'), pkg('unknown_pkg', '1.0.0')]);
      expect(result.advisories.map((a) => a.id), [
        'GHSA-zzzz-yyyy-xxxx',
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
      expect(await RepositoryAdvisoryFetcher(github).fetch('no/such'), isNull);
    });
  });
}
