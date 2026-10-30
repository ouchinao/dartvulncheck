import '../model/advisory.dart';
import '../model/errors.dart';
import '../model/package_ref.dart';
import '../model/severity.dart';
import 'advisory_source.dart';
import 'github_client.dart';
import 'github_global.dart';
import 'http_fetcher.dart';
import 'pub_dev.dart';

// Cached for one run only, never on disk: a stale "no problems" is worse
// than more requests.
class RepositoryAdvisoryFetcher {
  final GitHubClient github;
  final _cache = <String, Future<List<Advisory>?>>{};

  RepositoryAdvisoryFetcher(this.github);

  Future<List<Advisory>?> fetch(String repo) =>
      _cache.putIfAbsent(repo, () => _fetch(repo));

  Future<List<Advisory>?> _fetch(String repo) async {
    final url = github.endpoint('/repos/$repo/security-advisories',
        {'state': 'published', 'per_page': '100'});
    final List<Object?>? items;
    try {
      items = await github.getAllPages(url);
    } on GitHubHttpError {
      return null;
    }
    if (items == null) return null;
    return [
      for (final item in items)
        if (parseRepositoryAdvisory(item, repo) case final a?) a,
    ];
  }

  static Advisory? parseRepositoryAdvisory(Object? json, String repo) {
    if (json is! Map) return null;
    final id = json['ghsa_id'];
    if (id is! String) return null;
    final state = json['state'];
    if (state is String && state != 'published') return null;
    return Advisory(
      id: id,
      aliases: githubAliases(json, id),
      summary: '${json['summary'] ?? ''}'.trim(),
      severity: Severity.parse(json['severity']),
      url: Uri.parse(
          '${json['html_url'] ?? 'https://github.com/$repo/security/advisories/$id'}'),
      origin: AdvisoryOrigin.repository,
      repository: repo,
      affected: [
        for (final v in (json['vulnerabilities'] as List?) ?? const [])
          if (v is Map) githubAffected(v),
      ],
    );
  }
}

class RepositoryPackageSource with SourceNotes implements AdvisorySource {
  final PubDevClient pubDev;
  final RepositoryAdvisoryFetcher fetcher;
  final int pubDevConcurrency;
  final int githubConcurrency;
  final _repoOf = <String, Future<String?>>{};

  RepositoryPackageSource(
    this.pubDev,
    this.fetcher, {
    this.pubDevConcurrency = 8,
    this.githubConcurrency = 4,
  });

  int failures = 0;

  @override
  String get name => 'repository advisories';

  @override
  Future<List<Advisory>> query(List<PackageRef> packages) async {
    failures = 0;
    final lookups = packages.where((p) {
      if (p.isThirdPartyHosted) {
        notes.add('${p.name}: pub.dev 以外でホストされているので'
            'リポジトリアドバイザリを見ていません');
        return false;
      }
      return true;
    }).toList();

    final repos = await mapPool(lookups, pubDevConcurrency, (p) async {
      try {
        return await _repoOf.putIfAbsent(
            p.name, () => pubDev.repositoryUrl(p.name).then(_toRepo));
      } on SourceUnreachable catch (e) {
        _repoOf.remove(p.name);
        failures++;
        notes.add('${p.name}: ${e.message}');
        return null;
      }
    });

    final byRepo = <String, List<PackageRef>>{};
    for (var i = 0; i < lookups.length; i++) {
      final repo = repos[i];
      if (repo == null) {
        notes.add('${lookups[i].name}: リポジトリが GitHub に無いか不明なので'
            'リポジトリアドバイザリを見ていません');
        continue;
      }
      (byRepo[repo] ??= []).add(lookups[i]);
    }

    final repoNames = byRepo.keys.toList();
    final fetched = await mapPool(repoNames, githubConcurrency, (repo) async {
      try {
        return await fetcher.fetch(repo);
      } on SourceUnreachable catch (e) {
        failures++;
        notes.add('$repo: ${e.message}');
        return null;
      }
    });

    final lockNames = {for (final p in packages) p.name};
    final out = <Advisory>[];
    for (var i = 0; i < repoNames.length; i++) {
      final advisories = fetched[i];
      if (advisories == null) {
        notes.add('${repoNames[i]}: アドバイザリを読めませんでした');
        continue;
      }
      final fromRepo = byRepo[repoNames[i]]!;
      for (final a in advisories) {
        final affected = <AffectedPackage>[];
        final unnamed = a.affected.isEmpty || a.affected.any((e) => !e.hasName);
        for (final e in a.affected) {
          if (!e.hasName) continue;
          final eco = e.ecosystem?.toLowerCase();
          if (eco != null && eco.isNotEmpty && eco != 'pub') continue;
          if (lockNames.contains(e.name)) affected.add(e);
        }
        // Not skipped when no package is named: it may concern any package
        // published from this repository.
        if (unnamed) {
          for (final p in fromRepo) {
            if (!affected.any((e) => e.name == p.name)) {
              affected.add(AffectedPackage(name: p.name, ecosystem: 'pub'));
            }
          }
        }
        if (affected.isNotEmpty) {
          out.add(Advisory(
            id: a.id,
            aliases: a.aliases,
            summary: a.summary,
            severity: a.severity,
            url: a.url,
            origin: a.origin,
            repository: a.repository,
            affected: affected,
          ));
        }
      }
    }
    return out;
  }

  static String? _toRepo(String? url) =>
      url == null ? null : githubRepoFromUrl(url);
}

// Repository advisories, not the global database: the SDKs belong to no
// ecosystem that `affects=` can filter by.
class SdkAdvisorySource {
  final RepositoryAdvisoryFetcher fetcher;
  SdkAdvisorySource(this.fetcher);

  static const repositories = ['dart-lang/sdk', 'flutter/flutter'];

  Future<List<Advisory>> fetchAll() async {
    final out = <Advisory>[];
    for (final repo in repositories) {
      final advisories = await fetcher.fetch(repo);
      if (advisories == null) {
        throw SourceUnreachable(GitHubClient.sourceName, '$repo のアドバイザリを読めません');
      }
      out.addAll(advisories);
    }
    return out;
  }
}
