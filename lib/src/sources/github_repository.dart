import '../model/advisory.dart';
import '../model/errors.dart';
import '../model/notices.dart';
import '../model/package_ref.dart';
import '../model/severity.dart';
import 'github_client.dart';
import 'github_global.dart';
import 'pool.dart';
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
    final items = await github.getAllPages(github.endpoint(
        '/repos/$repo/security-advisories',
        {'state': 'published', 'per_page': '100'}));
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
    if (json['withdrawn_at'] != null) return null;
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
          if (v is Map) githubAffected(v, patched: v['patched_versions']),
      ],
    );
  }
}

class RepositoryResult {
  final List<Advisory> advisories;
  final List<LookupNote> notes;
  const RepositoryResult(this.advisories, this.notes);

  int get failures => notes.whereType<LookupFailed>().length;
}

// Not an AdvisorySource: nothing stands in for it, and it reports notes
// that the interchangeable sources do not have.
class RepositoryPackageSource {
  final PubDevClient pubDev;
  final RepositoryAdvisoryFetcher fetcher;
  final int pubDevConcurrency;
  final int githubConcurrency;

  RepositoryPackageSource(
    this.pubDev,
    this.fetcher, {
    this.pubDevConcurrency = 8,
    this.githubConcurrency = 4,
  });

  // Notes come back in the result, not as fields on this object: fields
  // would carry one call's state into the next.
  Future<RepositoryResult> query(List<PackageRef> packages) async {
    final hostedElsewhere = <LookupNote>[
      for (final p in packages)
        if (p.isThirdPartyHosted) HostedOutsidePubDev(p.name),
    ];
    final names = {
      for (final p in packages)
        if (!p.isThirdPartyHosted) p.name,
    }.toList();

    final (packagesByRepo, repoNotes) = await _findRepositories(names);
    final (advisoriesByRepo, fetchNotes) =
        await _fetchAdvisories(packagesByRepo.keys.toList());

    final lockNames = {for (final p in packages) p.name};
    final advisories = <Advisory>[];
    for (final MapEntry(key: repo, value: list) in advisoriesByRepo.entries) {
      for (final a in list) {
        final affected = _affectedInLock(a, lockNames, packagesByRepo[repo]!);
        if (affected.isNotEmpty) advisories.add(_withAffected(a, affected));
      }
    }
    return RepositoryResult(
        advisories, [...hostedElsewhere, ...repoNotes, ...fetchNotes]);
  }

  Future<(Map<String, List<String>>, List<LookupNote>)> _findRepositories(
      List<String> names) async {
    final found = await mapPool(names, pubDevConcurrency, (name) async {
      try {
        final url = await pubDev.repositoryUrl(name);
        final repo = url == null ? null : githubRepoFromUrl(url);
        return (repo, repo == null ? NoGitHubRepository(name) : null);
      } on RateLimited {
        rethrow;
      } on VulncheckException catch (e) {
        return (null, LookupFailed(name, e));
      }
    });

    final byRepo = <String, List<String>>{};
    final notes = <LookupNote>[];
    for (final (i, (repo, note)) in found.indexed) {
      if (repo != null) (byRepo[repo] ??= []).add(names[i]);
      if (note != null) notes.add(note);
    }
    return (byRepo, notes);
  }

  Future<(Map<String, List<Advisory>>, List<LookupNote>)> _fetchAdvisories(
      List<String> repos) async {
    final fetched = await mapPool(repos, githubConcurrency, (repo) async {
      try {
        final advisories = await fetcher.fetch(repo);
        return (
          advisories,
          advisories == null ? RepositoryUnreadable(repo) : null,
        );
      } on RateLimited {
        rethrow;
      } on VulncheckException catch (e) {
        return (null, LookupFailed(repo, e));
      }
    });

    final byRepo = <String, List<Advisory>>{};
    final notes = <LookupNote>[];
    for (final (i, (advisories, note)) in fetched.indexed) {
      if (advisories != null) byRepo[repos[i]] = advisories;
      if (note != null) notes.add(note);
    }
    return (byRepo, notes);
  }

  static List<AffectedPackage> _affectedInLock(
      Advisory a, Set<String> lockNames, List<String> fromRepo) {
    final affected = <AffectedPackage>[
      for (final e in a.affected)
        if (e.hasName && _isPub(e) && lockNames.contains(e.name)) e,
    ];
    // Not skipped when no package is named: it may concern any package
    // published from this repository. Not in the SDK repositories, though:
    // there an unnamed advisory is about the SDK, which the SDK stage
    // reports, and spreading it over meta, analyzer and the rest would put
    // the same three SDK advisories on every Flutter project as noise.
    final unnamed = a.affected.isEmpty || a.affected.any((e) => !e.hasName);
    final sdkRepository = SdkAdvisorySource.repositories.contains(a.repository);
    if (unnamed && !sdkRepository) {
      for (final name in fromRepo) {
        if (!affected.any((e) => e.name == name)) {
          affected.add(AffectedPackage(name: name, ecosystem: 'pub'));
        }
      }
    }
    return affected;
  }

  static bool _isPub(AffectedPackage e) {
    final eco = e.ecosystem?.toLowerCase();
    return eco == null || eco.isEmpty || eco == 'pub';
  }

  static Advisory _withAffected(Advisory a, List<AffectedPackage> affected) =>
      Advisory(
        id: a.id,
        aliases: a.aliases,
        summary: a.summary,
        severity: a.severity,
        url: a.url,
        origin: a.origin,
        repository: a.repository,
        affected: affected,
      );
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
        throw UnexpectedResponse(
            GitHubClient.sourceName, 'the advisories of $repo returned 404');
      }
      out.addAll(advisories);
    }
    return out;
  }
}
