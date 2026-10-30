import '../model/advisory.dart';
import '../model/errors.dart';
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

class RepositoryResult {
  final List<Advisory> advisories;
  final List<String> notes;
  final int failures;
  const RepositoryResult(this.advisories, this.notes, this.failures);
}

// Not an AdvisorySource: nothing stands in for it, and it reports notes and
// failures that the interchangeable sources do not have.
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

  // Notes and failures come back in the result, not as fields on this
  // object: fields would carry one call's state into the next.
  Future<RepositoryResult> query(List<PackageRef> packages) async {
    final notes = <String>[];
    var failures = 0;

    final lookups = <PackageRef>[];
    for (final p in packages) {
      if (p.isThirdPartyHosted) {
        notes.add('${p.name}: hosted outside pub.dev, repository advisories '
            'not checked');
      } else {
        lookups.add(p);
      }
    }
    final names = {for (final p in lookups) p.name}.toList();

    final repos = await mapPool(names, pubDevConcurrency, (name) async {
      try {
        final url = await pubDev.repositoryUrl(name);
        return url == null ? null : githubRepoFromUrl(url);
      } on SourceUnreachable catch (e) {
        failures++;
        notes.add('$name: ${e.message}');
        return null;
      }
    });

    final repoOf = <String, String>{};
    for (var i = 0; i < names.length; i++) {
      final repo = repos[i];
      if (repo == null) {
        notes.add('${names[i]}: no known GitHub repository, repository '
            'advisories not checked');
      } else {
        repoOf[names[i]] = repo;
      }
    }
    final byRepo = <String, List<String>>{};
    repoOf.forEach((name, repo) => (byRepo[repo] ??= []).add(name));

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
        notes.add('${repoNames[i]}: advisories could not be read');
        continue;
      }
      for (final a in advisories) {
        final affected = _affectedInLock(a, lockNames, byRepo[repoNames[i]]!);
        if (affected.isNotEmpty) out.add(_withAffected(a, affected));
      }
    }
    return RepositoryResult(out, notes, failures);
  }

  static List<AffectedPackage> _affectedInLock(
      Advisory a, Set<String> lockNames, List<String> fromRepo) {
    final affected = <AffectedPackage>[
      for (final e in a.affected)
        if (e.hasName && _isPub(e) && lockNames.contains(e.name)) e,
    ];
    // Not skipped when no package is named: it may concern any package
    // published from this repository.
    final unnamed = a.affected.isEmpty || a.affected.any((e) => !e.hasName);
    if (unnamed) {
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
        throw SourceUnreachable(
            GitHubClient.sourceName, 'cannot read the advisories of $repo');
      }
      out.addAll(advisories);
    }
    return out;
  }
}
