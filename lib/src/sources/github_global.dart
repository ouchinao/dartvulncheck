import '../model/advisory.dart';
import '../model/errors.dart';
import '../model/package_ref.dart';
import '../model/severity.dart';
import 'advisory_source.dart';
import 'github_client.dart';

// affects= instead of listing every pub advisory and matching here: one
// request per 1000 packages instead of paging the whole database.
class GitHubGlobalSource implements AdvisorySource {
  final GitHubClient github;
  final int chunkSize;

  GitHubGlobalSource(this.github, {this.chunkSize = 1000});

  @override
  String get name => 'GitHub Advisory Database';

  @override
  Future<List<Advisory>> query(List<PackageRef> packages) async {
    final byId = <String, Advisory>{};
    for (var i = 0; i < packages.length; i += chunkSize) {
      final chunk = packages.sublist(
          i, i + chunkSize > packages.length ? packages.length : i + chunkSize);
      final url = github.endpoint('/advisories', {
        'ecosystem': 'pub',
        'affects': chunk.map((p) => '${p.name}@${p.version}').join(','),
        'per_page': '100',
      });
      final items = await github.getAllPages(url);
      if (items == null) {
        throw const UnexpectedResponse(
            GitHubClient.sourceName, '/advisories returned 404');
      }
      for (final item in items) {
        final advisory = parseGlobalAdvisory(item);
        if (advisory != null) byId[advisory.id] = advisory;
      }
    }
    return byId.values.toList();
  }

  static Advisory? parseGlobalAdvisory(Object? json) {
    if (json is! Map) return null;
    final id = json['ghsa_id'];
    if (id is! String) return null;
    return Advisory(
      id: id,
      aliases: githubAliases(json, id),
      summary: '${json['summary'] ?? ''}'.trim(),
      severity: Severity.parse(json['severity']),
      url: Uri.parse(
          '${json['html_url'] ?? 'https://github.com/advisories/$id'}'),
      origin: AdvisoryOrigin.global,
      affected: [
        for (final v in (json['vulnerabilities'] as List?) ?? const [])
          if (v is Map) githubAffected(v, patched: _firstPatched(v)),
      ],
    );
  }
}

List<String> githubAliases(Map<Object?, Object?> json, String id) {
  final out = <String>{};
  final cve = json['cve_id'];
  if (cve is String && cve.isNotEmpty) out.add(cve);
  for (final ident in (json['identifiers'] as List?) ?? const []) {
    if (ident is Map && ident['value'] is String) {
      out.add(ident['value'] as String);
    }
  }
  out.remove(id);
  return out.toList();
}

// The patched field is passed in, not guessed here: the global and the
// repository API name it differently, and one function trying both would
// read a field that the other API might add with another meaning.
AffectedPackage githubAffected(Map<Object?, Object?> v,
    {required Object? patched}) {
  final package = v['package'];
  final range = v['vulnerable_version_range'];
  return AffectedPackage(
    name: package is Map ? package['name'] as String? : null,
    ecosystem: package is Map ? package['ecosystem'] as String? : null,
    ranges: range is String && range.trim().isNotEmpty ? [range] : const [],
    patched: patched is String && patched.trim().isNotEmpty ? patched : null,
  );
}

Object? _firstPatched(Map<Object?, Object?> v) {
  final patched = v['first_patched_version'];
  return patched is Map ? patched['identifier'] : patched;
}
