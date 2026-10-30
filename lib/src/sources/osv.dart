import '../model/advisory.dart';
import '../model/errors.dart';
import '../model/package_ref.dart';
import '../model/severity.dart';
import 'advisory_source.dart';
import 'http_fetcher.dart';
import 'pool.dart';

// Only a fallback, not the primary: same data as the GitHub Advisory
// Database, arriving later.
class OsvSource implements AdvisorySource {
  final HttpFetcher fetcher;
  final Uri base;
  final int batchSize;
  final int concurrency;

  OsvSource(this.fetcher,
      {required this.base, this.batchSize = 1000, this.concurrency = 8});

  static const sourceName = 'OSV.dev';

  @override
  String get name => sourceName;

  Uri _url(String path) => base.replace(
      path:
          '${base.path.endsWith('/') ? base.path.substring(0, base.path.length - 1) : base.path}$path');

  @override
  Future<List<Advisory>> query(List<PackageRef> packages) async {
    final ids = <String>{};
    for (var i = 0; i < packages.length; i += batchSize) {
      final end =
          i + batchSize > packages.length ? packages.length : i + batchSize;
      ids.addAll(await _queryBatch(packages.sublist(i, end)));
    }
    final list = ids.toList()..sort();
    final vulns = await mapPool(list, concurrency, _fetchVuln);
    return [
      for (final v in vulns)
        if (v != null) v
    ];
  }

  static const maxPages = 50;

  Future<Set<String>> _queryBatch(List<PackageRef> packages) async {
    final ids = <String>{};
    var pending = <(PackageRef, String?)>[for (final p in packages) (p, null)];
    var pages = 0;
    while (pending.isNotEmpty) {
      if (++pages > maxPages) {
        throw UnexpectedResponse(sourceName, 'more than $maxPages pages');
      }
      final body = {
        'queries': [
          for (final (p, token) in pending)
            {
              'package': {'name': p.name, 'ecosystem': 'Pub'},
              'version': '${p.version}',
              if (token != null) 'page_token': token,
            }
        ]
      };
      final response = await fetcher.postJson(_url('/v1/querybatch'), body,
          sourceName: sourceName);
      if (response.statusCode != 200) {
        throw UnexpectedResponse(sourceName, 'HTTP ${response.statusCode}');
      }
      final json = decodeJson(response, sourceName);
      final results = json is Map ? json['results'] : null;
      if (results is! List || results.length != pending.length) {
        throw const UnexpectedResponse(
            sourceName, 'malformed querybatch response');
      }
      final next = <(PackageRef, String?)>[];
      for (var i = 0; i < results.length; i++) {
        final r = results[i];
        if (r is! Map) continue;
        for (final v in (r['vulns'] as List?) ?? const []) {
          if (v is Map && v['id'] is String) ids.add(v['id'] as String);
        }
        final token = r['next_page_token'];
        if (token is String && token.isNotEmpty) {
          next.add((pending[i].$1, token));
        }
      }
      pending = next;
    }
    return ids;
  }

  Future<Advisory?> _fetchVuln(String id) async {
    final response = await fetcher.get(
        _url('/v1/vulns/${Uri.encodeComponent(id)}'),
        sourceName: sourceName);
    if (response.statusCode == 404) return null;
    if (response.statusCode != 200) {
      throw UnexpectedResponse(sourceName, 'HTTP ${response.statusCode}');
    }
    return parseOsvVuln(decodeJson(response, sourceName));
  }

  static Advisory? parseOsvVuln(Object? json) {
    if (json is! Map) return null;
    final id = json['id'];
    if (id is! String) return null;
    if (json['withdrawn'] != null) return null;
    final dbSpecific = json['database_specific'];
    var summary = '${json['summary'] ?? ''}'.trim();
    if (summary.isEmpty) {
      summary = '${json['details'] ?? ''}'.trim().split('\n').first;
    }
    return Advisory(
      id: id,
      aliases: [
        for (final a in (json['aliases'] as List?) ?? const [])
          if (a is String && a != id) a,
      ],
      summary: summary,
      severity:
          Severity.parse(dbSpecific is Map ? dbSpecific['severity'] : null),
      url: Uri.parse('https://osv.dev/vulnerability/$id'),
      origin: AdvisoryOrigin.osv,
      affected: [
        for (final a in (json['affected'] as List?) ?? const [])
          if (a is Map && _isPub(a)) _osvAffected(a),
      ],
    );
  }

  static bool _isPub(Map<Object?, Object?> affected) {
    final pkg = affected['package'];
    return pkg is Map && '${pkg['ecosystem']}'.toLowerCase() == 'pub';
  }

  // versions[] is not turned into ranges: OSV already matched the version,
  // and the matcher trusts a server match whose range it cannot read.
  static AffectedPackage _osvAffected(Map<Object?, Object?> a) {
    final pkg = a['package'] as Map<Object?, Object?>;
    final ranges = <String>[];
    String? firstFixed;
    for (final r in (a['ranges'] as List?) ?? const []) {
      if (r is! Map) continue;
      final type = r['type'];
      if (type != 'ECOSYSTEM' && type != 'SEMVER') continue;
      String? introduced;
      for (final e in (r['events'] as List?) ?? const []) {
        if (e is! Map) continue;
        if (e['introduced'] is String) {
          if (introduced != null) ranges.add(_lower(introduced));
          introduced = e['introduced'] as String;
        } else if (e['fixed'] is String) {
          final fixed = e['fixed'] as String;
          firstFixed ??= fixed;
          ranges.add(_join(introduced, '< $fixed'));
          introduced = null;
        } else if (e['last_affected'] is String) {
          ranges.add(_join(introduced, '<= ${e['last_affected']}'));
          introduced = null;
        }
      }
      if (introduced != null) ranges.add(_lower(introduced));
    }
    return AffectedPackage(
      name: pkg['name'] as String?,
      ecosystem: 'pub',
      ranges: ranges,
      patched: firstFixed,
    );
  }

  static String _lower(String introduced) =>
      introduced == '0' ? '>= 0.0.0-0' : '>= $introduced';

  static String _join(String? introduced, String upper) =>
      introduced == null || introduced == '0'
          ? upper
          : '>= $introduced, $upper';
}
