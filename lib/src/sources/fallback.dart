import '../model/advisory.dart';
import '../model/errors.dart';
import '../model/package_ref.dart';
import 'advisory_source.dart';

// Rate limiting does not switch to the fallback: the fix is a token, and a
// slower source would hide the problem.
class FallbackSource implements AdvisorySource {
  final AdvisorySource primary;
  final AdvisorySource fallback;
  final void Function(SourceUnreachable error)? onFallback;

  FallbackSource(this.primary, this.fallback, {this.onFallback});

  @override
  String get name => primary.name;

  @override
  Future<List<Advisory>> query(List<PackageRef> packages) async {
    try {
      return await primary.query(packages);
    } on SourceUnreachable catch (e) {
      onFallback?.call(e);
      return fallback.query(packages);
    }
  }
}
