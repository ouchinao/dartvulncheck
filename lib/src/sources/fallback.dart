import '../model/advisory.dart';
import '../model/errors.dart';
import '../model/package_ref.dart';
import 'advisory_source.dart';

// Rate limiting and denied access do not switch to the fallback: the fix is
// the token, and a slower source would hide the problem.
class FallbackSource implements AdvisorySource {
  final AdvisorySource primary;
  final AdvisorySource fallback;
  final void Function(VulncheckException error)? onFallback;

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
    } on UnexpectedResponse catch (e) {
      onFallback?.call(e);
      return fallback.query(packages);
    }
  }
}
