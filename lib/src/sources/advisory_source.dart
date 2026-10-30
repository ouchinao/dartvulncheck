import '../model/advisory.dart';
import '../model/package_ref.dart';

// One interface, not three clients known to the checker: OSV must stand in
// for GitHub without the rest of the tool knowing.
abstract class AdvisorySource {
  String get name;

  Future<List<Advisory>> query(List<PackageRef> packages);
}
