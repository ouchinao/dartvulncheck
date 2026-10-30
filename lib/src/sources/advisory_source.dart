import '../model/advisory.dart';
import '../model/package_ref.dart';

// One type for all three sources, so OSV can stand in for GitHub without
// the rest of the tool knowing.
abstract class AdvisorySource {
  String get name;

  Future<List<Advisory>> query(List<PackageRef> packages);
}

mixin SourceNotes {
  final List<String> notes = [];
}
