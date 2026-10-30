import 'package:pub_semver/pub_semver.dart';

import '../model/errors.dart';
import '../model/release.dart';
import 'pub_dev.dart';

class ReleaseCheck {
  final PubDevClient pubDev;
  final Version current;
  ReleaseCheck(this.pubDev, {required this.current});

  static const package = 'dartvulncheck';

  // Returned, not thrown: a failed lookup of the tool's own release says
  // nothing about the project being checked, so it must never reach the
  // exit code.
  Future<ReleaseStatus> status() async {
    final Version? latest;
    try {
      latest = await pubDev.latestVersion(package);
    } on VulncheckException catch (e) {
      return ReleaseUnknown(e);
    }
    if (latest == null) {
      return const ReleaseUnknown(UnexpectedResponse(
          PubDevClient.sourceName, 'no release of $package is listed'));
    }
    return latest > current ? NewerRelease(latest) : const UpToDate();
  }
}
