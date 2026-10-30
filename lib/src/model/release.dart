import 'package:pub_semver/pub_semver.dart';

import 'errors.dart';

// Three cases, not a nullable version: null would mean both "up to date"
// and "could not tell", and only the second is worth a --verbose line.
sealed class ReleaseStatus {
  const ReleaseStatus();
}

class NewerRelease extends ReleaseStatus {
  final Version latest;
  const NewerRelease(this.latest);
}

class UpToDate extends ReleaseStatus {
  const UpToDate();
}

class ReleaseUnknown extends ReleaseStatus {
  final VulncheckException cause;
  const ReleaseUnknown(this.cause);
}
