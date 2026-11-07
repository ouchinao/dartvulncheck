import 'package:pub_semver/pub_semver.dart';

import 'errors.dart';

// Found or one of three missing cases, not a nullable Version: not listed,
// not recorded and unavailable need different warning lines, and the last
// two are the ones an auditor must see (R1).
sealed class BundledDart {
  const BundledDart();
}

class BundledDartFound extends BundledDart {
  final Version dart;
  const BundledDartFound(this.dart);
}

// A sealed family of its own, not cases beside BundledDartFound: a warning
// that says the version is unknown can then carry only a reason it is.
sealed class BundledDartMissing extends BundledDart {
  const BundledDartMissing();
}

// Its own case, not Unavailable: nothing was asked, so the warning must
// not blame the manifest.
class BundledDartNotLookedUp extends BundledDartMissing {
  const BundledDartNotLookedUp();
}

class BundledDartNotListed extends BundledDartMissing {
  final Version flutter;
  const BundledDartNotListed(this.flutter);
}

// Apart from NotListed, not folded into it: the version is in the manifest
// (many releases from before 2022 are listed without a Dart SDK), so a
// reader should not go looking for a typo in the pin.
class BundledDartNotRecorded extends BundledDartMissing {
  final Version flutter;
  const BundledDartNotRecorded(this.flutter);
}

class BundledDartUnavailable extends BundledDartMissing {
  final VulncheckException cause;
  const BundledDartUnavailable(this.cause);
}
