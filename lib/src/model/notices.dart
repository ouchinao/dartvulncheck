import 'package:pub_semver/pub_semver.dart';

import 'bundled_dart.dart';
import 'errors.dart';
import 'sdk_info.dart';

// Typed notices, not message strings: sdk/, sources/ and check/ say what
// happened, and only report/ decides how it reads.
sealed class Warning {
  const Warning();
}

class SdkVersionOverrideInvalid extends Warning {
  final String value;
  const SdkVersionOverrideInvalid(this.value);
}

class FlutterVersionUnreadable extends Warning {
  const FlutterVersionUnreadable();
}

class SdkNotDetected extends Warning {
  const SdkNotDetected();
}

class FvmConfigUnreadable extends Warning {
  final String path;
  const FvmConfigUnreadable(this.path);
}

class DartVersionUnknown extends Warning {
  final BundledDartMissing why;
  const DartVersionUnknown(this.why);
}

class NoGitHubToken extends Warning {
  const NoGitHubToken();
}

class FellBackToOsv extends Warning {
  final VulncheckException cause;
  const FellBackToOsv(this.cause);
}

class RepositoryLookupsFailed extends Warning {
  final int count;
  const RepositoryLookupsFailed(this.count);
}

class SdkVersionMismatch extends Warning {
  final Version chosen;
  final Version onPath;
  final SdkOrigin origin;
  const SdkVersionMismatch(
      {required this.chosen, required this.onPath, required this.origin});
}

class ThirdPartyHostedChecked extends Warning {
  final int count;
  const ThirdPartyHostedChecked(this.count);
}

class EndpointOverridden extends Warning {
  final String variable;
  final Uri url;

  // Carried on the notice, not derived from the variable's name in report/:
  // which override the token travels with is decided where the token is
  // handed out, and the wording must not claim it for the others.
  final bool carriesToken;
  const EndpointOverridden(this.variable, this.url,
      {required this.carriesToken});
}

class NewerReleaseAvailable extends Warning {
  final Version current;
  final Version latest;
  const NewerReleaseAvailable({required this.current, required this.latest});
}

sealed class LookupNote {
  final String subject;
  const LookupNote(this.subject);
}

class HostedOutsidePubDev extends LookupNote {
  const HostedOutsidePubDev(super.subject);
}

class NoGitHubRepository extends LookupNote {
  const NoGitHubRepository(super.subject);
}

class RepositoryUnreadable extends LookupNote {
  const RepositoryUnreadable(super.subject);
}

class LookupFailed extends LookupNote {
  final VulncheckException error;
  const LookupFailed(super.subject, this.error);
}

// A note, not a Warning: a redirect is GitHub's normal answer for a renamed
// or transferred repository, and a stderr line for it on every run is the
// noise #10 reports; --verbose is where "what was checked against" lives
// (R1). The subject is the owner/repo pub.dev mapped.
class RepositoryMoved extends LookupNote {
  final Uri readFrom;
  const RepositoryMoved(super.subject, this.readFrom);
}
