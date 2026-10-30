import 'errors.dart';

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
  const DartVersionUnknown();
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
