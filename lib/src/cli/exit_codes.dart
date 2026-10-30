import '../check/result.dart';
import '../model/severity.dart';

// 3, not 2: it matches govulncheck, so mixed Go/Dart CI needs no mapping.
// 1 and 3 stay apart so "could not check" never reads as either answer.
abstract final class ExitCodes {
  static const ok = 0;
  static const error = 1;
  static const vulnerable = 3;
}

// Decided in cli/, not in report/: it is a policy of this command, and the
// report only describes what was found.
int exitCodeFor(CheckResult result,
    {required Severity failOn, required bool strict}) {
  if (result.hasErrors) return ExitCodes.error;
  final failing =
      result.findings.any((f) => f.counts(failOn: failOn, strict: strict));
  return failing ? ExitCodes.vulnerable : ExitCodes.ok;
}
