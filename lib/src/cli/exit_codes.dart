// 3, not 2: it matches govulncheck, so mixed Go/Dart CI needs no mapping.
// 1 and 3 stay apart so "could not check" never reads as either answer.
abstract final class ExitCodes {
  static const ok = 0;
  static const error = 1;
  static const vulnerable = 3;
}
