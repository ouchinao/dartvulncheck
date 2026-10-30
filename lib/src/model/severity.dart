// No severity computed from the CVSS vector when the source gives none:
// carrying a CVSS implementation is riskier than ranking unknown above
// critical, which fails CI instead of letting it through.
enum Severity {
  low,
  moderate,
  high,
  critical,
  unknown;

  int get rank => index;

  bool isAtLeast(Severity threshold) => rank >= threshold.rank;

  static Severity parse(Object? value) {
    if (value is! String) return Severity.unknown;
    return switch (value.trim().toLowerCase()) {
      'low' => Severity.low,
      'moderate' || 'medium' => Severity.moderate,
      'high' => Severity.high,
      'critical' => Severity.critical,
      _ => Severity.unknown,
    };
  }
}
