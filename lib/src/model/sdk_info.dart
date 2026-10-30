import 'package:pub_semver/pub_semver.dart';

class SdkInfo {
  final Version? flutter;
  final Version? dart;
  final String? channel;
  final String origin;

  const SdkInfo({this.flutter, this.dart, this.channel, required this.origin});

  bool get isEmpty => flutter == null && dart == null;

  @override
  String toString() {
    final parts = <String>[
      if (flutter != null)
        'Flutter $flutter${channel == null ? '' : ' $channel'}',
      if (dart != null) 'Dart $dart',
    ];
    return parts.join(' / ');
  }
}
