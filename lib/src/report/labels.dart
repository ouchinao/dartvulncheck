import '../model/sdk_info.dart';

// Shared by the text and JSON reports, so the two never drift apart.
String sdkLabel(SdkInfo info) => [
      if (info.flutter != null)
        'Flutter ${info.flutter}'
            '${info.channel == null ? '' : ' ${info.channel}'}',
      if (info.dart != null) 'Dart ${info.dart}',
    ].join(' / ');

String sdkOriginLabel(SdkOrigin origin) => switch (origin) {
      SdkOrigin.override => '--sdk-version',
      SdkOrigin.fvmrc => '.fvmrc',
      SdkOrigin.fvmConfig => 'fvm_config.json',
      SdkOrigin.flutterCommand => 'flutter --version',
      SdkOrigin.dartCommand => 'dart --version',
    };
