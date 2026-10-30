import '../model/sdk_info.dart';

// One mapping, not one per report: five strings in two places drift apart.
String sdkOriginLabel(SdkOrigin origin) => switch (origin) {
      SdkOrigin.override => '--sdk-version',
      SdkOrigin.fvmrc => '.fvmrc',
      SdkOrigin.fvmConfig => 'fvm_config.json',
      SdkOrigin.flutterCommand => 'flutter --version',
      SdkOrigin.dartCommand => 'dart --version',
    };
