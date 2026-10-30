import 'dart:io';

import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:http/http.dart' as http;

Future<void> main(List<String> arguments) async {
  final client = http.Client();
  try {
    exitCode = await Runner(
      client: client,
      environment: Platform.environment,
      out: stdout,
      err: stderr,
    ).run(arguments);
  } finally {
    client.close();
  }
  await Future.wait([stdout.flush(), stderr.flush()]);
}
