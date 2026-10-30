import 'dart:convert';
import 'dart:io';

class ProcessOutput {
  final int exitCode;
  final String stdout;
  final String stderr;
  const ProcessOutput(this.exitCode, this.stdout, this.stderr);
}

abstract class ProcessRunner {
  Future<ProcessOutput?> run(String executable, List<String> arguments,
      {String? workingDirectory});
}

class SystemProcessRunner implements ProcessRunner {
  const SystemProcessRunner();

  @override
  Future<ProcessOutput?> run(String executable, List<String> arguments,
      {String? workingDirectory}) async {
    try {
      final result = await Process.run(
        executable,
        arguments,
        workingDirectory: workingDirectory,
        // `flutter` and `dart` are .bat files on Windows.
        runInShell: Platform.isWindows,
        stdoutEncoding: utf8,
        stderrEncoding: utf8,
      );
      return ProcessOutput(
          result.exitCode, '${result.stdout}', '${result.stderr}');
    } on ProcessException {
      return null;
    }
  }
}
