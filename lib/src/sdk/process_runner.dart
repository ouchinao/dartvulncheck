import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

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
    var command = executable;
    // Located on PATH and started by full path, not by name: on Windows the
    // shell, and CreateProcess before it, look in the current directory
    // first, so a `flutter.bat` committed to the project being checked would
    // run with the user's rights.
    if (Platform.isWindows) {
      final found = findOnPath(
        executable,
        path: Platform.environment['PATH'] ?? '',
        pathExt: Platform.environment['PATHEXT'] ?? '.COM;.EXE;.BAT;.CMD',
        exists: (file) => File(file).existsSync(),
        context: p.windows,
      );
      if (found == null) return null;
      command = found;
    }
    try {
      final result = await Process.run(
        command,
        arguments,
        workingDirectory: workingDirectory,
        // A shell only on Windows, where `flutter` and `dart` are .bat files;
        // elsewhere it would only add quoting to get wrong.
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

String? findOnPath(
  String executable, {
  required String path,
  required String pathExt,
  required bool Function(String file) exists,
  p.Context? context,
}) {
  final ctx = context ?? p.context;
  // Lower-cased: PATHEXT is upper-case, the files are not, and only the
  // file system is case-insensitive.
  final extensions = [
    if (ctx.extension(executable).isNotEmpty) '',
    for (final e in pathExt.split(';'))
      if (e.isNotEmpty) e.toLowerCase(),
  ];
  for (final entry in path.split(';')) {
    final dir = entry.replaceAll('"', '').trim();
    if (dir.isEmpty) continue;
    for (final ext in extensions) {
      final candidate = ctx.join(dir, '$executable$ext');
      if (exists(candidate)) return candidate;
    }
  }
  return null;
}
