import 'package:dartvulncheck/dartvulncheck.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  const pathExt = '.COM;.EXE;.BAT;.CMD';

  test(
      'on Windows, flutter is taken from PATH, never from the current '
      'directory', () {
    final files = {r'C:\cwd\flutter.bat', r'C:\flutter\bin\flutter.bat'};
    expect(
      findOnPath('flutter',
          path: r'C:\Windows\system32;"C:\flutter\bin"',
          pathExt: pathExt,
          exists: files.contains,
          context: p.windows),
      r'C:\flutter\bin\flutter.bat',
    );
  });

  test('an executable that is on no PATH entry is not found', () {
    expect(
      findOnPath('flutter',
          path: r'C:\Windows\system32',
          pathExt: pathExt,
          exists: {r'C:\cwd\flutter.bat'}.contains,
          context: p.windows),
      isNull,
    );
  });

  test('PATHEXT order decides between dart.exe and dart.bat', () {
    final files = {r'C:\dart\bin\dart.exe', r'C:\dart\bin\dart.bat'};
    expect(
      findOnPath('dart',
          path: r'C:\dart\bin',
          pathExt: pathExt,
          exists: files.contains,
          context: p.windows),
      r'C:\dart\bin\dart.exe',
    );
  });
}
