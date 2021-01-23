packageName   = "nimAES"
version       = "0.1.2"
author        = "Andri Lim"
description   = "AES encryption algorithm"
license       = "MIT"
skipDirs     = @["tests", "docs"]

requires: "nim >= 1.0.6"

### Helper functions
proc test(env, path: string) =
  # Compilation language is controlled by TEST_LANG
  var lang = "c"
  if existsEnv"TEST_LANG":
    lang = getEnv"TEST_LANG"

  exec "nim " & lang & " " & env &
    " -r --hints:off --warnings:off " & path

task test, "Run tests":
  exec "nim -v"
  test "-d:release", "tests/test"
  # exec "nim c -r --gc:arc -d:release tests/test"

task testvcc, "Run tests":
  test "-d:release", "tests/test"
