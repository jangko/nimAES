packageName   = "nimAES"
version       = "0.1.2"
author        = "Andri Lim"
description   = "AES encryption algorithm"
license       = "MIT"
skipDirs     = @["tests", "docs"]

requires: "nim >= 1.0.6"

task tests, "Run tests":
  exec "nim -v"
  exec "nim c -r -d:release tests/test"
  # exec "nim c -r --gc:arc -d:release tests/test"
