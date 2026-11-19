version       = "0.1.0"
author        = "badinteger"
description   = "universal proxy client and server library for Nim"
license       = "MIT"
skipDirs      = @["tests", "examples"]

requires "nim >= 2.0.0"

task test, "run the test suite with and without ssl":
  exec "nim r -p:. tests/test.nim"
  exec "nim r -p:. -d:ssl tests/test.nim"
