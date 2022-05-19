# Package

version       = "0.1.0"
author        = "Status Research & Development GmbH"
description   = "Self-hosted fuzzing daemon"
license       = "MIT"
srcDir        = "src"
bin           = @["defuzze"]


# Dependencies

requires "nim >= 1.6.6",
         "yaml == 0.16.0"
