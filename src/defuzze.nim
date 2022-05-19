import os, tables, sugar, strtabs, sequtils, strutils, strscans, times
import asyncdispatch, asynctools/[asyncproc, asyncpipe]
import chronicles
import yaml/serialization, streams

type
  DefuzzeEnv* = object
    setup* {.defaultVal: "".}: string
    teardown* {.defaultVal: "".}: string
    commandPrefix* {.defaultVal: "".}: string

  DefuzzeTarget* = object
    git_url*: string
    git_branch*: string
    folder*: string
    envs*: seq[string]

  DefuzzeConfig* = object
    errorHook*: string
    recoverHook*: string
    workingDir*: string
    workingDirPermission {.transient.}: set[FilePermission]
    environments*: Table[string, DefuzzeEnv]
    targets*: Table[string, DefuzzeTarget]
    period* {.defaultVal: 60.}: int

proc getConf: DefuzzeConfig =
  if paramCount() != 1:
    quit "usage: defuzze [yaml config file]"
  var res: DefuzzeConfig
  let s = newFileStream(paramStr(1))
  load(s, res)
  s.close
  res

proc createDir(c: DefuzzeConfig, path: string) =
  createDir(path)
  setFilePermissions(path, c.workingDirPermission)

proc pollForExit(p: AsyncProcess): Future[int] {.async.} =
  # waitForExit fails, sometimes
  while p.running:
    await sleepAsync(1)
  return p.peekExitCode()

proc execProcess(command, dir: string, timeout: TimeInterval = 10.minutes, args: seq[string] = @[],
           env: StringTableRef = nil,
           options: set[ProcessOption] = {poStdErrToStdOut, poUsePath,
                                          poEvalCommand}
          ): Future[(seq[string], int)] {.async.} =
  let
    bufferSize = 1024
    p = startProcess(command, dir, args = args, env = env, options = options)
    start = now()
  var data = newString(bufferSize)
  var output: string

  trace "process started", command
  while start + timeout > now():
    let res = await p.outputHandle.readInto(addr data[0], bufferSize)
    if res > 0:
      data.setLen(res)
      output &= data
      data.setLen(bufferSize)
    else:
      break
  if p.running:
    # timed out
    p.kill()
  let exitcode = await p.pollForExit()
  close(p)
  return (output.split("\n"), exitcode)

proc createCommand(env: DefuzzeEnv, command: string): string =
  if env.commandPrefix.len > 0:
    env.commandPrefix.replace("$COMMAND", command)
  else:
    command

proc parseLibfuzzLine(s: string, errorFile: var string) =
  trace "line", s
  if s.startsWith("INFO:"): return

  if s.startsWith("##") or "Uses: " in s:
    # Recommended dictionary
    return
  if "NEW_FUNC" in s:
    return

  if s.startsWith("Done"):
    debug "Done!"
    return

  if s.startsWith("#"):
    var iterations, cov, ft, corpn, corps, limit, execs, rss: int
    var operation: string
    let fmted = s.splitWhitespace().join(" ")
    if not
      fmted.scanf("#$i $w cov: $i ft: $i corp: $i/$ib lim: $i exec/s: $i rss: $iMb", iterations, operation, cov, ft, corpn, corps, limit, execs, rss):
      echo "noo"
      echo fmted
    #else:
    #  trace "#", iterations, cov, corpn, execs
    return

  if "Test unit written to" in s:
    errorFile = s.splitWhitespace()[^1]
    return
  info "Unparsable string", s

proc getErrorFile(ss: seq[string]): string =
  for s in ss:
    parseLibfuzzLine(s, result)

proc executeFuzz(env: DefuzzeEnv, binary: string, corpuses: seq[string], duration: Duration, envVar: StringTableRef): Future[(int, seq[string])] {.async.} =
  #process = startProcess(wrappedCommand, parentDir(binary), env=envVar, options = {poEvalCommand, poStdErrToStdOut})
  logScope: binary
  let
    command =
      binary & " -timeout=20 -max_total_time=" & $duration.inSeconds & " -artifact_prefix=" & corpuses[0] & "/ " & corpuses.join(" ") #& $duration.seconds
    wrappedCommand = env.createCommand(command)
    bufferSize = 1024
    p = startProcess(wrappedCommand, env = envVar, options = {poEvalCommand, poStdErrToStdOut})
    start = now()
  var data = newString(bufferSize)
  var output: string
  var resultLines: seq[string]

  trace "process started", wrappedCommand
  while true:
    let res = await p.outputHandle.readInto(addr data[0], bufferSize)
    if res > 0:
      data.setLen(res)
      output &= data
      while '\n' in output:
        let pos = output.find('\n')
        resultLines.add(output[0..<pos])
        output = output[pos+1 .. ^1]
      data.setLen(bufferSize)

      if resultLines.len > 150:
        resultLines = resultLines[^100..^1]
    else:
      break
  let exitcode = await p.pollForExit()
  close(p)
  return (exitcode, resultLines)

proc testFailure(env: DefuzzeEnv, binary, failure: string, tries: int, envVar: StringTableRef): Future[int] {.async.} =
  for i in 0..<tries:
    let res = await executeFuzz(env, binary, @[failure], initDuration(minutes=1), envVar)

    if res[0] != 0:
      inc(result)

proc runFuzz(c: DefuzzeConfig, env: DefuzzeEnv, target, binary: string, corpuses: seq[string], duration: Duration, envVar: StringTableRef): Future[int] {.async.} =

  # workaround nim compiler crash
  let ffff = toSeq(walkDir(corpuses[0]))
  for f in ffff:
    if "-" in f.path.lastPathPart:
      let fullPath = absolutePath(f.path, corpuses[0])
      debug "Already existing crash for target"
      let tries = await testFailure(env, binary, fullPath, 100, envVar)

      if tries == 0:
        debug "Recovered!"
        discard await execProcess(c.recoverHook, "", env= {
          "TARGET": target,
          "BINARY": binary.lastPathPart,
          "FILE": f.path.lastPathPart
        }.newStringTable())

        let newPosition = f.path.split('-')[^1].absolutePath(corpuses[0])
        moveFile(fullPath, newPosition)
      else:
        debug "Still susceptible to crash.."
        return 1
  while true:
    let r = await executeFuzz(env, binary, corpuses, duration, envVar)

    if r[0] != 0:
      let file = getErrorFile(r[1])
      if file.len == 0:
        warn "Can't extract error file!", logs=r[1]
        # something probably went wrong
        return r[0]
      else:
        warn "Failed, testing reprodacibility", file=file
        let reproducability = await testFailure(env, binary, file, 100, envVar)
        warn "Failed!", binary, file, reproducability, logs=r[1]

        discard await execProcess(c.errorHook, "", env= {
          "TARGET": target,
          "BINARY": binary.lastPathPart,
          "FILE": file,
          "REPRO": $reproducability & "/100"
        }.newStringTable())

        if reproducability > 0:
          return r[0]
    else:
      return r[0]
  

proc mergeFuzz(c: DefuzzeConfig, env: DefuzzeEnv, binary, corpus: string, envVar: StringTableRef) {.async.} =
  let
    mergedDir = corpus & "_MERGED"
    command = binary & " -merge=1 " & mergedDir & " " & corpus

  createDir(c, mergedDir)
  let res = await execProcess(env.createCommand(command), "", 20.minutes, env=envVar)
  if res[1] != 0:
    warn "Failed to compress corpus!", logs=res[0]
    removeDir(mergedDir)
    return
  removeDir(corpus)
  moveDir(mergedDir, corpus)

proc runTarget(c: DefuzzeConfig, targetName, envName: string) {.async.} =
  logScope:
    targetName
    envName
  let
    target = c.targets[targetName]
    env = c.environments[envName]
    uniqueName = targetName & "-" & envName
    buildStartTime = now()

    sourcesDir = c.workingDir / "repos" / targetName
    fuzzingDir = sourcesDir / target.folder
    binDir = c.workingDir / "bin" / uniqueName
    corpusDir = c.workingDir / "corpus" / uniqueName
    targetCorpusDir = c.workingDir / "corpus" / targetName

    envVar = {
      "NAME": uniqueName,
      "WORK": c.workingDir,
      "SOURCES": sourcesDir,
      "BIN": binDir
    }.newStringTable

  debug "Env vars", envVar
  removeDir(binDir)
  createDir(c, binDir)

  let setup = @[
    execProcess(env.setup, c.workingDir, env=envVar),
  ]
  discard await all(setup)

  var setupSuccess = true
  for c in setup:
    let setupStep = await c

    if setupStep[1] != 0:
      warn "Failed setup step!", logs=setupStep[0]
      setupSuccess = false

  if setupSuccess:
    debug "setup finished"
    let buildScripts = toSeq(walkPattern(fuzzingDir / "build*"))
    if buildScripts.len != 1:
      warn "Expected one build script, found: ", buildScripts
    else:
      let buildScript = buildScripts[0]

      let buildResult = await execProcess(env.createCommand(buildScript), fuzzingDir, 5.minutes, env=envVar)

      if buildResult[1] != 0:
        warn "Failed to build a target!", log=buildResult[0]
      else:
        let binaries = collect:
          for f in walkDir(binDir):
            if f.kind == pcFile and fpOthersExec in getFilePermissions(f.path):
              f.path.lastPathPart
        
        debug "Binaries", binaries

        let runTime = initDuration(minutes=c.period) - (now() - buildStartTime)
        let futs = collect:
          for b in binaries:
            let subCorpusDir = corpusDir / b
            createDir(c, subCorpusDir)
            {b: c.runFuzz(env, targetName, absolutePath(b, binDir), @[subCorpusDir], runTime, envVar)}

        discard await all(toSeq(futs.values))
        debug "Finished running fuzzing"

        let cfuts = collect:
          for b, fut in futs:
            let res = await fut
            if res == 0:
              debug "Merging corpus", b

              let subCorpusDir = corpusDir / b
              mergeFuzz(c, env, absolutePath(b, binDir), subCorpusDir, envVar)

        await all(cfuts)
        debug "Finished merging"

  let cleanup = await execProcess(env.teardown, c.workingDir, 5.minutes, env=envVar)
  if cleanup[1] != 0:
    warn "Failed to cleanup!", logs=cleanup[0]

proc handleTarget(c: DefuzzeConfig, targetName: string) {.async.} =
  let
    target = c.targets[targetName]
    sourcesDir = c.workingDir / "repos" / targetName

  let cloneRes =
    if dirExists(sourcesDir):
      await execProcess("git fetch && git checkout origin/" & target.git_branch, sourcesDir)
    else:
      await execProcess("git clone --branch " & target.git_branch & " " & target.git_url & " " & targetName, c.workingDir / "repos")

  if cloneRes[1] != 0:
    warn "Failed to clone repo!", logs=cloneRes[0]
    return

  let futs = collect:
    for env in target.envs:
      if env notin c.environments:
        warn "Missing environment: ", env
        continue
      c.runTarget(targetName, env)
  await all(futs)

proc main {.async.} =
  while true:
    var conf = getConf()
    conf.workingDir = absolutePath(conf.workingDir)
    createDir(conf.workingDir)
    conf.workingDirPermission = getFilePermissions(conf.workingDir)
    createDir(conf, conf.workingDir / "repos")
    createDir(conf, conf.workingDir / "bin")
    createDir(conf, conf.workingDir / "corpus")

    var futs = collect():
      for target, _ in conf.targets:
        handleTarget(conf, target)
    await all(futs)

    await sleepAsync(10_000)

when isMainModule:
  waitFor(main())
