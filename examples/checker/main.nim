import std/[asyncdispatch, monotimes, times]
import prx

proc checkOne(p: Proxy, targetHost: string, targetPort: Port): Future[bool] {.async.} =
  try:
    let t0 = getMonoTime()
    let sock = await dialAsync(p, targetHost, targetPort)
    let ms = (getMonoTime() - t0).inMilliseconds
    echo "[OK] ", p, " (", ms, "ms)"
    sock.close()
    return true
  except CatchableError as e:
    echo "[FAIL] ", p, " - ", e.msg
    return false

proc main() {.async.} =
  let proxies = @[
    proxy("socks5://127.0.0.1:1080"),
    proxy("http://127.0.0.1:8080"),
    proxy("socks4://127.0.0.1:1081")
  ]

  echo "checking ", proxies.len, " proxies concurrently"
  var futures: seq[Future[bool]] = @[]
  for p in proxies:
    futures.add(checkOne(p, "example.com", Port(80)))

  for f in futures:
    discard await f

waitFor main()
