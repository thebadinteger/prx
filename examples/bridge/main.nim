import std/asyncdispatch
import prx

proc main() {.async.} =
  let upstream = proxy("socks5://127.0.0.1:1080")

  # create a local tcp bridge on 127.0.0.1:9000 forwarding to example.com:80
  echo "local bridge listening on 127.0.0.1:9000 -> forwarding via socks5"
  await startBridge(Port(9000), upstream, "example.com", Port(80))

waitFor main()
