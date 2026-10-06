import std/asyncdispatch
import prx

proc main() {.async.} =
  # chain traffic through multiple hops across different protocols
  let chain = [
    proxy("http://127.0.0.1:8080"),
    proxy("socks5://alice:secret@127.0.0.1:1080"),
    proxy("socks4://127.0.0.1:1081")
  ]

  try:
    let sock = await dialAsync(chain, "example.com", Port(80))
    await sock.send("HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    let head = await sock.recvLine()
    echo "received via chain: ", head
    sock.close()
  except CatchableError as e:
    echo "chain connection error: ", e.msg

waitFor main()
