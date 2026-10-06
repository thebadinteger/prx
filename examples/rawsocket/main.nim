import std/net
import prx

let p = proxy("socks5://127.0.0.1:1080")

try:
  # connect raw socket through proxy to target host and port
  let sock = dial(p, "example.com", Port(80))
  sock.send("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")

  while true:
    let line = sock.recvLine()
    echo line
    if line.len == 0: break
  sock.close()
except CatchableError as e:
  echo "raw socket error: ", e.msg
