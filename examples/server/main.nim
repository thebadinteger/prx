import std/asyncdispatch
import prx

# combo server supporting socks5 socks4 and http on port 8080
let srv = server(Port(8080), bindAddr = "127.0.0.1", kind = skAuto)

# optional authentication
srv.setAuth("admin", "secret123")

# optional logging callback
srv.setLogger(proc(msg: string) =
  echo "[prx server] ", msg
)

echo "starting unified proxy server on 127.0.0.1:8080"
waitFor srv.start()
