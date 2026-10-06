import std/httpclient except Proxy
import prx

let p = proxy("socks5://127.0.0.1:1080")

# scoped usage with automatic lifecycle cleanup
withProxy(p, proc(client: HttpClient) =
  try:
    echo client.getContent("https://httpbin.org/ip")
  except CatchableError as e:
    echo "request error: ", e.msg
)

# standalone client instance with explicit lifecycle
let adapter = startAdapter(p)
let client = newHttpClient(adapter)
try:
  echo client.getContent("https://httpbin.org/user-agent")
except CatchableError as e:
  echo "request error: ", e.msg
finally:
  client.close()
  adapter.stop()
