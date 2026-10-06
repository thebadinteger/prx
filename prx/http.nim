import std/[net, asyncnet, asyncdispatch, strutils, base64]
import types

proc buildConnectRequest*(proxy: Proxy, targetHost: string, targetPort: Port): string =
  let target = targetHost & ":" & $targetPort.int
  result = "CONNECT " & target & " HTTP/1.1\r\n"
  result.add("Host: " & target & "\r\n")
  result.add("Proxy-Connection: Keep-Alive\r\n")
  result.add("User-Agent: prx\r\n")

  if proxy.username.len > 0 or proxy.password.len > 0:
    let credentials = encode(proxy.username & ":" & proxy.password)
    result.add("Proxy-Authorization: Basic " & credentials & "\r\n")

  result.add("\r\n")

proc parseStatusCode(statusLine: string): int =
  let parts = statusLine.strip.split(' ', 2)
  if parts.len < 2:
    raise newException(ProxyProtocolError, "invalid http response " & statusLine)
  try:
    parseInt(parts[1])
  except ValueError:
    raise newException(ProxyProtocolError, "invalid http status code " & parts[1])

proc checkStatus(code: int, statusLine: string) =
  if code == 407:
    raise newException(ProxyAuthError, "proxy authentication required")
  if code < 200 or code >= 300:
    raise newException(ProxyConnectError, "http tunnel failed with " & statusLine)

proc handshake*(sock: Socket, proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1) =
  let req = buildConnectRequest(proxy, targetHost, targetPort)
  sock.send(req)

  let statusLine = sock.recvLine(timeout)
  if statusLine.strip.len == 0:
    raise newException(ProxyConnectError, "empty response from http proxy")

  let code = parseStatusCode(statusLine)

  # drain response headers
  while true:
    let line = sock.recvLine(timeout)
    if line.strip.len == 0:
      break

  checkStatus(code, statusLine)

proc handshake*(sock: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port): Future[void] {.async.} =
  let req = buildConnectRequest(proxy, targetHost, targetPort)
  await sock.send(req)

  let statusLine = await sock.recvLine
  if statusLine.strip.len == 0:
    raise newException(ProxyConnectError, "empty response from http proxy")

  let code = parseStatusCode(statusLine)

  # drain response headers
  while true:
    let line = await sock.recvLine
    if line.strip.len == 0:
      break

  checkStatus(code, statusLine)
