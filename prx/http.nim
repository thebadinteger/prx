import std/[net, asyncnet, asyncdispatch, strutils, base64]
import types, hostport, wire

const
  maxHeaderLine = 8192
  maxHeaderCount = 128

proc buildConnectRequest*(proxy: Proxy, targetHost: string, targetPort: Port): string =
  checkHost(stripBrackets(targetHost))
  let target = joinHostPort(targetHost, targetPort)
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
  if parts.len < 2 or not parts[0].startsWith("HTTP/"):
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

proc connectThrough(
  sock: Socket | AsyncSocket,
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  timeout: int
): Future[void] {.multisync.} =
  await sock.send(buildConnectRequest(proxy, targetHost, targetPort))

  let statusLine = await recvLineN(sock, maxHeaderLine, timeout)
  if statusLine.strip.len == 0:
    raise newException(ProxyConnectError, "empty response from http proxy")

  let code = parseStatusCode(statusLine)

  # drain response headers
  var count = 0
  while true:
    let line = await recvLineN(sock, maxHeaderLine, timeout)
    if line.len == 0:
      raise newException(ProxyConnectError, "http proxy closed the connection mid response")
    if line == "\r\n":
      break
    inc count
    if count > maxHeaderCount or line.len >= maxHeaderLine:
      raise newException(ProxyProtocolError, "http proxy response headers too large")

  checkStatus(code, statusLine)

proc handshake*(sock: Socket, proxy: Proxy, targetHost: string, targetPort: Port, timeout = -1) =
  connectThrough(sock, proxy, targetHost, targetPort, timeout)

proc handshake*(sock: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port): Future[void] =
  connectThrough(sock, proxy, targetHost, targetPort, -1)
