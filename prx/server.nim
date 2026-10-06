import std/[net, asyncnet, asyncdispatch, strutils, uri, base64]
import types, common, dialer, tunnel, udp

type
  ServerKind* = enum
    skAuto
    skSocks5
    skSocks4
    skHttp

  AuthHandler* = proc(user, pass: string): bool {.closure, gcsafe.}
  FilterHandler* = proc(host: string, port: Port): bool {.closure, gcsafe.}
  LogHandler* = proc(msg: string) {.closure, gcsafe.}


  ProxyServer* = ref object
    kind*: ServerKind
    bindAddr*: string
    port*: Port
    upstream*: Proxy
    authProc*: AuthHandler
    filterProc*: FilterHandler
    logProc*: LogHandler
    running*: bool
    socket*: AsyncSocket
    activeConnections*: int
    totalConnections*: int
    totalBytesSent*: int64
    totalBytesRecv*: int64

proc log(server: ProxyServer, msg: string) =
  if not server.logProc.isNil:
    server.logProc(msg)

proc newServer*(
  port: Port = Port(1080),
  bindAddr = "127.0.0.1",
  kind = skAuto,
  upstream: Proxy = nil
): ProxyServer =
  ProxyServer(
    kind: kind,
    bindAddr: bindAddr,
    port: port,
    upstream: upstream,
    running: false
  )

proc setAuth*(server: ProxyServer, username, password: string) =
  server.authProc = proc(u, p: string): bool =
    u == username and p == password

proc setAuth*(server: ProxyServer, handler: AuthHandler) =
  server.authProc = handler

proc setFilter*(server: ProxyServer, handler: FilterHandler) =
  server.filterProc = handler

proc setLogger*(server: ProxyServer, handler: LogHandler) =
  server.logProc = handler

proc connectTarget(server: ProxyServer, host: string, port: Port): Future[AsyncSocket] {.async.} =
  if not server.upstream.isNil:
    result = await dialAsync(server.upstream, host, port)
  else:
    result = await asyncnet.dial(host, port, buffered = false)

proc recvNullTerminated(sock: AsyncSocket): Future[string] {.async.} =
  result = ""
  while true:
    let b = await recvExact(sock, 1)
    if b[0] == '\x00':
      break
    result.add(b[0])

proc handleSocks5Udp(server: ProxyServer, client: AsyncSocket) {.async.} =
  let relaySock = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  relaySock.bindAddr(Port(0), server.bindAddr)
  let boundPort = relaySock.getLocalAddr()[1]

  server.log("socks5 udp associate listening on " & server.bindAddr & ":" & $boundPort.int)

  # reply success with bound address and port
  let pBytes = boundPort.toBytes
  var reply = "\x05\x00\x00\x01"
  if isIpv4(server.bindAddr) and server.bindAddr != "0.0.0.0":
    let ip = parseIpAddress(server.bindAddr)
    for b in ip.address_v4: reply.add(b.char)
  else:
    reply.add("\x7F\x00\x00\x01")
  reply.add(pBytes[0].char)
  reply.add(pBytes[1].char)
  await client.send(reply)

  var clientUdpAddr = ""
  var clientUdpPort = Port(0)
  var running = true

  let outSock = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  outSock.bindAddr(Port(0), "127.0.0.1")

  # pump responses back to client
  proc pumpResponses(): Future[void] {.async.} =
    while running:
      try:
        let dg = await outSock.recvDatagram()
        if clientUdpAddr.len > 0 and clientUdpPort.int > 0:
          let pkt = encodeUdpPacket(dg.address, dg.port, dg.data)
          await relaySock.sendTo(clientUdpAddr, clientUdpPort, pkt)
          server.totalBytesSent += pkt.len
      except CatchableError:
        break

  # pump client packets to target
  proc pumpIncoming(): Future[void] {.async.} =
    while running:
      try:
        let dg = await relaySock.recvDatagram()
        clientUdpAddr = dg.address
        clientUdpPort = dg.port
        let (destHost, destPort, payload) = decodeUdpPacket(dg.data)
        if not server.filterProc.isNil and not server.filterProc(destHost, destPort):
          continue
        await outSock.sendTo(destHost, destPort, payload)
        server.totalBytesRecv += dg.data.len
      except CatchableError:
        break

  asyncCheck pumpResponses()
  asyncCheck pumpIncoming()

  # wait until client closes tcp connection
  while true:
    let b = await client.recv(1)
    if b.len == 0:
      break

  running = false
  relaySock.close()
  outSock.close()

proc handleSocks5(server: ProxyServer, client: AsyncSocket) {.async.} =
  let nmethods = (await recvExact(client, 1))[0].int
  let methods = await recvExact(client, nmethods)

  let needAuth = not server.authProc.isNil
  if needAuth:
    if '\x02' notin methods:
      await client.send("\x05\xFF")
      return
    await client.send("\x05\x02")

    # read auth subnegotiation
    let ver = await recvExact(client, 1)
    if ver[0] != '\x01':
      await client.send("\x01\x01")
      return
    let ulen = (await recvExact(client, 1))[0].int
    let uname = await recvExact(client, ulen)
    let plen = (await recvExact(client, 1))[0].int
    let passwd = await recvExact(client, plen)

    if not server.authProc(uname, passwd):
      await client.send("\x01\x01")
      return
    await client.send("\x01\x00")
  else:
    if '\x00' notin methods:
      await client.send("\x05\xFF")
      return
    await client.send("\x05\x00")

  # read connect command
  let reqHead = await recvExact(client, 4)
  if reqHead[0] != '\x05' or (reqHead[1] != '\x01' and reqHead[1] != '\x03'):
    # command not supported
    await client.send("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
    return

  let cmd = reqHead[1]

  var targetHost = ""
  let atyp = reqHead[3].byte
  case atyp
  of 0x01:
    let ipBytes = await recvExact(client, 4)
    targetHost = $ipBytes[0].int & "." & $ipBytes[1].int & "." & $ipBytes[2].int & "." & $ipBytes[3].int
  of 0x03:
    let dlen = (await recvExact(client, 1))[0].int
    targetHost = await recvExact(client, dlen)
  of 0x04:
    let ipBytes = await recvExact(client, 16)
    var parts: seq[string] = @[]
    for i in countup(0, 14, 2):
      let val = (ipBytes[i].int shl 8) or ipBytes[i + 1].int
      parts.add(toHex(val, 1).toLowerAscii)
    targetHost = parts.join(":")
  else:
    await client.send("\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
    return

  let portBytes = await recvExact(client, 2)
  let targetPort = toPort(portBytes[0].byte, portBytes[1].byte)

  if cmd == '\x03':
    await handleSocks5Udp(server, client)
    return

  if not server.filterProc.isNil and not server.filterProc(targetHost, targetPort):
    await client.send("\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
    return

  server.log("socks5 connect " & targetHost & ":" & $targetPort.int)

  var targetSock: AsyncSocket
  try:
    targetSock = await server.connectTarget(targetHost, targetPort)
  except CatchableError as e:
    server.log("socks5 dial error " & e.msg)
    await client.send("\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
    return

  # send connection success
  await client.send("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

  let (sent, recv) = await pipe(client, targetSock)
  server.totalBytesSent += sent
  server.totalBytesRecv += recv

proc handleSocks4(server: ProxyServer, client: AsyncSocket) {.async.} =
  let cmd = (await recvExact(client, 1))[0].byte
  if cmd != 0x01:
    await client.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
    return

  let portBytes = await recvExact(client, 2)
  let targetPort = toPort(portBytes[0].byte, portBytes[1].byte)
  let ipBytes = await recvExact(client, 4)
  let userId = await recvNullTerminated(client)

  if not server.authProc.isNil and not server.authProc(userId, ""):
    await client.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
    return

  var targetHost = ""
  # check socks4a domain extension
  if ipBytes[0] == '\x00' and ipBytes[1] == '\x00' and ipBytes[2] == '\x00' and ipBytes[3] != '\x00':
    targetHost = await recvNullTerminated(client)
  else:
    targetHost = $ipBytes[0].int & "." & $ipBytes[1].int & "." & $ipBytes[2].int & "." & $ipBytes[3].int

  if not server.filterProc.isNil and not server.filterProc(targetHost, targetPort):
    await client.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
    return

  server.log("socks4 connect " & targetHost & ":" & $targetPort.int)

  var targetSock: AsyncSocket
  try:
    targetSock = await server.connectTarget(targetHost, targetPort)
  except CatchableError as e:
    server.log("socks4 dial error " & e.msg)
    await client.send("\x00\x5B\x00\x00\x00\x00\x00\x00")
    return

  # send socks4 success
  await client.send("\x00\x5A\x00\x00\x00\x00\x00\x00")

  let (sent, recv) = await pipe(client, targetSock)
  server.totalBytesSent += sent
  server.totalBytesRecv += recv

proc checkHttpAuth(server: ProxyServer, headers: seq[(string, string)]): bool =
  if server.authProc.isNil:
    return true
  for (k, v) in headers:
    if k.toLowerAscii == "proxy-authorization":
      let parts = v.strip.split(' ', 1)
      if parts.len == 2 and parts[0].toLowerAscii == "basic":
        try:
          let decoded = decode(parts[1].strip)
          let creds = decoded.split(':', 1)
          let u = creds[0]
          let p = if creds.len > 1: creds[1] else: ""
          return server.authProc(u, p)
        except CatchableError:
          return false
  return false

proc handleHttp(server: ProxyServer, client: AsyncSocket, initialChar: char) {.async.} =
  let restOfLine = await client.recvLine
  let firstLine = initialChar & restOfLine

  var headers: seq[(string, string)] = @[]
  while true:
    let line = await client.recvLine
    if line.strip.len == 0:
      break
    let parts = line.split(':', 1)
    if parts.len == 2:
      headers.add((parts[0].strip, parts[1].strip))

  if not server.checkHttpAuth(headers):
    await client.send("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"prx\"\r\nContent-Length: 0\r\n\r\n")
    return

  let reqParts = firstLine.strip.split(' ', 2)
  if reqParts.len < 2:
    return

  let httpMethod = reqParts[0].toUpperAscii
  let targetUri = reqParts[1]

  if httpMethod == "CONNECT":
    let hp = targetUri.split(':', 1)
    let targetHost = hp[0]
    let targetPort = if hp.len > 1: Port(parseInt(hp[1])) else: Port(443)

    if not server.filterProc.isNil and not server.filterProc(targetHost, targetPort):
      await client.send("HTTP/1.1 403 Forbidden\r\n\r\n")
      return

    server.log("http connect " & targetHost & ":" & $targetPort.int)

    var targetSock: AsyncSocket
    try:
      targetSock = await server.connectTarget(targetHost, targetPort)
    except CatchableError as e:
      server.log("http dial error " & e.msg)
      await client.send("HTTP/1.1 502 Bad Gateway\r\n\r\n")
      return

    # send connection established
    await client.send("HTTP/1.1 200 Connection Established\r\n\r\n")

    let (sent, recv) = await pipe(client, targetSock)
    server.totalBytesSent += sent
    server.totalBytesRecv += recv
  else:
    # forward plain http proxy request
    let u = parseUri(targetUri)
    let targetHost = u.hostname
    let targetPort = if u.port.len > 0: Port(parseInt(u.port)) else: Port(80)

    if not server.filterProc.isNil and not server.filterProc(targetHost, targetPort):
      await client.send("HTTP/1.1 403 Forbidden\r\n\r\n")
      return

    var targetSock: AsyncSocket
    try:
      targetSock = await server.connectTarget(targetHost, targetPort)
    except CatchableError as e:
      server.log("http forward dial error " & e.msg)
      await client.send("HTTP/1.1 502 Bad Gateway\r\n\r\n")
      return

    let path = if u.path.len == 0: "/" else: u.path
    let pathQuery = if u.query.len > 0: path & "?" & u.query else: path
    var fwd = httpMethod & " " & pathQuery & " HTTP/1.1\r\n"
    for (k, v) in headers:
      let lk = k.toLowerAscii
      if lk != "proxy-authorization" and lk != "proxy-connection":
        fwd.add(k & ": " & v & "\r\n")
    fwd.add("\r\n")

    await targetSock.send(fwd)

    let (sent, recv) = await pipe(client, targetSock)
    server.totalBytesSent += sent
    server.totalBytesRecv += recv

proc handleClient(server: ProxyServer, client: AsyncSocket) {.async.} =
  inc server.totalConnections
  inc server.activeConnections

  try:
    let firstByte = await recvExact(client, 1)
    if firstByte.len == 0:
      client.close
      return

    case server.kind
    of skSocks5:
      if firstByte[0] == '\x05':
        await handleSocks5(server, client)
    of skSocks4:
      if firstByte[0] == '\x04':
        await handleSocks4(server, client)
    of skHttp:
      await handleHttp(server, client, firstByte[0])
    of skAuto:
      # detect protocol from first byte
      case firstByte[0]
      of '\x05':
        await handleSocks5(server, client)
      of '\x04':
        await handleSocks4(server, client)
      else:
        await handleHttp(server, client, firstByte[0])
  except CatchableError as e:
    server.log("client error " & e.msg)
  finally:
    dec server.activeConnections
    client.close

proc start*(server: ProxyServer): Future[void] {.async.} =
  server.socket = newAsyncSocket(buffered = false)
  server.socket.setSockOpt(OptReuseAddr, true)
  server.socket.bindAddr(server.port, server.bindAddr)
  server.socket.listen()
  server.port = server.socket.getLocalAddr()[1]
  server.running = true
  server.log("proxy server listening on " & server.bindAddr & ":" & $server.port.int)

  while server.running:
    try:
      let client = await server.socket.accept()
      asyncCheck handleClient(server, client)
    except CatchableError as e:
      if not server.running:
        break
      server.log("accept error " & e.msg)

proc stop*(server: ProxyServer) =
  server.running = false
  if not server.socket.isNil:
    server.socket.close()
