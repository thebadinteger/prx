import std/[net, asyncnet, asyncdispatch, strutils, uri, base64]
import types, common, hostport, wire, dialer, tunnel, udp

when not defined(windows):
  from std/posix import ECONNREFUSED, ENETUNREACH

const
  maxHeaderLine = 8192
  maxHeaderCount = 128
  maxSocks4Field = 255
  maxUdpFailures = 16
  acceptBackoff = 50

  repGeneralFailure = '\x01'
  repNotAllowed = '\x02'
  repNetworkUnreachable = '\x03'
  repHostUnreachable = '\x04'
  repConnectionRefused = '\x05'
  repCommandNotSupported = '\x07'
  repAddressNotSupported = '\x08'

  socks4Granted = "\x00\x5A\x00\x00\x00\x00\x00\x00"
  socks4Rejected = "\x00\x5B\x00\x00\x00\x00\x00\x00"

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
    handshakeTimeout*: int

  Connection = ref object
    sock: AsyncSocket
    negotiating: bool

  UdpSession = ref object
    server: ProxyServer
    relaySock: AsyncSocket
    outSock: AsyncSocket
    outSock6: AsyncSocket
    clientIp: IpAddress
    clientPort: Port
    active: bool

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
    running: false,
    handshakeTimeout: 30000
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

proc allowed(server: ProxyServer, host: string, port: Port): bool =
  server.filterProc.isNil or server.filterProc(host, port)

proc connectTarget(server: ProxyServer, conn: Connection, host: string, port: Port): Future[AsyncSocket] {.async.} =
  conn.negotiating = false
  if not server.upstream.isNil:
    result = await dialAsync(server.upstream, host, port)
  else:
    result = await asyncnet.dial(host, port, buffered = false)

proc relay(server: ProxyServer, conn: Connection, target: AsyncSocket, reply = "", request = "") {.async.} =
  ## Sends reply to the client and request to the target, then pipes both ways
  try:
    if reply.len > 0:
      await conn.sock.send(reply)
    if request.len > 0:
      await target.send(request)
  except CatchableError:
    closeQuietly(target)
    raise
  let (sent, recv) = await pipe(conn.sock, target)
  server.totalBytesSent += sent
  server.totalBytesRecv += recv

proc recvNullTerminated(sock: AsyncSocket): Future[string] {.async.} =
  result = ""
  while true:
    let b = await recvExact(sock, 1)
    if b[0] == '\x00':
      break
    if result.len >= maxSocks4Field:
      raise newException(ProxyProtocolError, "socks4 field too long")
    result.add(b[0])

proc socks5Reply(rep: char, host = "0.0.0.0", port = Port(0)): string =
  result = "\x05" & rep & "\x00"
  result.addAddress(host, port)

proc socks5FailureCode(e: ref CatchableError): char =
  result = repHostUnreachable
  if e of OSError:
    let code = (ref OSError)(e).errorCode
    when defined(windows):
      # winsock codes and the win32 codes reported by overlapped connects
      if code in [10061'i32, 1225]:
        result = repConnectionRefused
      elif code in [10051'i32, 1231]:
        result = repNetworkUnreachable
    else:
      if code == ECONNREFUSED:
        result = repConnectionRefused
      elif code == ENETUNREACH:
        result = repNetworkUnreachable

proc boundReply(target: AsyncSocket): string =
  ## success reply carrying the local address of the outbound connection
  result = socks5Reply('\x00')
  try:
    let (host, port) = target.getLocalAddr()
    var ip: IpAddress
    if tryParseIp(host, ip):
      result = socks5Reply('\x00', $unmapped(ip), port)
  except CatchableError:
    discard

proc fromClient(session: UdpSession, address: string, port: Port): bool =
  var ip: IpAddress
  result = false
  if tryParseIp(address, ip) and unmapped(ip) == session.clientIp:
    if session.clientPort == Port(0):
      session.clientPort = port
    result = session.clientPort == port

proc pumpToClient(session: UdpSession, outSock: AsyncSocket) {.async.} =
  var failures = 0
  while session.active and failures < maxUdpFailures:
    try:
      let dg = await outSock.recvDatagram()
      failures = 0
      if dg.data.len > 0 and session.clientPort != Port(0):
        let pkt = encodeUdpPacket(dg.address, dg.port, dg.data)
        await session.relaySock.sendTo($session.clientIp, session.clientPort, pkt)
        session.server.totalBytesRecv += pkt.len
    except CatchableError:
      inc failures

proc outboundSocket(session: UdpSession, family: IpAddressFamily): AsyncSocket =
  ## The ipv6 socket is opened on the first datagram that needs it
  if family == IpAddressFamily.IPv6 and session.outSock6.isNil:
    let sock = newAsyncSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
    try:
      sock.bindAddr(Port(0))
    except CatchableError:
      closeQuietly(sock)
      raise
    session.outSock6 = sock
    asyncCheck pumpToClient(session, sock)
  if family == IpAddressFamily.IPv6: session.outSock6 else: session.outSock

proc forward(session: UdpSession, packet: string) {.async.} =
  let server = session.server
  let (destHost, destPort, payload) = decodeUdpPacket(packet)
  if isValidHost(destHost) and destPort != Port(0) and server.allowed(destHost, destPort):
    let ip = unmapped(resolveHost(destHost))
    await session.outboundSocket(ip.family).sendTo($ip, destPort, payload)
    server.totalBytesSent += packet.len

proc pumpToTargets(session: UdpSession) {.async.} =
  var failures = 0
  while session.active and failures < maxUdpFailures:
    var dg: tuple[data: string, address: string, port: Port]
    var received = false
    try:
      dg = await session.relaySock.recvDatagram()
      received = true
      failures = 0
    except CatchableError:
      inc failures
    if received and session.fromClient(dg.address, dg.port) and not isFragment(dg.data):
      # one bad or undeliverable datagram must not end the association
      try:
        await session.forward(dg.data)
      except CatchableError:
        discard

proc handleSocks5Udp(server: ProxyServer, conn: Connection) {.async.} =
  let client = conn.sock
  # the relay must be reachable on the address the client already talks to
  let localIp = unmapped(parseIpAddress(client.getLocalAddr()[0]))
  let session = UdpSession(
    server: server,
    clientIp: unmapped(parseIpAddress(client.getPeerAddr()[0])),
    active: true
  )
  let domain = if localIp.family == IpAddressFamily.IPv6: AF_INET6 else: AF_INET
  session.relaySock = newAsyncSocket(domain, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  session.outSock = newAsyncSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  try:
    session.relaySock.bindAddr(Port(0), $localIp)
    session.outSock.bindAddr(Port(0))
    let boundPort = session.relaySock.getLocalAddr()[1]
    server.log("socks5 udp associate listening on " & joinHostPort($localIp, boundPort))

    conn.negotiating = false
    await client.send(socks5Reply('\x00', $localIp, boundPort))
    asyncCheck pumpToTargets(session)
    asyncCheck pumpToClient(session, session.outSock)

    # the association lives as long as the tcp control connection
    while (await client.recv(1)).len > 0:
      discard
  finally:
    session.active = false
    closeQuietly(session.relaySock)
    closeQuietly(session.outSock)
    if not session.outSock6.isNil:
      closeQuietly(session.outSock6)

proc handleSocks5(server: ProxyServer, conn: Connection) {.async.} =
  let client = conn.sock
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
  let cmd = reqHead[1]
  if reqHead[0] != '\x05' or (cmd != '\x01' and cmd != '\x03'):
    await client.send(socks5Reply(repCommandNotSupported))
    return
  if reqHead[3] notin {atypIpv4, atypDomain, atypIpv6}:
    await client.send(socks5Reply(repAddressNotSupported))
    return

  let (targetHost, targetPort) = await recvAddress(client, reqHead[3], -1)

  if cmd == '\x03':
    # datagrams would bypass the upstream proxy so they are refused instead
    if server.upstream.isNil:
      await handleSocks5Udp(server, conn)
    else:
      await client.send(socks5Reply(repCommandNotSupported))
    return

  if not isValidHost(targetHost):
    await client.send(socks5Reply(repGeneralFailure))
    return

  if not server.allowed(targetHost, targetPort):
    await client.send(socks5Reply(repNotAllowed))
    return

  server.log("socks5 connect " & joinHostPort(targetHost, targetPort))

  var targetSock: AsyncSocket
  var failure = '\x00'
  try:
    targetSock = await server.connectTarget(conn, targetHost, targetPort)
  except CatchableError as e:
    server.log("socks5 dial error " & e.msg)
    failure = socks5FailureCode(e)
  if failure != '\x00':
    await client.send(socks5Reply(failure))
    return

  await server.relay(conn, targetSock, reply = boundReply(targetSock))

proc handleSocks4(server: ProxyServer, conn: Connection) {.async.} =
  let client = conn.sock
  let cmd = (await recvExact(client, 1))[0].byte
  if cmd != 0x01:
    await client.send(socks4Rejected)
    return

  let portBytes = await recvExact(client, 2)
  let targetPort = toPort(portBytes[0].byte, portBytes[1].byte)
  let ipBytes = await recvExact(client, 4)
  let userId = await recvNullTerminated(client)

  if not server.authProc.isNil and not server.authProc(userId, ""):
    await client.send(socks4Rejected)
    return

  var targetHost = ""
  # check socks4a domain extension
  if ipBytes[0] == '\x00' and ipBytes[1] == '\x00' and ipBytes[2] == '\x00' and ipBytes[3] != '\x00':
    targetHost = await recvNullTerminated(client)
  else:
    targetHost = $ipBytes[0].int & "." & $ipBytes[1].int & "." & $ipBytes[2].int & "." & $ipBytes[3].int

  if not isValidHost(targetHost) or not server.allowed(targetHost, targetPort):
    await client.send(socks4Rejected)
    return

  server.log("socks4 connect " & joinHostPort(targetHost, targetPort))

  var targetSock: AsyncSocket
  var failed = false
  try:
    targetSock = await server.connectTarget(conn, targetHost, targetPort)
  except CatchableError as e:
    server.log("socks4 dial error " & e.msg)
    failed = true
  if failed:
    await client.send(socks4Rejected)
    return

  await server.relay(conn, targetSock, reply = socks4Granted)

proc httpReply(status: string, extraHeaders = ""): string =
  "HTTP/1.1 " & status & "\r\n" & extraHeaders & "Content-Length: 0\r\nConnection: close\r\n\r\n"

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

proc recvHeaders(client: AsyncSocket): Future[seq[(string, string)]] {.async.} =
  result = @[]
  while true:
    let line = await client.recvLine(maxLength = maxHeaderLine)
    if line.strip.len == 0:
      break
    if line.len >= maxHeaderLine or result.len >= maxHeaderCount:
      raise newException(ProxyProtocolError, "http request headers too large")
    let parts = line.split(':', 1)
    if parts.len == 2:
      result.add((parts[0].strip, parts[1].strip))

proc parseConnectTarget(target: string, host: var string, port: var Port): bool =
  var rest = ""
  result = splitHost(target, host, rest) and isValidHost(host)
  if result:
    if rest.len == 0:
      port = Port(443)
    else:
      result = parsePort(rest, port)

proc parseForwardTarget(target: string, host: var string, port: var Port, pathQuery: var string): bool =
  let u = parseUri(target)
  host = u.hostname
  port = Port(80)
  let path = if u.path.len == 0: "/" else: u.path
  pathQuery = if u.query.len > 0: path & "?" & u.query else: path
  u.scheme.toLowerAscii == "http" and isValidHost(host) and
    (u.port.len == 0 or parsePort(u.port, port))

proc buildForwardRequest(httpMethod, pathQuery: string, headers: seq[(string, string)]): string =
  var upgrade = false
  result = httpMethod & " " & pathQuery & " HTTP/1.1\r\n"
  for (k, v) in headers:
    case k.toLowerAscii
    of "proxy-authorization", "proxy-connection", "keep-alive":
      discard
    of "connection":
      if "upgrade" in v.toLowerAscii:
        upgrade = true
        result.add(k & ": " & v & "\r\n")
    else:
      result.add(k & ": " & v & "\r\n")
  if not upgrade:
    result.add("Connection: close\r\n")
  result.add("\r\n")

proc handleHttp(server: ProxyServer, conn: Connection, initialChar: char) {.async.} =
  let client = conn.sock
  let restOfLine = await client.recvLine(maxLength = maxHeaderLine)
  let firstLine = initialChar & restOfLine

  var headers: seq[(string, string)] = @[]
  var tooLarge = firstLine.len >= maxHeaderLine
  if not tooLarge:
    try:
      headers = await recvHeaders(client)
    except ProxyProtocolError:
      tooLarge = true
  if tooLarge:
    await client.send(httpReply("431 Request Header Fields Too Large"))
    return

  if not server.checkHttpAuth(headers):
    await client.send(httpReply("407 Proxy Authentication Required",
      "Proxy-Authenticate: Basic realm=\"prx\"\r\n"))
    return

  let reqParts = firstLine.splitWhitespace()
  if reqParts.len != 3 or not reqParts[2].startsWith("HTTP/"):
    await client.send(httpReply("400 Bad Request"))
    return

  let httpMethod = reqParts[0].toUpperAscii
  let isConnect = httpMethod == "CONNECT"
  var targetHost, pathQuery = ""
  var targetPort: Port
  let valid =
    if isConnect: parseConnectTarget(reqParts[1], targetHost, targetPort)
    else: parseForwardTarget(reqParts[1], targetHost, targetPort, pathQuery)
  if not valid:
    await client.send(httpReply("400 Bad Request"))
    return

  if not server.allowed(targetHost, targetPort):
    await client.send(httpReply("403 Forbidden"))
    return

  let label = if isConnect: "http connect " else: "http forward "
  server.log(label & joinHostPort(targetHost, targetPort))

  var targetSock: AsyncSocket
  var failed = false
  try:
    targetSock = await server.connectTarget(conn, targetHost, targetPort)
  except CatchableError as e:
    server.log(label & "dial error " & e.msg)
    failed = true
  if failed:
    await client.send(httpReply("502 Bad Gateway"))
    return

  if isConnect:
    await server.relay(conn, targetSock, reply = "HTTP/1.1 200 Connection Established\r\n\r\n")
  else:
    await server.relay(conn, targetSock, request = buildForwardRequest(httpMethod, pathQuery, headers))

proc watchHandshake(server: ProxyServer, conn: Connection) =
  ## Drops clients that stay silent instead of finishing their request.
  if server.handshakeTimeout > 0:
    let timer = sleepAsync(server.handshakeTimeout)
    timer.addCallback(proc() =
      if conn.negotiating:
        server.log("client handshake timed out")
        closeQuietly(conn.sock)
    )

proc handleClient(server: ProxyServer, client: AsyncSocket) {.async.} =
  inc server.totalConnections
  inc server.activeConnections
  let conn = Connection(sock: client, negotiating: true)
  watchHandshake(server, conn)

  try:
    let firstByte = await recvExact(client, 1)

    case server.kind
    of skSocks5:
      if firstByte[0] == '\x05':
        await handleSocks5(server, conn)
    of skSocks4:
      if firstByte[0] == '\x04':
        await handleSocks4(server, conn)
    of skHttp:
      await handleHttp(server, conn, firstByte[0])
    of skAuto:
      # detect protocol from first byte
      case firstByte[0]
      of '\x05':
        await handleSocks5(server, conn)
      of '\x04':
        await handleSocks4(server, conn)
      else:
        await handleHttp(server, conn, firstByte[0])
  except CatchableError as e:
    server.log("client error " & e.msg)
  finally:
    conn.negotiating = false
    dec server.activeConnections
    closeQuietly(client)

proc listen*(server: ProxyServer) =
  ## binds the listening socket and resolves server.port when it was 0
  let sock = newAsyncSocket(if isIpv6(server.bindAddr): AF_INET6 else: AF_INET, buffered = false)
  try:
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(server.port, server.bindAddr)
    sock.listen()
    server.port = sock.getLocalAddr()[1]
  except CatchableError:
    closeQuietly(sock)
    raise
  server.socket = sock
  server.running = true
  server.log("proxy server listening on " & joinHostPort(server.bindAddr, server.port))

proc serve*(server: ProxyServer): Future[void] {.async.} =
  ## accepts clients on a socket prepared by listen until stop is called
  while server.running:
    var failed = false
    try:
      let client = await server.socket.accept()
      asyncCheck handleClient(server, client)
    except CatchableError as e:
      if server.running:
        server.log("accept error " & e.msg)
        failed = true
    if failed:
      await sleepAsync(acceptBackoff)

proc start*(server: ProxyServer): Future[void] {.async.} =
  if not server.running:
    server.listen()
  await server.serve()

proc stop*(server: ProxyServer) =
  server.running = false
  if not server.socket.isNil:
    closeQuietly(server.socket)
