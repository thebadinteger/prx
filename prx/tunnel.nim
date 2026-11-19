import std/[net, asyncnet, asyncdispatch]
import types, common, wire, dialer

when defined(windows):
  from std/winlean import shutdown
  const shutWrite = 1.cint
else:
  from std/posix import shutdown, SHUT_WR
  let shutWrite = SHUT_WR

const pumpBufferSize = 8192

proc finishWrite(sock: AsyncSocket) =
  ## signals eof to the peer while the opposite direction keeps flowing
  if not sock.isClosed:
    if sock.isSsl:
      closeQuietly(sock)
    else:
      discard shutdown(sock.getFd, shutWrite)

proc pump(src, dst: AsyncSocket): Future[int64] {.async.} =
  result = 0
  try:
    while true:
      let data = await src.recv(pumpBufferSize)
      if data.len == 0:
        break
      await dst.send(data)
      result += data.len
    finishWrite(dst)
  except CatchableError:
    closeQuietly(src)
    closeQuietly(dst)

proc pipe*(sockA, sockB: AsyncSocket): Future[tuple[bytesAtoB, bytesBtoA: int64]] {.async.} =
  let aToB = pump(sockA, sockB)
  let bToA = pump(sockB, sockA)
  await aToB and bToA
  closeQuietly(sockA)
  closeQuietly(sockB)
  result = (aToB.read, bToA.read)

proc handleBridgeClient(client: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port) {.async.} =
  try:
    let upstreamSock = await dialAsync(proxy, targetHost, targetPort)
    discard await pipe(client, upstreamSock)
  except CatchableError:
    closeQuietly(client)

proc startBridge*(
  localPort: Port,
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  bindAddr = "127.0.0.1"
): Future[void] {.async.} =
  let server = newAsyncSocket(if isIpv6(bindAddr): AF_INET6 else: AF_INET, buffered = false)
  try:
    server.setSockOpt(OptReuseAddr, true)
    server.bindAddr(localPort, bindAddr)
    server.listen()
    while true:
      let client = await server.accept()
      asyncCheck handleBridgeClient(client, proxy, targetHost, targetPort)
  finally:
    closeQuietly(server)
