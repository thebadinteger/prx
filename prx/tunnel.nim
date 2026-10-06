import std/[net, asyncnet, asyncdispatch]
import types, dialer

proc pump(src, dst: AsyncSocket, transferred: ptr int64): Future[void] {.async.} =
  try:
    while true:
      let data = await src.recv(8192)
      if data.len == 0:
        break
      await dst.send(data)
      transferred[] += data.len
  except CatchableError:
    discard
  finally:
    src.close()
    dst.close()

proc pipe*(sockA, sockB: AsyncSocket): Future[tuple[bytesAtoB, bytesBtoA: int64]] {.async.} =
  var aToB: int64 = 0
  var bToA: int64 = 0
  let f1 = pump(sockA, sockB, addr aToB)
  let f2 = pump(sockB, sockA, addr bToA)
  await f1 and f2
  result = (aToB, bToA)

proc handleBridgeClient(client: AsyncSocket, proxy: Proxy, targetHost: string, targetPort: Port) {.async.} =
  try:
    let upstreamSock = await dialAsync(proxy, targetHost, targetPort)
    discard await pipe(client, upstreamSock)
  except CatchableError:
    client.close()

proc startBridge*(
  localPort: Port,
  proxy: Proxy,
  targetHost: string,
  targetPort: Port,
  bindAddr = "127.0.0.1"
): Future[void] {.async.} =
  let server = newAsyncSocket(buffered = false)
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(localPort, bindAddr)
  server.listen()
  while true:
    let client = await server.accept()
    asyncCheck handleBridgeClient(client, proxy, targetHost, targetPort)
