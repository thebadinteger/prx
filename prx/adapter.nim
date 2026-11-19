import std/[net, asyncdispatch, os, atomics]
import std/httpclient except Proxy
import types, hostport, server

const
  maxBindAddr = 256
  maxUpstream = 2048
  maxError = 256

  stateStarting = 0
  stateReady = 1
  stateFailed = 2

type
  AdapterContext = object
    state: Atomic[int]
    running: Atomic[bool]
    port: Port
    upstreamTimeout: int
    upstreamRemoteDns: bool
    bindAddrLen: int
    bindAddrBuf: array[maxBindAddr, char]
    upstreamLen: int
    upstreamBuf: array[maxUpstream, char]
    errorLen: int
    errorBuf: array[maxError, char]
    thread: Thread[ptr AdapterContext]

  LocalAdapter* = ref object
    port*: Port
    bindAddr*: string
    upstream*: Proxy
    isThreaded*: bool
    server*: ProxyServer
    ctx: ptr AdapterContext

proc store(buf: var openArray[char], len: var int, value: string) =
  len = min(value.len, buf.len)
  if len > 0:
    copyMem(addr buf[0], addr value[0], len)

proc load(buf: openArray[char], len: int): string =
  result = newString(len)
  if len > 0:
    copyMem(addr result[0], addr buf[0], len)

proc httpUrl*(a: LocalAdapter): string =
  "http://" & joinHostPort(a.bindAddr, a.port)

proc socks5Url*(a: LocalAdapter): string =
  "socks5://" & joinHostPort(a.bindAddr, a.port)

proc proxy*(a: LocalAdapter): Proxy =
  newProxy(a.bindAddr, a.port, pkHttp)

proc socksProxy*(a: LocalAdapter): Proxy =
  newProxy(a.bindAddr, a.port, pkSocks5)

proc stop*(a: LocalAdapter) =
  if a.isThreaded:
    if not a.ctx.isNil:
      a.ctx.running.store(false)
      joinThread(a.ctx.thread)
      deallocShared(a.ctx)
      a.ctx = nil
  else:
    if not a.server.isNil:
      a.server.stop()

proc adapterWorker(ctx: ptr AdapterContext) {.thread.} =
  var srv: ProxyServer
  try:
    var upstream: Proxy = nil
    if ctx.upstreamLen > 0:
      upstream = parseProxy(load(ctx.upstreamBuf, ctx.upstreamLen), timeout = ctx.upstreamTimeout)
      upstream.remoteDns = ctx.upstreamRemoteDns
    srv = newServer(ctx.port, load(ctx.bindAddrBuf, ctx.bindAddrLen), kind = skAuto, upstream = upstream)
    srv.listen()
  except CatchableError as e:
    store(ctx.errorBuf, ctx.errorLen, e.msg)
    ctx.state.store(stateFailed)
    return
  ctx.port = srv.port
  ctx.state.store(stateReady)
  asyncCheck srv.serve()

  # run dispatch loop
  while ctx.running.load and srv.running:
    try:
      poll(20)
    except CatchableError:
      break
  srv.stop()

proc startAdapter*(upstream: Proxy, bindAddr = "127.0.0.1"): LocalAdapter =
  let ustr = if upstream.isNil: "" else: $upstream
  if bindAddr.len > maxBindAddr or ustr.len > maxUpstream:
    raise newException(ProxyProtocolError, "adapter address too long")
  let ctx = createShared(AdapterContext)
  ctx.running.store(true)
  store(ctx.bindAddrBuf, ctx.bindAddrLen, bindAddr)
  store(ctx.upstreamBuf, ctx.upstreamLen, ustr)
  if not upstream.isNil:
    ctx.upstreamTimeout = upstream.timeout
    ctx.upstreamRemoteDns = upstream.remoteDns
  # thread handle lives in shared memory and is never moved
  createThread(ctx.thread, adapterWorker, ctx)
  while ctx.state.load == stateStarting:
    os.sleep(1)

  if ctx.state.load == stateFailed:
    joinThread(ctx.thread)
    let reason = load(ctx.errorBuf, ctx.errorLen)
    deallocShared(ctx)
    raise newException(ProxyConnectError, "cannot start local adapter: " & reason)

  LocalAdapter(
    port: ctx.port,
    bindAddr: bindAddr,
    upstream: upstream,
    isThreaded: true,
    ctx: ctx
  )

proc startAdapterAsync*(upstream: Proxy, bindAddr = "127.0.0.1"): Future[LocalAdapter] {.async.} =
  let srv = newServer(Port(0), bindAddr, kind = skAuto, upstream = upstream)
  srv.listen()
  asyncCheck srv.serve()

  result = LocalAdapter(
    port: srv.port,
    bindAddr: bindAddr,
    upstream: upstream,
    isThreaded: false,
    server: srv
  )

proc newHttpClient*(adapter: LocalAdapter): HttpClient =
  httpclient.newHttpClient(proxy = httpclient.newProxy(adapter.httpUrl))

proc newAsyncHttpClient*(adapter: LocalAdapter): AsyncHttpClient =
  httpclient.newAsyncHttpClient(proxy = httpclient.newProxy(adapter.httpUrl))

proc withProxy*(proxy: Proxy, action: proc(client: HttpClient)) =
  let adapter = startAdapter(proxy)
  let client = httpclient.newHttpClient(proxy = httpclient.newProxy(adapter.httpUrl))
  try:
    action(client)
  finally:
    client.close()
    adapter.stop()

proc withProxyAsync*(proxy: Proxy, action: proc(client: AsyncHttpClient): Future[void]) {.async.} =
  let adapter = await startAdapterAsync(proxy)
  let client = httpclient.newAsyncHttpClient(proxy = httpclient.newProxy(adapter.httpUrl))
  try:
    await action(client)
  finally:
    client.close()
    adapter.stop()
