import std/[net, asyncdispatch, os]
import std/httpclient except Proxy
import types, server

const
  maxBindAddr = 256
  maxUpstream = 1024

type
  AdapterContext = object
    ready: bool
    running: bool
    port: Port
    bindAddrLen: int
    bindAddrBuf: array[maxBindAddr, char]
    upstreamLen: int
    upstreamBuf: array[maxUpstream, char]
    thread: Thread[ptr AdapterContext]

  LocalAdapter* = ref object
    port*: Port
    bindAddr*: string
    upstream*: Proxy
    isThreaded*: bool
    server*: ProxyServer
    ctx: ptr AdapterContext

proc httpUrl*(a: LocalAdapter): string =
  "http://" & a.bindAddr & ":" & $a.port.int

proc socks5Url*(a: LocalAdapter): string =
  "socks5://" & a.bindAddr & ":" & $a.port.int

proc proxy*(a: LocalAdapter): Proxy =
  newProxy(a.bindAddr, a.port, pkHttp)

proc socksProxy*(a: LocalAdapter): Proxy =
  newProxy(a.bindAddr, a.port, pkSocks5)

proc stop*(a: LocalAdapter) =
  if a.isThreaded:
    if not a.ctx.isNil:
      a.ctx.running = false
      joinThread(a.ctx.thread)
      deallocShared(a.ctx)
      a.ctx = nil
  else:
    if not a.server.isNil:
      a.server.stop()

proc adapterWorker(ctx: ptr AdapterContext) {.thread.} =
  var bindAddr = newString(ctx.bindAddrLen)
  if ctx.bindAddrLen > 0:
    copyMem(bindAddr[0].addr, ctx.bindAddrBuf[0].addr, ctx.bindAddrLen)
  var ustr = newString(ctx.upstreamLen)
  if ctx.upstreamLen > 0:
    copyMem(ustr[0].addr, ctx.upstreamBuf[0].addr, ctx.upstreamLen)
  let upstream = if ustr.len > 0: parseProxy(ustr) else: nil
  let srv = newServer(ctx.port, bindAddr, kind = skAuto, upstream = upstream)
  asyncCheck srv.start()
  while not srv.running:
    poll(2)
  ctx.port = srv.port
  ctx.ready = true

  # run dispatch loop
  while ctx.running and srv.running:
    try:
      poll(20)
    except CatchableError:
      break
  try:
    srv.stop()
  except CatchableError:
    discard

proc startAdapter*(upstream: Proxy, bindAddr = "127.0.0.1"): LocalAdapter =
  let ustr = if upstream.isNil: "" else: $upstream
  if bindAddr.len > maxBindAddr or ustr.len > maxUpstream:
    raise newException(ProxyProtocolError, "adapter address too long")
  let ctx = createShared(AdapterContext)
  ctx.ready = false
  ctx.running = true
  ctx.port = Port(0)
  ctx.bindAddrLen = bindAddr.len
  if bindAddr.len > 0:
    copyMem(ctx.bindAddrBuf[0].addr, bindAddr[0].unsafeAddr, bindAddr.len)
  ctx.upstreamLen = ustr.len
  if ustr.len > 0:
    copyMem(ctx.upstreamBuf[0].addr, ustr[0].unsafeAddr, ustr.len)
  # thread handle lives in shared memory and is never moved
  createThread(ctx.thread, adapterWorker, ctx)
  while not ctx.ready:
    os.sleep(2)

  LocalAdapter(
    port: ctx.port,
    bindAddr: bindAddr,
    upstream: upstream,
    isThreaded: true,
    ctx: ctx
  )

proc startAdapterAsync*(upstream: Proxy, bindAddr = "127.0.0.1"): Future[LocalAdapter] {.async.} =
  let srv = newServer(Port(0), bindAddr, kind = skAuto, upstream = upstream)
  asyncCheck srv.start()
  while not srv.running:
    await sleepAsync(2)

  LocalAdapter(
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
