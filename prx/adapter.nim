import std/[net, asyncdispatch, os]
import std/httpclient except Proxy
import types, server

type
  AdapterParams = object
    bindAddr: string
    upstreamStr: string

  AdapterContext = object
    ready: bool
    running: bool
    port: Port
    params: AdapterParams

  LocalAdapter* = ref object
    port*: Port
    bindAddr*: string
    upstream*: Proxy
    isThreaded*: bool
    server*: ProxyServer
    ctx: ptr AdapterContext
    thread: Thread[ptr AdapterContext]

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
      joinThread(a.thread)
      deallocShared(a.ctx)
      a.ctx = nil
  else:
    if not a.server.isNil:
      a.server.stop()

proc adapterWorker(ctx: ptr AdapterContext) {.thread.} =
  let upstream = if ctx.params.upstreamStr.len > 0: parseProxy(ctx.params.upstreamStr) else: nil
  let srv = newServer(ctx.port, ctx.params.bindAddr, kind = skAuto, upstream = upstream)
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
  let ctx = createShared(AdapterContext)
  ctx.ready = false
  ctx.running = true
  ctx.port = Port(0)
  ctx.params = AdapterParams(
    bindAddr: bindAddr,
    upstreamStr: if upstream.isNil: "" else: $upstream
  )
  var thr: Thread[ptr AdapterContext]
  createThread(thr, adapterWorker, ctx)
  while not ctx.ready:
    os.sleep(2)

  LocalAdapter(
    port: ctx.port,
    bindAddr: bindAddr,
    upstream: upstream,
    isThreaded: true,
    ctx: ctx,
    thread: thr
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
