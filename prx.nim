import std/[net, asyncnet, asyncdispatch]
import prx/[types, common, socks4, socks5, http, dialer, tunnel, server, udp, adapter]

export net
export asyncnet
export asyncdispatch
export types
export common
export socks4
export socks5
export http
export dialer
export tunnel
export server
export udp
export adapter



proc proxy*(raw: string, defaultKind = pkSocks5, timeout = 10000, remoteDns = true): Proxy =
  parseProxy(raw, defaultKind, timeout, remoteDns)

proc proxy*(
  host: string,
  port: Port,
  kind = pkSocks5,
  username = "",
  password = "",
  timeout = 10000,
  remoteDns = true
): Proxy =
  newProxy(host, port, kind, username, password, timeout, remoteDns)

proc server*(
  port: Port = Port(1080),
  bindAddr = "127.0.0.1",
  kind = skAuto,
  upstream: Proxy = nil
): ProxyServer =
  newServer(port, bindAddr, kind, upstream)

