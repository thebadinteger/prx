import std/[net, asyncnet, asyncdispatch, strutils]
import types

proc recvExact*(sock: Socket, size: int, timeout = -1): string =
  result = ""
  while result.len < size:
    var chunk = ""
    let readBytes = sock.recv(chunk, size - result.len, timeout)
    if readBytes <= 0:
      raise newException(ProxyConnectError, "connection closed prematurely")
    result.add(chunk)

proc recvExact*(sock: AsyncSocket, size: int): Future[string] {.async.} =
  result = ""
  while result.len < size:
    let chunk = await sock.recv(size - result.len)
    if chunk.len == 0:
      raise newException(ProxyConnectError, "connection closed prematurely")
    result.add(chunk)

proc isIpv4*(host: string): bool =
  try:
    let ip = parseIpAddress(host)
    return ip.family == IpAddressFamily.IPv4
  except ValueError:
    return false

proc isIpv6*(host: string): bool =
  try:
    let ip = parseIpAddress(host)
    return ip.family == IpAddressFamily.IPv6
  except ValueError:
    return false

proc recvDatagram*(sock: AsyncSocket, maxSize = 65535): Future[tuple[data: string, address: string, port: Port]] {.async.} =
  var data = newFutureVar[string]()
  var address = newFutureVar[string]()
  var port = newFutureVar[Port]()
  data.mget().setLen(maxSize)
  address.mget().setLen(46)
  let n = await sock.recvFrom(data, maxSize, address, port)
  result = (data.mget()[0 ..< n], address.mget().strip(chars = {'\0'}), port.mget())

