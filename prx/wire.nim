import std/[net, asyncnet, asyncdispatch, nativesockets]
import types, common, hostport

type
  HostPort* = tuple[host: string, port: Port]

const
  atypIpv4* = '\x01'
  atypDomain* = '\x03'
  atypIpv6* = '\x04'

proc closeQuietly*(sock: Socket | AsyncSocket) =
  try:
    sock.close()
  except CatchableError:
    discard

proc tryParseIp*(host: string, ip: var IpAddress): bool =
  try:
    ip = parseIpAddress(host)
    result = true
  except ValueError:
    result = false

proc unmapped*(ip: IpAddress): IpAddress =
  ## Turns an ipv4-mapped ipv6 address into the plain ipv4 address
  const prefix = [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
  result = ip
  if ip.family == IpAddressFamily.IPv6 and ip.address_v6[0 .. 11] == prefix:
    result = IpAddress(family: IpAddressFamily.IPv4)
    for i in 0 .. 3:
      result.address_v4[i] = ip.address_v6[12 + i]

proc checkHost*(host: string) =
  if not isValidHost(host):
    raise newException(ProxyProtocolError,
      "target host must be 1 to 255 bytes without whitespace or control characters")

proc resolveHost*(host: string, allowIpv6 = true): IpAddress =
  ## blocking lookup that prefers ipv4 and falls back to ipv6 when allowed
  ## an ip literal is returned as is
  if tryParseIp(host, result):
    return
  checkHost(host)
  var aiList: ptr AddrInfo
  try:
    aiList = getAddrInfo(host, Port(0), AF_UNSPEC)
  except OSError as e:
    raise newException(ProxyConnectError, "cannot resolve host " & host, e)
  var found = false
  var it = aiList
  while it != nil:
    let isV4 = it.ai_family == toInt(AF_INET)
    if isV4 or (allowIpv6 and not found and it.ai_family == toInt(AF_INET6)):
      var ip: IpAddress
      if tryParseIp(getAddrString(it.ai_addr), ip):
        result = ip
        found = true
        if isV4:
          break
    it = it.ai_next
  freeAddrInfo(aiList)
  if not found:
    raise newException(ProxyConnectError, "cannot resolve host " & host)

proc addPort*(buf: var string, port: Port) =
  let p = port.toBytes
  buf.add(p[0].char)
  buf.add(p[1].char)

proc addIp*(buf: var string, ip: IpAddress) =
  case ip.family
  of IpAddressFamily.IPv4:
    buf.add(atypIpv4)
    for b in ip.address_v4:
      buf.add(b.char)
  of IpAddressFamily.IPv6:
    buf.add(atypIpv6)
    for b in ip.address_v6:
      buf.add(b.char)

proc addAddress*(buf: var string, targetHost: string, port: Port, remoteDns = true) =
  let host = stripBrackets(targetHost)
  var ip: IpAddress
  if tryParseIp(host, ip):
    buf.addIp(ip)
  elif remoteDns:
    checkHost(host)
    buf.add(atypDomain)
    buf.add(host.len.char)
    buf.add(host)
  else:
    buf.addIp(resolveHost(host))
  buf.addPort(port)

proc parseAddress*(data: string, pos: var int): HostPort =
  template need(n: int) =
    if pos + n > data.len:
      raise newException(ProxyProtocolError, "truncated socks5 address")

  need(1)
  let atyp = data[pos]
  inc pos
  case atyp
  of atypIpv4:
    need(4)
    var ip = IpAddress(family: IpAddressFamily.IPv4)
    for i in 0 .. 3:
      ip.address_v4[i] = data[pos + i].byte
    result.host = $ip
    pos += 4
  of atypIpv6:
    need(16)
    var ip = IpAddress(family: IpAddressFamily.IPv6)
    for i in 0 .. 15:
      ip.address_v6[i] = data[pos + i].byte
    result.host = $ip
    pos += 16
  of atypDomain:
    need(1)
    let n = data[pos].int
    inc pos
    need(n)
    result.host = data[pos ..< pos + n]
    pos += n
  else:
    raise newException(ProxyProtocolError, "invalid socks5 address type " & $atyp.int)
  need(2)
  result.port = toPort(data[pos].byte, data[pos + 1].byte)
  pos += 2

proc isFragment*(udpPacket: string): bool =
  ## fragmented socks5 datagrams are not reassembled and must be dropped
  udpPacket.len > 2 and udpPacket[2] != '\x00'

# the async variants take a timeout only to share code with the sync ones
# async deadlines are enforced by the dialer

proc recvN*(sock: Socket, size, timeout: int): string =
  recvExact(sock, size, timeout)

proc recvN*(sock: AsyncSocket, size, timeout: int): Future[string] =
  recvExact(sock, size)

proc recvLineN*(sock: Socket, maxLength, timeout: int): string =
  sock.recvLine(timeout, maxLength = maxLength)

proc recvLineN*(sock: AsyncSocket, maxLength, timeout: int): Future[string] =
  sock.recvLine(maxLength = maxLength)

proc recvAddress*(
  sock: Socket | AsyncSocket,
  atyp: char,
  timeout: int
): Future[HostPort] {.multisync.} =
  ## Reads the ADDR PORT that follows an already received ATYP byte
  var raw = newStringOfCap(24)
  raw.add(atyp)
  case atyp
  of atypIpv4:
    raw.add(await recvN(sock, 6, timeout))
  of atypIpv6:
    raw.add(await recvN(sock, 18, timeout))
  of atypDomain:
    let n = await recvN(sock, 1, timeout)
    raw.add(n)
    raw.add(await recvN(sock, n[0].int + 2, timeout))
  else:
    raise newException(ProxyProtocolError, "invalid socks5 address type " & $atyp.int)
  var pos = 0
  result = parseAddress(raw, pos)
