import std/strutils
from std/nativesockets import Port

proc stripBrackets*(host: string): string =
  if host.len >= 2 and host[0] == '[' and host[^1] == ']':
    host[1 ..^ 2]
  else:
    host

proc isValidHost*(host: string): bool =
  result = host.len in 1 .. 255
  for c in host:
    if c <= ' ' or c == '\x7F':
      result = false

proc joinHostPort*(host: string, port: Port): string =
  let h = stripBrackets(host)
  if ':' in h:
    "[" & h & "]:" & $port.int
  else:
    h & ":" & $port.int

proc parsePort*(s: string, port: var Port): bool =
  result = false
  if s.len in 1 .. 5 and s.allCharsInSet(Digits):
    let n = parseInt(s)
    if n in 1 .. 65535:
      port = Port(n)
      result = true

proc splitHost*(s: string, host, rest: var string): bool =
  result = false
  if s.startsWith('['):
    let close = s.find(']')
    if close > 1 and (close == s.high or s[close + 1] == ':'):
      host = s[1 ..< close]
      rest = if close == s.high: "" else: s[close + 2 .. ^1]
      result = true
  else:
    let colon = s.find(':')
    host = if colon < 0: s else: s[0 ..< colon]
    rest = if colon < 0: "" else: s[colon + 1 .. ^1]
    result = host.len > 0

proc parseEndpoint*(s: string, host: var string, port: var Port): bool =
  var rest = ""
  splitHost(s, host, rest) and parsePort(rest, port)
