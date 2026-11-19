import std/unittest
import prx

suite "prx proxy parser":
  test "parse uri socks5":
    let p = parseProxy("socks5://alice:secret123@127.0.0.1:1080")
    check p.kind == pkSocks5
    check p.host == "127.0.0.1"
    check p.port == Port(1080)
    check p.username == "alice"
    check p.password == "secret123"

  test "parse uri socks4a":
    let p = parseProxy("socks4a://10.0.0.1:1080")
    check p.kind == pkSocks4a
    check p.host == "10.0.0.1"
    check p.port == Port(1080)

  test "parse uri http and https":
    let p1 = parseProxy("http://proxy.local:8080")
    check p1.kind == pkHttp
    check p1.port == Port(8080)

    let p2 = parseProxy("https://secure.proxy.local:8443")
    check p2.kind == pkHttps
    check p2.port == Port(8443)

  test "parse host port format":
    let p = parseProxy("192.168.1.100:3128", pkHttp)
    check p.kind == pkHttp
    check p.host == "192.168.1.100"
    check p.port == Port(3128)

  test "parse host port user pass format":
    let p = parseProxy("192.168.1.100:1080:myuser:mypass", pkSocks5)
    check p.kind == pkSocks5
    check p.host == "192.168.1.100"
    check p.port == Port(1080)
    check p.username == "myuser"
    check p.password == "mypass"

  test "parse user pass at host port":
    let p = parseProxy("bot1:pwd99@1.2.3.4:9050", pkSocks5)
    check p.kind == pkSocks5
    check p.host == "1.2.3.4"
    check p.port == Port(9050)
    check p.username == "bot1"
    check p.password == "pwd99"

  test "parse rdns flag from query":
    let p1 = parseProxy("socks5://127.0.0.1:1080?rdns=0")
    check p1.remoteDns == false

    let p2 = parseProxy("socks5://127.0.0.1:1080?remotedns=false")
    check p2.remoteDns == false

    let p3 = parseProxy("socks5://127.0.0.1:1080?rdns=1")
    check p3.remoteDns == true

    let p4 = parseProxy("socks5h://127.0.0.1:1080")
    check p4.remoteDns == true

    let p5 = parseProxy("socks4://127.0.0.1:1080")
    check p5.remoteDns == false

    let p6 = parseProxy("socks4a://127.0.0.1:1080")
    check p6.remoteDns == true

    let p7 = parseProxy("127.0.0.1:1080", defaultRemoteDns = false)
    check p7.remoteDns == false

  test "socks4 resolves locally unless asked otherwise":
    check newProxy("1.2.3.4", Port(1080), pkSocks4).remoteDns == false
    check newProxy("1.2.3.4", Port(1080), pkSocks4, remoteDns = true).remoteDns == true
    check newProxy("1.2.3.4", Port(1080), pkSocks4a).remoteDns == true
    check newProxy("1.2.3.4", Port(1080)).remoteDns == true
    check proxy("1.2.3.4", Port(1080), pkSocks4).remoteDns == false
    check parseProxy("1.2.3.4:1080", pkSocks4).remoteDns == false
    check parseProxy("user:pass@1.2.3.4:1080", pkSocks4).remoteDns == false
    check parseProxy("1.2.3.4:1080", pkSocks4a, defaultRemoteDns = false).remoteDns == true
    check parseProxy("socks4://1.2.3.4:1080?rdns=1").remoteDns == true

  test "reject missing and invalid ports":
    for raw in ["1.2.3.4", "1.2.3.4:0", "1.2.3.4:99999", "1.2.3.4:abc",
                "socks5://1.2.3.4:99999", "socks5://1.2.3.4:abc", "user:pass@1.2.3.4"]:
      expect ProxyProtocolError:
        discard parseProxy(raw)

  test "parse ipv6 hosts":
    let p1 = parseProxy("socks5://[::1]:1080")
    check p1.host == "::1"
    check p1.port == Port(1080)
    check $p1 == "socks5://[::1]:1080"

    let p2 = parseProxy("[2001:db8::1]:3128", pkHttp)
    check p2.host == "2001:db8::1"
    check p2.port == Port(3128)

    let p3 = parseProxy("user:pass@[::1]:1080")
    check p3.host == "::1"
    check p3.username == "user"
    check p3.password == "pass"

    let p4 = parseProxy("[::1]:1080:user:pass")
    check p4.host == "::1"
    check p4.username == "user"
    check p4.password == "pass"

  test "credentials with reserved characters":
    let p1 = parseProxy("socks5://user:p%40ss%3Aword@1.2.3.4:1080")
    check p1.username == "user"
    check p1.password == "p@ss:word"

    let p2 = parseProxy("1.2.3.4:1080:user:pa:ss")
    check p2.password == "pa:ss"

    let p3 = parseProxy("user:p@ss@1.2.3.4:1080")
    check p3.host == "1.2.3.4"
    check p3.password == "p@ss"

    let original = newProxy("proxy.local", Port(1080), username = "a@b", password = "c:d/e")
    let reparsed = parseProxy($original)
    check reparsed.host == "proxy.local"
    check reparsed.username == "a@b"
    check reparsed.password == "c:d/e"
