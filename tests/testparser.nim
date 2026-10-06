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
