# HolyNet architecture

## Modules

| Path | Responsibility |
|---|---|
| src/HolyNet.HC | Single library loader |
| src/Net/ | Shrine-derived driver and stack; NetUp and CConn transport abstraction |
| src/Crypto/ | SHA-256, HMAC, HKDF, X25519, ChaCha20-Poly1305, demo-grade randomness |
| src/Tls/ | TLS 1.3 over CConn, unauthenticated certificates |
| src/Http/ | HTTP/1.1 request and response framing |
| src/Json/ | JSON parser, lookup and formatting |
| src/Util/ | Serial logging helpers |
| lab/ | Containerized QEMU lab, file staging, mock service |
| tests/ | Network, crypto, TLS, HTTP and JSON tests |

## Contracts

- `NetUp()` returns 0 on success and -1 on failure; repeated successful calls reuse the network.
- `ConnTcpOpen(host, port)` returns a `CConn` or NULL. Dotted-quad addresses bypass DNS.
- `ConnTlsOpen(host, port)` adds TLS; `ConnTlsOpenSni(host, port, sni)` separates the destination address from SNI.
- `CConn` has read/write/close function pointers. Call `c->close(c)` to close and free it.
- `HttpRequest(c, method, host, path, extra_headers, body, body_len)` returns `CHttpResponse` or NULL. Free responses with `HttpResponseFree`; close the connection separately.
- `JsonParse` returns an owned CJson tree; release it with `JsonFree`. JsonGet/JsonStr borrow from that tree.
- Crypto primitives use caller-owned output buffers. X25519 callers must reject all-zero secrets. HKDF expansion is limited to 255 SHA-256 blocks.

## Staging

The lab mounts this repository at /src, and optionally an application at /app. It copies .HC, .HH and .DD files under src/, tests/ and examples/ to corresponding B:/ paths. Duplicate guest paths are errors. The supplied entry path is relative to its repository and runs after all files are delivered.

No application source is vendored into this repository. The mock service uses an Apify-shaped JSON fixture for HTTP/TLS and transport tests; the production API client lives separately.
