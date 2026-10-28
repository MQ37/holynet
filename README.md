<div align="center">

<img src="assets/holynet.png" width="260" alt="An illuminated Christian cross with a gold halo and pixel circuit traces">

<h1>HolyNet</h1>

<p><strong>Let there be GET.</strong><br>
Networking for stock TempleOS. Written in HolyC.<br>
In memory of Terry A. Davis, God's chosen programmer.</p>

<p><code>HolyC only</code> · <code>TempleOS V5.03</code> · <code>TLS 1.3</code> · <code>rootless Podman</code></p>

</div>

---

TempleOS has no built-in networking. HolyNet gives it a PCnet driver, a TCP/IP stack, TLS 1.3, HTTP and JSON. All guest-side code is HolyC. The virtual NIC sends packets. The guest does its own cryptography.

**640 × 480. Sixteen colours. One HTTPS connection.**

> Networking heresy. God intended TempleOS to stay offline. We added TCP/IP anyway.

HolyNet is the foundation. **HolyApify**, in the sibling `holyapify` repository, uses it to run Apify Actors from the TempleOS terminal.

**Experimental, unauthenticated TLS.** Server certificates and CertificateVerify signatures are not validated. The random generator is experimental. Record tags and Finished are checked, but the client cannot establish the server's identity. Use disposable credentials and non-sensitive data only. [Security model →](SECURITY.md)

## The stack

| Layer | Implementation |
|---|---|
| Hardware | AMD PCnet virtual NIC and PCI discovery |
| Network | Ethernet, ARP, IPv4, ICMP, UDP, DHCP and DNS |
| Transport | TCP with receive windows, timeouts and retransmission |
| Crypto | SHA-256, HMAC, HKDF, X25519 and ChaCha20-Poly1305 |
| TLS | TLS 1.3 with X25519 and ChaCha20-Poly1305; no certificate authentication |
| HTTP | HTTP/1.1, Content-Length and chunked bodies, 8 MiB response limit |
| JSON | Parsing, field lookup, escaping and pretty printing |
| Lab | Stock live CD, serial file delivery, automated tests and screenshots |

The network stack is adapted from Shrine. [The patch notes](src/Net/PATCHES.md) cover the changes to its TCP, DNS, driver and timeout handling.

## Boot the lab

You need Linux, rootless Podman and access to `/dev/kvm`. QEMU, TempleOS, the compiler and all test code execute inside the container. No host packages are installed.

From this repository's root:

```sh
podman build -t localhost/tos-lab:1 -f lab/Containerfile .
```

Download the stock ISO inside a container, into RAM-backed storage, and check its expected SHA-256:

```sh
podman run --rm --userns=keep-id --read-only --cap-drop=ALL \
  --security-opt no-new-privileges \
  -v /dev/shm:/scratch:rw localhost/tos-lab:1 sh -eu -c '
    mkdir -p /scratch/templeos-net
    cd /scratch/templeos-net
    curl --fail --location --output TempleOS.ISO \
      https://templeos.org/Downloads/TempleOS.ISO
    echo "5d0fc944e5d89c155c0fc17c148646715bc1db6fa5750c0b913772cfec19ba26  TempleOS.ISO" \
      | sha256sum --check -
  '
```

Then test TLS against the local mock server:

```sh
lab/tos --net mock tests/TlsMock.HC
```

The launcher starts rootless Podman. It boots the stock TempleOS live CD, transfers the source to the guest RAM drive, compiles it there and prints serial test output. A passing run ends with `TOS-DONE fail=0`.

The source tree and ISO are read-only mounts. Screenshots, packet captures and TLS debugging keys go to `/dev/shm/templeos-net/out/`. Everything in that directory disappears on reboot. Choose a separate RAM-backed `TOS_OUT` for concurrent runs; `TOS_ISO` overrides the ISO path.

## Write HolyC

The lab stages library files at `B:/src/` and test files at `B:/tests/`. Includes currently use these fixed paths.

```c
#include "B:/src/HolyNet"

if (NetUp == 0) {
  CConn *conn = ConnTlsOpen("api.apify.com", 443);
  if (conn) {
    CHttpResponse *r = HttpRequest(conn, "GET", "api.apify.com",
      "/v2/users/me", NULL, NULL, 0);
    if (r) {
      Print("HTTP %d\n", r->status);
      HttpResponseFree(r);
    }
    conn->close(conn);
  }
}
```

This example needs `open` networking for DNS. With no token, the expected API response is HTTP 401. In restricted `apify` mode, use `ConnTlsOpenSni("10.0.2.100", 443, "api.apify.com")` instead.

The small `CConn` interface lets HTTP run over TCP, TLS or an in-memory test connection. [API contracts →](docs/ARCHITECTURE.md)

## Network modes

| Mode | Guest access |
|---|---|
| `none` | No external service forwarding; default |
| `mockplain` | Local HTTP fixture at `10.0.2.100:80` |
| `mock` | Local TLS fixture at `10.0.2.100:443` |
| `apify` | Raw TCP forwarding to `api.apify.com` on ports 80 and 443 |
| `open` | General outbound access through QEMU user networking, including DNS |

The forwarder copies raw TCP bytes. It does not terminate TLS. The local fixture happens to use Apify-shaped endpoints, providing repeatable HTTP/TLS tests without an account or external service.

## Tests

```sh
lab/tos tests/CryptoHash.HC
lab/tos tests/TlsHandshake.HC
lab/tos --net mock tests/TlsMock.HC
lab/test-all
```

The full suite runs up to four VMs at a time and exits nonzero if any test fails. It includes unauthenticated real-API checks and one DNS/TCP test with `open` networking.

Coverage includes RFC crypto vectors, handshake rejection, TLS records, HTTP framing, malformed JSON, slow readers, a 50 KB upload and repeated connections. [Validation history and current checks →](docs/STATUS.md)

## Applications bring their own HolyC

Keep an application beside HolyNet:

```text
holynet/                 holyapify/
  src/HolyNet.HC           src/HolyApify.HC
  src/Net/                src/Apify/
  src/Crypto/             tests/
  src/Tls/                lab/
  lab/                    lab/tos  → invokes the HolyNet lab
```

`TOS_APP_DIR` adds an application's `src/` and `tests/` trees to the guest. Both source trees are mounted read-only and staged onto the same RAM drive. Duplicate guest paths are refused. The app's entry file runs after staging; the shared tests and helpers stay available.

## Limits of divine intervention

- Stock TempleOS V5.03 and QEMU's PCnet card are the tested target. Other NICs are not supported.
- TLS supports one cipher suite and one key exchange. Certificate authentication is absent.
- There is no browser, HTTP/2, IPv6 or general-purpose operating-system network service.
- This is experimental code, not audited cryptography. Some test vectors still need transcription checks against their original publications.
- Compilation happens inside TempleOS at runtime. There is no host-side HolyC build step.

## Credits

**Terry A. Davis** created TempleOS and HolyC. HolyNet runs on his work and is dedicated to his memory.

The network stack is derived from [minexew/Shrine](https://github.com/minexew/Shrine), commit `348386b`, under the Unlicense. X25519 follows TweetNaCl's field arithmetic; Poly1305 follows the poly1305-donna 26-bit layout. [Third-party notices →](THIRD_PARTY_NOTICES.md)

No license is granted for original project code. Third-party code retains its existing terms. This is an independent project, not endorsed by the TempleOS project.
