// CConn over the vendored Shrine TCP stack: ConnTcpOpen resolves, connects and returns a byte stream.
#ifndef CONNTCP_HC
#define CONNTCP_HC

#include "B:/src/Net/Conn"
#include "B:/src/Net/NetUp"

Option(OPTf_WARN_DUP_TYPES, OFF);

#define CONNTCP_TIMEOUT_MS  60000   // default for reads (no data at all) and writes (window stays shut)

// Tuning knob for tests: receive buffer of the next connections in bytes (power of two, <= 32768), 0 = default
I64 conn_tcp_rcvbuf = 0;

// Dotted quads short-circuit DNS. The result is in network byte order, like sockaddr_in wants it.
static Bool ConnTcpResolve(U8 *host, U32 *ip_n)
{
  if (inet_pton(AF_INET, host, ip_n) == 1)
    return TRUE;

  Bool found = FALSE;
  addrinfo *res = NULL, *a;

  if (getaddrinfo(host, NULL, NULL, &res) >= 0) {
    for (a = res; a; a = a->ai_next)
      if (a->ai_family == AF_INET) {
        *ip_n = (a->ai_addr(sockaddr_in *))->sin_addr.s_addr;
        found = TRUE;
        break;
      }
    freeaddrinfo(res);
  }
  return found;
}

static I64 ConnTcpRead(CConn *c, U8 *buf, I64 len)
{
  return recv(c->sock, buf, len, 0);
}

static I64 ConnTcpWrite(CConn *c, U8 *buf, I64 len)
{
  return send(c->sock, buf, len, 0);   // returns len once every byte is on the wire, or < 0
}

static U0 ConnTcpClose(CConn *c)
{
  close(c->sock);
  Free(c);
}

// How long a read may wait for the first byte, for slow servers (e.g. the 300 s Apify sync run).
U0 ConnTcpSetReadTimeout(CConn *c, I64 ms)
{
  setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO_MS, &ms, sizeof(ms));
}

CConn *ConnTcpOpen(U8 *host, I64 port)
{
  if (!host || port < 1 || port > 65535)
    return NULL;

  sockaddr_in addr;
  MemSet(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  if (!ConnTcpResolve(host, &addr.sin_addr.s_addr))
    return NULL;

  I64 fd = socket(AF_INET, SOCK_STREAM);
  if (fd <= 0)
    return NULL;

  I64 timeout = CONNTCP_TIMEOUT_MS;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO_MS, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO_MS, &timeout, sizeof(timeout));
  if (conn_tcp_rcvbuf)
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF_BYTES, &conn_tcp_rcvbuf, sizeof(conn_tcp_rcvbuf));

  if (connect(fd, &addr, sizeof(addr)) < 0) {
    close(fd);
    return NULL;
  }

  CConn *c = CAlloc(sizeof(CConn));
  c->read = &ConnTcpRead;
  c->write = &ConnTcpWrite;
  c->close = &ConnTcpClose;
  c->sock = fd;
  return c;
}

Option(OPTf_WARN_DUP_TYPES, ON);

#endif
