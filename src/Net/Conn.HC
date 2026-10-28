// A byte-stream connection. Plain TCP (ConnTcpOpen) and TLS 1.3 (ConnTlsOpen) both return one,
// so the HTTP client does not care which it talks over.

#ifndef CONN_HC
#define CONN_HC

class CConn
{
  I64 (*read)(CConn *c, U8 *buf, I64 len);        // blocks until >= 1 byte; returns bytes, 0 on EOF, <0 on error
  I64 (*write)(CConn *c, U8 *buf, I64 len);       // returns len on success, <0 on error
  U0  (*close)(CConn *c);                         // closes and frees the connection
  I64 sock;                                       // underlying TCP socket (owned by the TCP layer)
  U8 *priv;                                       // per-implementation state
};

I64 ConnReadFull(CConn *c, U8 *buf, I64 len)      // read exactly len bytes, or return <len on EOF/error
{
  I64 got = 0, n;
  while (got < len) {
    n = c->read(c, buf + got, len - got);
    if (n <= 0)
      break;
    got += n;
  }
  return got;
}

I64 ConnWriteStr(CConn *c, U8 *s)
{
  return c->write(c, s, StrLen(s));
}

#endif
