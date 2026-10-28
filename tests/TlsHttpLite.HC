// Just enough HTTP for the TLS tests: reads one framed response (Content-Length or chunked), no close_notify needed.
I64 TlsLiteReadResponse(CConn *c, U8 *out, I64 cap)
{
  I64 n = 0, r, clen = -1, hdr = -1;
  U8 *p;
  while (n < cap - 1) {
    out[n] = 0;
    if (hdr < 0) {
      p = StrFind("\r\n\r\n", out);
      if (p) {
        hdr = p + 4 - out;
        p = StrFind("Content-Length: ", out);
        if (p)
          clen = Str2I64(p + 16);
      }
    }
    if (hdr >= 0) {
      if (clen >= 0 && n >= hdr + clen)
        return n;
      if (clen < 0 && n >= hdr + 5 && !MemCmp(out + n - 5, "0\r\n\r\n", 5))
        return n;
    }
    r = c->read(c, out + n, cap - 1 - n);
    if (r <= 0)
      return -1;
    n += r;
  }
  return -1;
}
