// Helpers shared by the ConnTcp tests: a raw HTTP/1.1 request over a CConn, chunked decoding, the mock's /big body.
#include "B:/tests/Test"
#include "B:/src/Net/ConnTcp"

Option(OPTf_WARN_DUP_TYPES, OFF);
Option(OPTf_WARN_PAREN, OFF);

#define CONN_MAX_RESPONSE 262144

// Reads until EOF (or error) with reads of `chunk` bytes, sleeping `pause_ms` after each. NUL terminated.
U8 *ConnReadAll(CConn *c, I64 *len_out, I64 chunk, I64 pause_ms)
{
  U8 *buf = MAlloc(CONN_MAX_RESPONSE + 1);
  I64 n = 0, r;

  while (n < CONN_MAX_RESPONSE) {
    r = c->read(c, buf + n, Min(chunk, CONN_MAX_RESPONSE - n));
    if (r <= 0)
      break;
    n += r;
    if (pause_ms)
      Sleep(pause_ms);
  }
  buf[n] = 0;
  *len_out = n;
  return buf;
}

I64 HttpStatusOf(U8 *resp)
{
  if (StrNCmp(resp, "HTTP/1.", 7) || resp[8] != ' ')
    return -1;
  return Str2I64(resp + 9);
}

U8 *HttpBodyOf(U8 *resp)
{
  U8 *p = StrFind("\r\n\r\n", resp);
  if (!p)
    return NULL;
  return p + 4;
}

// Decodes a chunked body into out; returns the decoded length, or -1 unless the framing is exact up to the final chunk.
I64 ChunkedDecode(U8 *body, I64 len, U8 *out)
{
  U8 *p = body, *end = body + len;
  I64 n = 0, size, i;

  while (TRUE) {
    size = 0;
    i = 0;
    while (p < end && *p != '\r') {
      if (!(('0' <= *p <= '9') || ('a' <= *p <= 'f')))
        return -1;
      if (*p <= '9')
        size = size * 16 + *p - '0';
      else
        size = size * 16 + *p - 'a' + 10;
      p++;
      i++;
    }
    if (!i || p + 2 > end || p[1] != '\n')
      return -1;
    p += 2;
    if (!size) {
      if (p + 2 == end && p[0] == '\r' && p[1] == '\n')
        return n;
      return -1;
    }
    if (p + size + 2 > end || p[size] != '\r' || p[size + 1] != '\n')
      return -1;
    MemCpy(out + n, p, size);
    n += size;
    p += size + 2;
  }
}

// What the mock's GET /big returns after chunk decoding (json.dumps of 300 small objects)
U8 *BigExpected(I64 *len_out)
{
  U8 *buf = MAlloc(CONN_MAX_RESPONSE), *p = buf;
  I64 i;

  *p++ = '[';
  for (i = 0; i < 300; i++) {
    if (i)
      p += StrLen(StrPrint(p, ", "));
    p += StrLen(StrPrint(p, "{\"i\": %d, \"text\": \"line %d \\u00e9 \\\"quoted\\\"\"}", i, i));
  }
  *p++ = ']';
  *len_out = p - buf;
  return buf;
}

// GET path from the mock/relay, Connection: close; returns the whole response (caller Frees) or NULL
U8 *ConnGet(U8 *host, I64 port, U8 *path, U8 *extra_headers, I64 *len_out, I64 chunk, I64 pause_ms)
{
  CConn *c = ConnTcpOpen(host, port);
  if (!c)
    return NULL;

  U8 *req = MStrPrint("GET %s HTTP/1.1\r\nHost: api.apify.com\r\nConnection: close\r\nAccept-Encoding: identity\r\n%s\r\n",
      path, extra_headers);
  Bool ok = ConnWriteStr(c, req) == StrLen(req);
  Free(req);

  U8 *resp = NULL;
  if (ok)
    resp = ConnReadAll(c, len_out, chunk, pause_ms);
  c->close(c);
  return resp;
}
