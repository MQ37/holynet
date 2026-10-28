// HTTP/1.1 client over any CConn. One request per connection (Connection: close).
// Response framing: 1xx skipped, then chunked, Content-Length or read-to-EOF.
// Malformed input returns NULL; a body over HTTP_MAX_BODY returns status HTTP_ERR_TOO_BIG and no body.
#ifndef HTTP1_HC
#define HTTP1_HC

#include "B:/src/Net/Conn"

#define HTTP_MAX_BODY    0x800000
#define HTTP_MAX_LINE    8192
#define HTTP_MAX_HEADERS 100
#define HTTP_RD_BUF      4096
#define HTTP_ERR_TOO_BIG -2

class CHttpResponse
{
  I64 status;       // HTTP status, or HTTP_ERR_TOO_BIG
  U8 *body;         // NUL-terminated, never NULL
  I64 body_len;
};

class CHttpRd
{
  CConn *c;
  U8 *buf;
  I64 pos, len;
  Bool eof;
};

class CHttpBody
{
  U8 *p;
  I64 n, cap;
};

U0 HttpResponseFree(CHttpResponse *r)
{
  if (r) {
    Free(r->body);
    Free(r);
  }
}

Bool HttpRdFill(CHttpRd *r)
{
  I64 n;
  if (r->eof)
    return FALSE;
  n = r->c->read(r->c, r->buf, HTTP_RD_BUF);
  if (n <= 0) {
    r->eof = TRUE;
    return FALSE;
  }
  r->pos = 0;
  r->len = n;
  return TRUE;
}

I64 HttpRdByte(CHttpRd *r)
{
  if (r->pos >= r->len && !HttpRdFill(r))
    return -1;
  return r->buf[r->pos++];
}

// Reads one line without its CR LF into out. Returns the length, -1 on EOF or a line over max.
I64 HttpRdLine(CHttpRd *r, U8 *out, I64 max)
{
  I64 n = 0, ch;
  while (TRUE) {
    ch = HttpRdByte(r);
    if (ch < 0)
      return -1;
    if (ch == '\n')
      break;
    if (n >= max - 1)
      return -1;
    out[n++] = ch;
  }
  if (n && out[n - 1] == '\r')
    n--;
  out[n] = 0;
  return n;
}

Bool HttpBodyAdd(CHttpBody *b, U8 *data, I64 n)
{
  U8 *p;
  I64 cap;
  if (n > HTTP_MAX_BODY - b->n)
    return FALSE;
  if (b->n + n + 1 > b->cap) {
    cap = b->cap * 2;
    if (cap < b->n + n + 1)
      cap = b->n + n + 1;
    if (cap < 256)
      cap = 256;
    p = MAlloc(cap);
    MemCpy(p, b->p, b->n);
    Free(b->p);
    b->p = p;
    b->cap = cap;
  }
  MemCpy(b->p + b->n, data, n);
  b->n += n;
  b->p[b->n] = 0;
  return TRUE;
}

// Copies n body bytes from the reader. Returns 1 ok, 0 truncated, -1 too big.
I64 HttpRdBodyN(CHttpRd *r, CHttpBody *b, I64 n)
{
  I64 k;
  while (n > 0) {
    if (r->pos >= r->len && !HttpRdFill(r))
      return 0;
    k = r->len - r->pos;
    if (k > n)
      k = n;
    if (!HttpBodyAdd(b, r->buf + r->pos, k))
      return -1;
    r->pos += k;
    n -= k;
  }
  return 1;
}

I64 HttpHexVal(I64 ch)
{
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

// Same return codes as HttpRdBodyN. Extensions and trailers are read and dropped.
I64 HttpRdChunked(CHttpRd *r, CHttpBody *b, U8 *line)
{
  I64 size, i, d, rc, n;
  while (TRUE) {
    if (HttpRdLine(r, line, HTTP_MAX_LINE) < 0)
      return 0;
    size = 0;
    for (i = 0; (d = HttpHexVal(line[i])) >= 0; i++) {
      if (i >= 8)
        return 0;
      size = size * 16 + d;
    }
    if (!i || (line[i] && line[i] != ';' && line[i] != ' ' && line[i] != '\t'))
      return 0;
    if (!size)
      break;
    if (size > HTTP_MAX_BODY - b->n)
      return -1;
    rc = HttpRdBodyN(r, b, size);
    if (rc != 1)
      return rc;
    if (HttpRdLine(r, line, HTTP_MAX_LINE) != 0)
      return 0;
  }
  do
    n = HttpRdLine(r, line, HTTP_MAX_LINE);
  while (n > 0);
  return 1;
}

// Reads until EOF. Same return codes as HttpRdBodyN.
I64 HttpRdToEof(CHttpRd *r, CHttpBody *b)
{
  do {
    if (r->pos < r->len) {
      if (!HttpBodyAdd(b, r->buf + r->pos, r->len - r->pos))
        return -1;
      r->pos = r->len;
    }
  } while (HttpRdFill(r));
  return 1;
}

Bool HttpHeaderIs(U8 *line, U8 *name)
{
  I64 n = StrLen(name);
  return !StrNICmp(line, name, n) && line[n] == ':';
}

// Content-Length value, -2 if it is not a plain number, HTTP_MAX_BODY + 1 if absurdly large.
I64 HttpParseLen(U8 *s)
{
  I64 v = 0, digits = 0;
  while (*s == ' ' || *s == '\t')
    s++;
  while (*s >= '0' && *s <= '9') {
    if (++digits > 10)
      return HTTP_MAX_BODY + 1;
    v = v * 10 + *s++ - '0';
  }
  while (*s == ' ' || *s == '\t')
    s++;
  if (!digits || *s)
    return -2;
  return v;
}

Bool HttpIsDigit(I64 ch)
{
  return ch >= '0' && ch <= '9';
}

// Parses "HTTP/1.x SSS ..." and returns SSS, -1 if malformed.
I64 HttpParseStatus(U8 *line, I64 n)
{
  if (n < 12 || StrNCmp(line, "HTTP/1.", 7) || !HttpIsDigit(line[7]) || line[8] != ' ')
    return -1;
  if (!HttpIsDigit(line[9]) || !HttpIsDigit(line[10]) || !HttpIsDigit(line[11]))
    return -1;
  if (n > 12 && line[12] != ' ')
    return -1;
  return (line[9] - '0') * 100 + (line[10] - '0') * 10 + line[11] - '0';
}

CHttpResponse *HttpReadResponse(CConn *c, Bool head)
{
  CHttpRd rd;
  CHttpBody b;
  CHttpResponse *resp = NULL;
  U8 *line = MAlloc(HTTP_MAX_LINE);
  I64 status, n, i, clen = -1, rc = 1;
  Bool chunked = FALSE;

  rd.c = c;
  rd.buf = MAlloc(HTTP_RD_BUF);
  rd.pos = rd.len = 0;
  rd.eof = FALSE;
  b.p = NULL;
  b.n = b.cap = 0;

  while (TRUE) {
    n = HttpRdLine(&rd, line, HTTP_MAX_LINE);
    status = HttpParseStatus(line, n);
    if (status < 0)
      goto done;
    clen = -1;
    chunked = FALSE;
    for (i = 0; TRUE; i++) {
      n = HttpRdLine(&rd, line, HTTP_MAX_LINE);
      if (n < 0 || i >= HTTP_MAX_HEADERS)
        goto done;
      if (!n)
        break;
      if (HttpHeaderIs(line, "content-length"))
        clen = HttpParseLen(line + 15);
      else if (HttpHeaderIs(line, "transfer-encoding") && StrIMatch("chunked", line + 18))
        chunked = TRUE;
    }
    if (status < 100 || status > 199 || status == 101)
      break;
  }

  if (clen == -2)
    goto done;
  if (head || status == 204 || status == 304)
    rc = 1;
  else if (chunked)
    rc = HttpRdChunked(&rd, &b, line);
  else if (clen > HTTP_MAX_BODY)
    rc = -1;
  else if (clen >= 0)
    rc = HttpRdBodyN(&rd, &b, clen);
  else
    rc = HttpRdToEof(&rd, &b);
  if (rc == 0)
    goto done;
  if (rc < 0) {
    Free(b.p);
    b.p = NULL;
    b.n = 0;
    status = HTTP_ERR_TOO_BIG;
  }
  if (!b.p)
    b.p = CAlloc(1);
  resp = MAlloc(sizeof(CHttpResponse));
  resp->status = status;
  resp->body = b.p;
  resp->body_len = b.n;
  b.p = NULL;
done:
  Free(b.p);
  Free(rd.buf);
  Free(line);
  return resp;
}

Bool HttpHasCtl(U8 *s)
{
  for (; *s; s++)
    if (*s < 0x20 || *s == 0x7F)
      return TRUE;
  return FALSE;
}

// extra_headers: zero or more "Name: value\r\n" lines, or NULL. body may be NULL.
// Returns NULL on a connection error or a malformed response. Does not close c.
CHttpResponse *HttpRequest(CConn *c, U8 *method, U8 *host, U8 *path, U8 *extra_headers, U8 *body, I64 body_len)
{
  U8 *head, *req;
  I64 hl, rc;
  Bool is_head;

  if (!extra_headers)
    extra_headers = "";
  if (!body)
    body_len = 0;
  if (HttpHasCtl(method) || HttpHasCtl(host) || HttpHasCtl(path))
    return NULL;
  head = MStrPrint("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept-Encoding: identity\r\n%s",
        method, path, host, extra_headers);
  if (body)
    req = MStrPrint("%sContent-Length: %d\r\n\r\n", head, body_len);
  else
    req = MStrPrint("%s\r\n", head);
  Free(head);
  hl = StrLen(req);
  head = MAlloc(hl + body_len);
  MemCpy(head, req, hl);
  MemCpy(head + hl, body, body_len);
  Free(req);
  rc = c->write(c, head, hl + body_len);
  Free(head);
  if (rc < 0)
    return NULL;
  is_head = !StrCmp(method, "HEAD");
  return HttpReadResponse(c, is_head);
}

#endif
