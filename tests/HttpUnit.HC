#include "B:/tests/Test"
#include "B:/src/Http/Http1"
#include "B:/tests/HttpFake"

// Runs one canned response through HttpRequest; fragment size 0 = whole.
CHttpResponse *Fetch(U8 *raw, I64 frag, U8 *method="GET")
{
  CConn *c = FakeNew(raw, StrLen(raw), frag);
  CHttpResponse *r = HttpRequest(c, method, "h", "/p", NULL, NULL, 0);
  FakeClose(c);
  return r;
}

U0 CheckBody(U8 *raw, I64 frag, I64 status, U8 *body, U8 *what)
{
  CHttpResponse *r = Fetch(raw, frag);
  U8 *msg = MStrPrint("%s frag=%d", what, frag);
  if (r) {
    TestCheck(r->status == status, msg);
    TestCheck(!StrCmp(r->body, body) && r->body_len == StrLen(body), msg);
  } else
    TestCheck(FALSE, msg);
  Free(msg);
  HttpResponseFree(r);
}

U0 CheckNull(U8 *raw, U8 *what)
{
  CHttpResponse *r = Fetch(raw, 0);
  TestCheck(!r, what);
  HttpResponseFree(r);
}

I64 frags[7] = {0, 1, 2, 3, 5, 7, 64};

U0 Main()
{
  I64 f;
  CConn *c;
  CFake *fk;
  CHttpResponse *r;
  U8 *big;

  for (f = 0; f < 7; f++) {
    CheckBody("HTTP/1.1 200 OK\r\ncontent-LENGTH: 5\r\nX: y\r\n\r\nhello", frags[f], 200, "hello", "content-length");
    CheckBody("HTTP/1.1 201 Created\r\nTransfer-Encoding: Chunked\r\n\r\n5;ext=1\r\nhello\r\n"
          "A\r\n, world 12\r\n0\r\nTrailer: x\r\nAnother: y\r\n\r\n", frags[f], 201, "hello, world 12", "chunked");
    CheckBody("HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nuntil eof", frags[f], 200, "until eof", "eof body");
    CheckBody("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", frags[f], 200, "ok", "1xx skipped");
    CheckBody("HTTP/1.1 204 No Content\r\n\r\n", frags[f], 204, "", "204");
    CheckBody("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", frags[f], 404, "", "empty");
    CheckBody("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n", frags[f], 200, "", "chunked no final crlf");
  }

  CheckBody("HTTP/1.1 200\r\nContent-Length: 1\r\n\r\nx", 0, 200, "x", "no reason phrase");
  CheckBody("HTTP/1.1 200 OK\nContent-Length: 1\n\nx", 0, 200, "x", "bare LF");
  CheckBody("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef", 0, 200, "abc", "extra bytes ignored");

  CheckNull("", "empty response");
  CheckNull("garbage\r\n\r\n", "garbage status");
  CheckNull("HTTP/2 200 OK\r\n\r\n", "http2 status");
  CheckNull("HTTP/1.1 2x0 OK\r\n\r\n", "bad status digits");
  CheckNull("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", "truncated body");
  CheckNull("HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nx", "bad content-length");
  CheckNull("HTTP/1.1 200 OK\r\nContent-Length: 1", "truncated headers");
  CheckNull("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhi\r\n0\r\n\r\n", "bad chunk size");
  CheckNull("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX\r\n0\r\n\r\n", "chunk without crlf");
  CheckNull("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", "truncated chunk");
  CheckNull("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n000000005\r\nhello\r\n0\r\n\r\n", "chunk size too many digits");

  r = Fetch("HTTP/1.1 200 OK\r\nContent-Length: 9000000\r\n\r\nx", 0);
  TestCheck(r && r->status == HTTP_ERR_TOO_BIG && !r->body_len && !*r->body, "content-length over limit");
  HttpResponseFree(r);
  r = Fetch("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFF\r\nx", 0);
  TestCheck(r && r->status == HTTP_ERR_TOO_BIG, "chunk over limit");
  HttpResponseFree(r);
  r = Fetch("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n", 0);
  TestCheck(r && r->status == HTTP_ERR_TOO_BIG, "huge content-length");
  HttpResponseFree(r);

  // many chunks adding up to the limit: 9 MB of eof body
  big = MAlloc(9 << 20);
  MemSet(big, 'a', 9 << 20);
  StrCpy(big, "HTTP/1.1 200 OK\r\n\r\n");
  c = FakeNew(big, 9 << 20, 0);
  r = HttpRequest(c, "GET", "h", "/", NULL, NULL, 0);
  TestCheck(r && r->status == HTTP_ERR_TOO_BIG, "eof body over limit");
  HttpResponseFree(r);
  FakeClose(c);
  Free(big);

  // request framing
  c = FakeNew("HTTP/1.1 204 No Content\r\n\r\n", 27, 0);
  fk = c->priv;
  r = HttpRequest(c, "POST", "api.example", "/x?y=1", "X-A: 1\r\n", "abc", 3);
  TestCheck(r && r->status == 204, "post response");
  TestCheck(!StrCmp(fk->wbuf, "POST /x?y=1 HTTP/1.1\r\nHost: api.example\r\nConnection: close\r\n"
        "Accept-Encoding: identity\r\nX-A: 1\r\nContent-Length: 3\r\n\r\nabc"), "post request bytes");
  HttpResponseFree(r);
  FakeClose(c);

  c = FakeNew("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody", 40, 0);
  fk = c->priv;
  r = HttpRequest(c, "HEAD", "h", "/", NULL, NULL, 0);
  TestCheck(r && r->status == 200 && !r->body_len, "head has no body");
  TestCheck(!StrCmp(fk->wbuf, "HEAD / HTTP/1.1\r\nHost: h\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"), "head request bytes");
  HttpResponseFree(r);
  FakeClose(c);

  c = FakeNew("", 0, 0);
  TestCheck(!HttpRequest(c, "GET", "h", "/a\r\nX: y", NULL, NULL, 0), "CRLF in path refused");
  TestCheck(!HttpRequest(c, "GET", "h\r\n", "/", NULL, NULL, 0), "CRLF in host refused");
  TestCheck(!HttpRequest(c, "GET", "h", "/", NULL, NULL, 0), "EOF before response");
  FakeClose(c);

  TestDone();
}
Main;
