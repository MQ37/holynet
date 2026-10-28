// Run with: lab/tos --net mockplain tests/ConnTcp.HC
#include "B:/tests/ConnUtil"

#define BIG_PATH "/big"

U0 CheckBig(U8 *resp, I64 n, U8 *what)
{
  I64 want_len, got_len;
  U8 *want = BigExpected(&want_len), *body, *dec;

  TestCheck(resp && HttpStatusOf(resp) == 200, what);
  if (!resp || !(body = HttpBodyOf(resp))) {
    TestCheck(FALSE, "big: no body");
    Free(want);
    return;
  }
  dec = MAlloc(CONN_MAX_RESPONSE);
  got_len = ChunkedDecode(body, n - (body - resp), dec);
  TestCheck(got_len == want_len, "big: chunk framing exact and length");
  TestCheck(got_len == want_len && !MemCmp(dec, want, want_len), "big: every byte matches");
  SerPrint("%s: %d bytes on the wire, %d decoded (want %d)\n", what, n, got_len, want_len);
  Free(dec);
  Free(want);
}

U0 TestBigFast()
{
  I64 n = 0;
  F64 t0 = tS;
  U8 *resp = ConnGet("10.0.2.100", 80, BIG_PATH, "", &n, 4096, 0);
  SerPrint("big fast: %.3f s\n", tS - t0);
  CheckBig(resp, n, "GET /big (4096-byte reads)");
  Free(resp);
}

U0 TestBigSlow()
{
  I64 n = 0, rt0 = tcp_retransmits;
  F64 t0 = tS;

  conn_tcp_rcvbuf = 4096;     // window much smaller than the response: it has to close and reopen
  U8 *resp = ConnGet("10.0.2.100", 80, BIG_PATH, "", &n, 200, 3);
  conn_tcp_rcvbuf = 0;
  SerPrint("big slow: %.3f s, retransmits %d\n", tS - t0, tcp_retransmits - rt0);
  CheckBig(resp, n, "GET /big (slow reader, 4 KiB window)");
  Free(resp);
}

U0 TestUsersMe()
{
  I64 n = 0;
  U8 *resp = ConnGet("10.0.2.100", 80, "/v2/users/me", "Authorization: Bearer test-token\r\n", &n, 4096, 0);

  TestCheck(resp && HttpStatusOf(resp) == 200, "users/me: 200");
  TestCheck(resp && StrFind("mockUser", resp), "users/me: body");
  Free(resp);

  resp = ConnGet("10.0.2.100", 80, "/v2/users/me", "", &n, 4096, 0);
  TestCheck(resp && HttpStatusOf(resp) == 401, "users/me without token: 401");
  Free(resp);
}

// 50 KB JSON body; the mock logs it in mock.log, where the pattern can be checked from the host
#define POST_BODY_LEN 51200

U0 TestPost()
{
  I64 i, n = 0, rt0 = tcp_retransmits;
  U8 *body = MAlloc(POST_BODY_LEN + 1), *req, *resp;
  F64 t0 = tS;

  MemCpy(body, "{\"data\":\"", 9);
  for (i = 9; i < POST_BODY_LEN - 2; i++)
    body[i] = 'a' + (i * 7) % 26;
  MemCpy(body + POST_BODY_LEN - 2, "\"}", 2);
  body[POST_BODY_LEN] = 0;

  CConn *c = ConnTcpOpen("10.0.2.100", 80);
  TestCheck(c != NULL, "post: open");
  if (c) {
    req = MStrPrint("POST /v2/acts/x/run-sync-get-dataset-items HTTP/1.1\r\nHost: api.apify.com\r\n"
        "Connection: close\r\nAuthorization: Bearer test-token\r\nContent-Type: application/json\r\n"
        "Content-Length: %d\r\n\r\n", POST_BODY_LEN);
    TestCheck(ConnWriteStr(c, req) == StrLen(req), "post: headers written");
    Free(req);
    TestCheck(c->write(c, body, POST_BODY_LEN) == POST_BODY_LEN, "post: 50 KB body written");
    resp = ConnReadAll(c, &n, 4096, 0);
    TestCheck(HttpStatusOf(resp) == 201, "post: 201");
    TestCheck(StrFind("example.org", resp) != NULL, "post: response body");
    Free(resp);
    c->close(c);
  }
  SerPrint("post: %.3f s, retransmits %d\n", tS - t0, tcp_retransmits - rt0);
  Free(body);
}

U0 TestRefused()
{
  F64 t0 = tS;
  CConn *c = ConnTcpOpen("10.0.2.100", 81);

  SerPrint("refused: %.3f s\n", tS - t0);
  TestCheck(c == NULL, "closed port: NULL");
  if (c)
    c->close(c);

  TestCheck(ConnTcpOpen(NULL, 80) == NULL, "NULL host");
  TestCheck(ConnTcpOpen("10.0.2.100", 0) == NULL, "port 0");
  TestCheck(ConnTcpOpen("10.0.2.100", 70000) == NULL, "port 70000");
}

// Names do not resolve in the offline lab modes: NULL, no crash, no hang
U0 TestNoDns()
{
  F64 t0 = tS;
  CConn *c = ConnTcpOpen("no-such-host.invalid", 80);

  SerPrint("unresolvable name: %.3f s\n", tS - t0);
  TestCheck(c == NULL, "unresolvable name: NULL");
  if (c)
    c->close(c);
}

// Open and close many times: ports, sockets and buffers must not run out
U0 TestRepeat()
{
  I64 i, n, ok = 0;
  F64 t0 = tS;
  U8 *resp;

  for (i = 0; i < 40; i++) {
    resp = ConnGet("10.0.2.100", 80, "/v2/users/me", "Authorization: Bearer test-token\r\n", &n, 4096, 0);
    if (resp && HttpStatusOf(resp) == 200)
      ok++;
    Free(resp);
  }
  SerPrint("repeat: %d/40 ok in %.3f s\n", ok, tS - t0);
  TestCheck(ok == 40, "40 sequential connections");
}

TestCheck(NetUp == 0, "NetUp");
TestCheck(IcmpPing(0x0A000202, 2000), "ping gateway");
TestBigFast;
TestBigSlow;
TestUsersMe;
TestPost;
TestRefused;
TestRepeat;
TestNoDns;
SerPrint("retransmits total %d, dropped segments %d\n", tcp_retransmits, tcp_dropped_segments);
TestDone;
