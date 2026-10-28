// TLS 1.3 against the lab mock API (--net mock): handshake timing, GET, chunked body, 50 KB POST, keep-alive, repeats.
#include "B:/tests/Test"
#include "B:/src/Tls/Tls13"
#include "B:/tests/TlsHttpLite"

#define MOCK_HOST "10.0.2.100"

// Sends a request and reads one framed response (no reliance on close_notify). Returns the byte count or -1.
I64 Fetch(CConn *c, U8 *req, I64 rlen, U8 *out, I64 cap)
{
  if (c->write(c, req, rlen) != rlen)
    return -1;
  return TlsLiteReadResponse(c, out, cap);
}

Bool Has(U8 *hay, U8 *needle)
{
  return StrFind(needle, hay) != NULL;
}

I64 ReadOne(CConn *c, U8 *out, I64 cap)
{
  return TlsLiteReadResponse(c, out, cap);
}

U0 MockTests()
{
  U8 *buf = MAlloc(200000), *req = MAlloc(60000), *hdr;
  CConn *c;
  I64 n, i, t0;
  F64 t;

  t = tS;
  c = ConnTlsOpen(MOCK_HOST, 443);
  SerPrint("handshake %.2f s, err=%s\n", tS - t, tls_err);
  TestCheck(c != NULL, "handshake");
  if (!c) {
    TestDone;
    return;
  }

  hdr = "GET /v2/users/me HTTP/1.1\r\nHost: api.apify.com\r\nAuthorization: Bearer test-token\r\nAccept-Encoding: identity\r\n\r\n";
  TestCheck(c->write(c, hdr, StrLen(hdr)) == StrLen(hdr), "write request");
  n = ReadOne(c, buf, 4000);
  TestCheck(n > 0 && Has(buf, "200 OK") && Has(buf, "mockUser"), "GET /v2/users/me");
  TestCheck(c->write(c, hdr, StrLen(hdr)) == StrLen(hdr), "write second request on same connection");
  n = ReadOne(c, buf, 4000);
  TestCheck(n > 0 && Has(buf, "mockUser"), "keep-alive second GET");
  c->close(c);

  hdr = "GET /big HTTP/1.1\r\nHost: x\r\nAccept-Encoding: identity\r\n\r\n";
  c = ConnTlsOpen(MOCK_HOST, 443);
  TestCheck(c != NULL, "handshake for /big");
  n = Fetch(c, hdr, StrLen(hdr), buf, 199999);
  SerPrint("big response %d bytes\n", n);
  TestCheck(n > 15000 && Has(buf, "chunked") && Has(buf, "line 299"), "chunked /big read completely");
  c->close(c);

  // 50 KB POST body: the mock reads Content-Length bytes, so a short or reordered write breaks the reply
  StrPrint(req, "POST /v2/acts/a/run-sync-get-dataset-items HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer test-token\r\n"
    "Content-Type: application/json\r\nContent-Length: 50000\r\n\r\n");
  n = StrLen(req);
  for (i = 0; i < 50000; i++)
    req[n + i] = 'a' + i % 26;
  c = ConnTlsOpen(MOCK_HOST, 443);
  TestCheck(c != NULL, "handshake for POST");
  n = Fetch(c, req, n + 50000, buf, 199999);
  TestCheck(n > 0 && Has(buf, "201 Created") && Has(buf, "Example Org"), "50 KB POST accepted");
  c->close(c);

  // many sessions in a row: sequence numbers, buffering, close
  hdr = "GET /v2/users/me HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer test-token\r\n\r\n";
  t0 = 0;
  for (i = 0; i < 12; i++) {
    c = ConnTlsOpen(MOCK_HOST, 443);
    if (!c) {
      SerPrint("run %d: open failed: %s\n", i, tls_err);
      break;
    }
    n = Fetch(c, hdr, StrLen(hdr), buf, 199999);
    if (n > 0 && Has(buf, "mockUser"))
      t0++;
    c->close(c);
  }
  TestCheck(t0 == 12, "12 sessions in a row");

  // one connection, many requests
  c = ConnTlsOpen(MOCK_HOST, 443);
  hdr = "GET /v2/users/me HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer test-token\r\n\r\n";
  t0 = 0;
  for (i = 0; i < 40 && c; i++) {
    c->write(c, hdr, StrLen(hdr));
    if (ReadOne(c, buf, 4000) > 0 && Has(buf, "mockUser"))
      t0++;
  }
  TestCheck(t0 == 40, "40 requests on one connection");
  if (c)
    c->close(c);
  Free(buf);
  Free(req);
}

TestCheck(NetUp == 0, "NetUp");
MockTests;
TestDone;
