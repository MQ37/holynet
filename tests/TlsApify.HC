// TLS 1.3 against the real api.apify.com (--net apify): handshake and one unauthenticated request, expects 401 + JSON error.
#include "B:/tests/Test"
#include "B:/src/Tls/Tls13"
#include "B:/tests/TlsHttpLite"

TestCheck(NetUp == 0, "NetUp");
F64 t = tS;
CConn *c = ConnTlsOpenSni("10.0.2.100", 443, "api.apify.com");
SerPrint("handshake %.2f s, err=%s\n", tS - t, tls_err);
TestCheck(c != NULL, "handshake with api.apify.com");
if (c) {
  U8 *req = "GET /v2/users/me HTTP/1.1\r\nHost: api.apify.com\r\nAccept-Encoding: identity\r\n\r\n";
  U8 *buf = MAlloc(20000);
  I64 n;
  c->write(c, req, StrLen(req));
  n = TlsLiteReadResponse(c, buf, 20000);
  SerPrint("%d bytes: %.400s\n", n, buf);
  TestCheck(!MemCmp(buf, "HTTP/1.1 401", 12), "HTTP 401");
  TestCheck(StrFind("\"error\"", buf) != NULL, "JSON error body");
  c->close(c);
  Free(buf);
}
TestDone;
