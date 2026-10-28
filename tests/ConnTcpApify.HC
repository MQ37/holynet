// Run with: lab/tos --net apify tests/ConnTcpApify.HC   (only api.apify.com is reachable, via 10.0.2.100)
#include "B:/tests/ConnUtil"

TestCheck(NetUp == 0, "NetUp");

I64 n = 0;
U8 *resp = ConnGet("10.0.2.100", 80, "/v2/users/me", "", &n, 4096, 0);

TestCheck(resp != NULL, "response received");
if (resp) {
  SerPrint("status %d, %d bytes\n", HttpStatusOf(resp), n);
  TestCheck(HttpStatusOf(resp) == 301, "plain HTTP to api.apify.com answers 301");
  TestCheck(StrFind("https://api.apify.com", resp) != NULL, "Location points at https");
}
Free(resp);
TestDone;
