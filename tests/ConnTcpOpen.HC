// Run with: lab/tos --net open tests/ConnTcpOpen.HC   (needs the internet: resolves api.apify.com through the lab's DNS)
#include "B:/tests/ConnUtil"

TestCheck(NetUp == 0, "NetUp");

addrinfo *res = NULL;
F64 t0 = tS;
I64 err = getaddrinfo("api.apify.com", NULL, NULL, &res);

TestCheck(err >= 0 && res != NULL, "DNS: api.apify.com resolves");
if (res) {
  U8 text[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(res->ai_addr(sockaddr_in *))->sin_addr, text, INET_ADDRSTRLEN);
  SerPrint("api.apify.com = %s (%.3f s)\n", text, tS - t0);
  freeaddrinfo(res);
}

t0 = tS;
CConn *c = ConnTcpOpen("api.apify.com", 443);
SerPrint("connect by name: %.3f s\n", tS - t0);
TestCheck(c != NULL, "ConnTcpOpen by name");
if (c)
  c->close(c);

c = ConnTcpOpen("no-such-host.invalid", 443);
TestCheck(c == NULL, "unresolvable name: NULL");
TestDone;
