// Run with: lab/tos --net mockplain tests/NetUp.HC
#include "B:/tests/Test"
#include "B:/src/Net/NetUp"

I64 up = NetUp;
TestCheck(up == 0, "NetUp: DHCP lease");
TestCheck(IPv4GetAddress == 0x0A00020F, "NetUp: leased 10.0.2.15");
TestCheck(NetUp == 0, "NetUp twice");
TestCheck(ArpCacheFindByIP(0x0A000202) != NULL || IcmpPing(0x0A000202, 2000), "gateway reachable");
TestCheck(IcmpPing(0x0A000202, 2000), "ping gateway");
TestDone;
