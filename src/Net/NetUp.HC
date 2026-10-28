// Brings up the vendored Shrine network stack (PCnet driver, ARP/IPv4/ICMP/UDP/TCP, DNS, DHCP).
// Including this file loads the stack; calling NetUp starts the receive task and runs DHCP.
#ifndef NETUP_HC
#define NETUP_HC

Option(OPTf_WARN_PAREN, OFF);
Option(OPTf_WARN_DUP_TYPES, OFF);

#include "B:/src/Net/NetFifo"
#include "B:/src/Net/PCNet"
#include "B:/src/Net/NativeSocket"
#include "B:/src/Net/Ethernet"
#include "B:/src/Net/Arp"
#include "B:/src/Net/IPv4"
#include "B:/src/Net/Icmp"
#include "B:/src/Net/Tcp"
#include "B:/src/Net/Udp"
#include "B:/src/Net/Dns"
#include "B:/src/Net/NetHandlerTask"
#include "B:/src/Net/Netcfg"

Option(OPTf_WARN_PAREN, ON);
Option(OPTf_WARN_DUP_TYPES, ON);

#define NETUP_CARD_TIMEOUT_MS 5000

// 0 on success (card found, DHCP lease obtained), -1 otherwise. Safe to call again once it succeeded.
I64 NetUp()
{
  if (IPv4GetAddress)
    return 0;

  if (!netfifo_handler_task)
    netfifo_handler_task = Spawn(&NetHandlerTask, NULL, "NetHandler");

  I64 maxtime = cnts.jiffies + NETUP_CARD_TIMEOUT_MS * JIFFY_FREQ / 1000;

  while (!pcnet_ready) {
    if (cnts.jiffies > maxtime)
      return -1;

    Sleep(10);
  }

  return DhcpConfigure;
}

#endif
