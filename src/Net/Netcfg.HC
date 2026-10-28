// Derived from minexew/Shrine (Unlicense, see LICENSE-Shrine.txt); local changes are listed in PATCHES.md.
#include "B:/src/Net/Dhcp"

#define CLIENT_START            0
#define CLIENT_DISCOVER         1
#define CLIENT_REQUEST          2
#define CLIENT_REQUEST_ACCEPTED 3

#define DHCP_TIMEOUT  3000
#define MAX_RETRIES   3

I64 DhcpConfigureInner(I64 sock, U32* yiaddr_out, U32* dns_ip_out, U32* router_ip_out, U32* subnet_mask_out) {
  I64 state = CLIENT_START;
  I64 retries = 0;

  I64 timeout = DHCP_TIMEOUT;

  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_MS, &timeout, sizeof(timeout)) < 0)
    return -1;

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(68);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, &addr, sizeof(addr)) < 0)
    return -1;

  U32 xid = DhcpBeginTransaction();

  I64 error = 0;

  U32 dhcp_addr;
  U8 buffer[2048];

  I64 count;
  sockaddr_in addr_in;

  while (state != CLIENT_REQUEST_ACCEPTED) {
    if (state == CLIENT_START) {
      state = CLIENT_DISCOVER;
      retries = 0;
    }
    else if (state == CLIENT_DISCOVER) {
      error = DhcpSendDiscover(xid);
      if (error < 0) return error;

      count = recvfrom(sock, buffer, sizeof(buffer), 0, &addr_in, sizeof(addr_in));

      if (count > 0)
        error = DhcpParseOffer(xid, buffer, count, yiaddr_out, dns_ip_out, router_ip_out, subnet_mask_out);

      if (count > 0 && error >= 0) {
        dhcp_addr = ntohl(addr_in.sin_addr.s_addr);

        state = CLIENT_REQUEST;
        retries = 0;
      }
      else if (++retries == MAX_RETRIES) {
        return -1;
      }
    }
    else if (state == CLIENT_REQUEST) {
      error = DhcpSendRequest(xid, *yiaddr_out, dhcp_addr);
      if (error < 0) return error;

      count = recvfrom(sock, buffer, sizeof(buffer), 0, &addr_in, sizeof(addr_in));

      if (count > 0)
        error = DhcpParseAck(xid, buffer, count);

      if (count > 0 && error >= 0) {
        dhcp_addr = ntohl(addr_in.sin_addr.s_addr);
        state = CLIENT_REQUEST_ACCEPTED;
      }
      else if (++retries == MAX_RETRIES) {
        return -1;
      }
    }
  }

  return state;
}

I64 DhcpConfigure() {
  I64 sock = socket(AF_INET, SOCK_DGRAM);

  if (sock < 0)
    return -1;

  U32 yiaddr = 0, dns_ip = 0, router_ip = 0, subnet_mask = 0;
  I64 state = DhcpConfigureInner(sock, &yiaddr, &dns_ip, &router_ip, &subnet_mask);

  close(sock);

  if (state != CLIENT_REQUEST_ACCEPTED)
    return -1;

  IPv4SetAddress(yiaddr);
  IPv4SetSubnet(router_ip, subnet_mask);
  DnsSetResolverIPv4(dns_ip);
  return 0;
}
