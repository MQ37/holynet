// Derived from minexew/Shrine (Unlicense, see LICENSE-Shrine.txt); local changes are listed in PATCHES.md.
#define ICMP_TYPE_ECHO_REPLY      0
#define ICMP_TYPE_ECHO_REQUEST    8

class CIcmpHeader {
  U8 type;
  U8 code;
  U16 checksum;
  U16 identifier;
  U16 seq_number;
};

U8 *icmp_reply = CAlloc(65536);   // flag per echo identifier: reply seen

U16 IcmpComputeChecksum(U8 *buf, I64 size)
{
  I64 i;
  U64 sum = 0;

  for (i = 0; i + 1 < size; i += 2)
    sum += *(buf + i)(U16*);

  if (i < size)
    sum += buf[i];

  while ((sum >> 16) != 0)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum(U16);
}

I64 IcmpSendReply(U32 dest_ip, U16 identifier, U16 seq_number, U8* payload, I64 length) {
  U8* frame;
  I64 index = IPv4PacketAlloc(&frame, IP_PROTO_ICMP, IPv4GetAddress(), dest_ip, sizeof(CIcmpHeader) + length);

  if (index < 0)
    return index;

  CIcmpHeader* hdr = frame;
  hdr->type = ICMP_TYPE_ECHO_REPLY;
  hdr->code = 0;
  hdr->checksum = 0;
  hdr->identifier = identifier;
  hdr->seq_number = seq_number;

  MemCpy(frame + sizeof(CIcmpHeader), payload, length);
  hdr->checksum = IcmpComputeChecksum(frame, sizeof(CIcmpHeader) + length);
  return IPv4PacketFinish(index);
}

I64 IcmpSendRequest(U32 dest_ip, U16 identifier, U16 seq_number, U8* payload, I64 length) {
  U8* frame;
  I64 index = IPv4PacketAlloc(&frame, IP_PROTO_ICMP, IPv4GetAddress(), dest_ip, sizeof(CIcmpHeader) + length);

  if (index < 0)
    return index;

  CIcmpHeader* hdr = frame;
  hdr->type = ICMP_TYPE_ECHO_REQUEST;
  hdr->code = 0;
  hdr->checksum = 0;
  hdr->identifier = identifier;
  hdr->seq_number = seq_number;

  MemCpy(frame + sizeof(CIcmpHeader), payload, length);
  hdr->checksum = IcmpComputeChecksum(frame, sizeof(CIcmpHeader) + length);
  return IPv4PacketFinish(index);
}

I64 icmp_ping_count = 0;

// Sends one echo request and waits for the reply. TRUE if it came within timeout_ms.
Bool IcmpPing(U32 dest_ip, I64 timeout_ms) {
  I64 id = 1 + (icmp_ping_count++ & 0x7fff);

  icmp_reply[id] = 0;

  if (IcmpSendRequest(dest_ip, id, 0, "pingpong", 8) < 0)
    return FALSE;

  I64 maxtime = cnts.jiffies + timeout_ms * JIFFY_FREQ / 1000;

  while (cnts.jiffies < maxtime) {
    if (icmp_reply[id])
      return TRUE;

    Sleep(1);
  }

  return FALSE;
}

I64 IcmpHandler(CIPv4Packet* packet) {
  if (packet->proto != IP_PROTO_ICMP)
    return -1;

  if (packet->length < sizeof(CIcmpHeader))
    return -1;

  CIcmpHeader* hdr = packet->data;

  if (hdr->type == ICMP_TYPE_ECHO_REPLY && hdr->code == 0) {
    icmp_reply[hdr->identifier] = 1;
  }

  if (hdr->type == ICMP_TYPE_ECHO_REQUEST && hdr->code == 0) {
    // This also makes sure that we don't stall NetHandlerTask
    ArpCachePut(packet->source_ip, packet->l2_frame->source_addr);

    IcmpSendReply(packet->source_ip, hdr->identifier, hdr->seq_number,
        packet->data + sizeof(CIcmpHeader), packet->length - sizeof(CIcmpHeader));
  }

  return 0;
}

RegisterL4Protocol(IP_PROTO_ICMP, &IcmpHandler);
