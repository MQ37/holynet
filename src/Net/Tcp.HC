// Derived from minexew/Shrine (Unlicense, see LICENSE-Shrine.txt); local changes are listed in PATCHES.md.
// https://tools.ietf.org/html/rfc793

// See https://en.wikipedia.org/wiki/File:Tcp_state_diagram_fixed_new.svg
#define TCP_STATE_CLOSED        0
#define TCP_STATE_LISTEN        1
#define TCP_STATE_SYN_SENT      2
#define TCP_STATE_SYN_RECEIVED  3
#define TCP_STATE_ESTABLISHED   4
#define TCP_STATE_FIN_WAIT_1    5
#define TCP_STATE_FIN_WAIT_2    6
#define TCP_STATE_CLOSE_WAIT    7
#define TCP_STATE_CLOSING       8
#define TCP_STATE_LAST_ACK      9
#define TCP_STATE_TIME_WAIT     10

#define TCP_CONNECT_TIMEOUT     10000

#define TCP_DEFAULT_MSS         536

#define TCP_MAX_RETRIES         8
#define TCP_CLOSE_TIMEOUT       5000

#define TCP_WINDOW_SIZE         32768     // receive buffer; a power of two, below 64 KiB (no window scaling)

#define TCP_FLAG_FIN            0x01
#define TCP_FLAG_SYN            0x02
#define TCP_FLAG_RST            0x04
#define TCP_FLAG_PSH            0x08
#define TCP_FLAG_ACK            0x10
#define TCP_FLAG_URG            0x20

#define TCP_SRTT_ALPHA          0.9
#define TCP_RTO_MIN             0.2
#define TCP_RTO_MAX             10
#define TCP_RTO_BETA            2

class CTcpHeader {
  U16 source_port;
  U16 dest_port;
  U32 seq;
  U32 ack;
  U8 data_offset;
  U8 flags;
  U16 window_size;
  U16 checksum;
  U16 urgent_pointer;
};

class CTcpSendBufHeader {
  CTcpSendBufHeader* next;

  F64 time_sent;
  U32 length;
  U32 retries;
  U32 seq_start;
  U32 seq_end;
};

class CTcpSocket {
  CSocket sock;

  I64 state;

  U32 local_addr;
  U16 local_port;

  U32 remote_addr;
  U32 remote_port;

  U32 snd_una;    // seq number of first unacknowledged octet
  U32 snd_nxt;    // seq number of next octet to send
  U32 snd_wnd;    // allowed number of unacknowledged outgoing octets
  U32 mss;        // maximum segment size

  U32 rcv_nxt;    // seq number of next octet to receive
  U32 rcv_wnd;    // allowed number of unacknowledged incoming octets

  F64 conntime;
  F64 srtt;

  I64 recv_buf_size;
  U8* recv_buf;
  I64 recv_buf_read_pos;
  I64 recv_buf_write_pos;

  CTcpSocket* backlog_next;
  CTcpSocket* backlog_first;
  CTcpSocket* backlog_last;
  I64 backlog_remaining;

  CTcpSendBufHeader* send_buf_first;
  CTcpSendBufHeader* send_buf_last;

  I64 rcv_adv;    // window we last advertised
  I64 rcvtimeo_ms;
  I64 sndtimeo_ms;
};

class CTcpPseudoHeader {
  U32 source_addr;
  U32 dest_addr;
  U8 zeros;
  U8 protocol;
  U16 tcp_length;
};

class CTcpSocketListItem {
  CTcpSocketListItem *prev;
  CTcpSocketListItem *next;
  CTcpSocket *sock;
};

static CTcpSocketListItem** tcp_socket_list;

// Free space in the receive ring buffer, which is what we may advertise to the peer.
static I64 TcpRecvWindow(CTcpSocket* s) {
  return (s->recv_buf_read_pos - s->recv_buf_write_pos - 1) & (s->recv_buf_size - 1);
}

I64 tcp_retransmits = 0;      // statistics, for tests
I64 tcp_dropped_segments = 0;

static CTcpSocket* GetTcpSocketFromList(CIPv4Packet* packet, CTcpHeader* hdr) {
  CTcpSocketListItem* item = tcp_socket_list[ntohs(hdr->dest_port)]->next;
  while (item) {
    if (item->sock->remote_addr == packet->source_ip &&
      item->sock->remote_port == ntohs(hdr->source_port)) {
      return item->sock;
    }
    item = item->next;
  }
  return NULL;
}

U0 AddTcpSocketToList(CTcpSocket* s) {
  CTcpSocketListItem* prev = tcp_socket_list[s->local_port];
  CTcpSocketListItem* new = CAlloc(sizeof(CTcpSocketListItem));
  while (prev->next) {
    prev = prev->next;
  }
  new->prev = prev;
  new->sock = s;
  prev->next = new;
}

CTcpSocket* RemoveTcpSocketFromList(CTcpSocket* s) {
  CTcpSocketListItem* prev = NULL;
  CTcpSocketListItem* next = NULL;
  CTcpSocketListItem* item = tcp_socket_list[s->local_port]->next;
  while (item) {
    if (item->sock==s) {
      prev = item->prev;
      next = item->next;
      if (prev) {
        prev->next = next;
      }
      if (next) {
        next->prev = prev;
      }
      return s;
    }
    item = item->next;
  }
  return NULL;
}

// TODO: this takes up half a meg, change it to a binary tree or something
static CTcpSocket** tcp_bound_sockets;

static U16 tcp_next_source_port = RandU16();

static Bool TcpIsSynchronizedState(I64 state) {
  return state == TCP_STATE_ESTABLISHED || state == TCP_STATE_FIN_WAIT_1
      || state == TCP_STATE_FIN_WAIT_2 || state == TCP_STATE_CLOSE_WAIT
      || state == TCP_STATE_CLOSING || state == TCP_STATE_LAST_ACK
      || state == TCP_STATE_TIME_WAIT;
}

static U16 TcpPartialChecksum(U32 sum, U8* header, I64 length) {
  I64 nleft = length;
  U16* w = header;

  while (nleft > 1)  {
    sum += *(w++);
    nleft -= 2;
  }

  return sum;
}

static U16 TcpFinalChecksum(U32 sum, U8* header, I64 length) {
  I64 nleft = length;
  U16* w = header;

  while (nleft > 1)  {
    sum += *(w++);
    nleft -= 2;
  }

  // mop up an odd byte, if necessary
  if (nleft == 1) {
    sum += ((*w) & 0x00ff);
  }

  // add back carry outs from top 16 bits to low 16 bits
  sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
  sum += (sum >> 16);         // add carry
  return (~sum) & 0xffff;
}

I64 TcpPacketAlloc(U8** frame_out, U32 source_ip, U16 source_port, U32 dest_ip, U16 dest_port,
    U32 seq, U32 ack, U8 flags, I64 window, I64 length) {
  U8* frame;
  I64 index = IPv4PacketAlloc(&frame, IP_PROTO_TCP, source_ip, dest_ip,
      sizeof(CTcpHeader) + length);

  if (index < 0)
    return index;

  CTcpHeader* hdr = frame;
  hdr->source_port = htons(source_port);
  hdr->dest_port = htons(dest_port);
  hdr->seq = htonl(seq);
  hdr->ack = htonl(ack);
  hdr->data_offset = (sizeof(CTcpHeader) / 4) << 4;
  hdr->flags = flags;
  hdr->window_size = htons(window);
  hdr->checksum = 0;
  hdr->urgent_pointer = 0;

  *frame_out = frame + sizeof(CTcpHeader);
  return index;
}

I64 TcpPacketFinish(I64 index, U32 source_ip, U32 dest_ip, U8* frame, I64 length,
    CTcpSendBufHeader** send_buf_out) {
  CTcpHeader* hdr = frame - sizeof(CTcpHeader);

  CTcpPseudoHeader pseudo;
  pseudo.source_addr = htonl(source_ip);
  pseudo.dest_addr = htonl(dest_ip);
  pseudo.zeros = 0;
  pseudo.protocol = IP_PROTO_TCP;
  pseudo.tcp_length = htons(sizeof(CTcpHeader) + length);

  U32 sum = TcpPartialChecksum(0, &pseudo, sizeof(CTcpPseudoHeader));
  hdr->checksum = TcpFinalChecksum(sum, hdr, sizeof(CTcpHeader) + length);

  if (send_buf_out) {
    CTcpSendBufHeader* sb = MAlloc(sizeof(CTcpSendBufHeader) + sizeof(CTcpHeader) + length);
    sb->next = NULL;
    sb->time_sent = tS;
    sb->length = sizeof(CTcpHeader) + length;
    sb->retries = 0;
    sb->seq_start = ntohl(hdr->seq);
    sb->seq_end = 0;      // NEEDS TO BE SET UPSTREAM

    MemCpy((sb(U8*)) + sizeof(CTcpSendBufHeader), frame, sizeof(CTcpHeader) + length);
    *send_buf_out = sb;
  }

  return IPv4PacketFinish(index);
}

// Send a TCP frame with flags and/or data
I64 TcpSend(U32 local_addr, U16 local_port, U32 remote_addr, U16 remote_port, U32 seq, U32 ack, U8 flags) {
  U8* frame;
  I64 index = TcpPacketAlloc(&frame,
      local_addr, local_port, remote_addr, remote_port,
      seq, ack, flags, 0, 0);

  if (index < 0)
    return index;

  return TcpPacketFinish(index, local_addr, remote_addr, frame, 0, NULL);
}

// Send a TCP frame with flags only, no data
I64 TcpSend2(CTcpSocket* s, U8 flags) {
  U8* frame;
  I64 window = TcpRecvWindow(s);
  I64 index = TcpPacketAlloc(&frame,
      s->local_addr, s->local_port, s->remote_addr, s->remote_port,
      s->snd_nxt, s->rcv_nxt, flags, window, 0);

  if (index < 0)
    return index;

  s->rcv_adv = window;

  if (flags & TCP_FLAG_SYN)
    s->snd_nxt++;

  if (flags & TCP_FLAG_FIN)
    s->snd_nxt++;

  if (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) {
    CTcpSendBufHeader* sb;
    I64 error = TcpPacketFinish(index, s->local_addr, s->remote_addr, frame, 0, &sb);
    sb->seq_end = s->snd_nxt;

    // Append to SendBuf chain
    if (s->send_buf_first)
      s->send_buf_last->next = sb;
    else
      s->send_buf_first = sb;

    s->send_buf_last = sb;
    return error;
  }

  return TcpPacketFinish(index, s->local_addr, s->remote_addr, frame, 0, NULL);
}

// Send a TCP frame with flags and data
I64 TcpSendData2(CTcpSocket* s, U8 flags, U8* data, I64 length) {
  U8* frame;
  I64 window = TcpRecvWindow(s);
  I64 index = TcpPacketAlloc(&frame,
      s->local_addr, s->local_port, s->remote_addr, s->remote_port,
      s->snd_nxt, s->rcv_nxt, flags, window, length);

  if (index < 0)
    return index;

  s->rcv_adv = window;

  if (length)
    MemCpy(frame, data, length);

  s->snd_nxt += length;

  CTcpSendBufHeader* sb;
  I64 error = TcpPacketFinish(index, s->local_addr, s->remote_addr, frame, length, &sb);
  sb->seq_end = s->snd_nxt;

  // Append to SendBuf chain
  if (s->send_buf_first)
    s->send_buf_last->next = sb;
  else
    s->send_buf_first = sb;

  s->send_buf_last = sb;
  return error;
}

I64 TcpParsePacket(CTcpHeader** header_out, U8** data_out, I64* length_out, CIPv4Packet* packet) {
  if (packet->proto != IP_PROTO_TCP)
    return -1;

  // FIXME: validate packet->length
  // FIXME: checksum

  CTcpHeader* hdr = packet->data;
  I64 header_length = (hdr->data_offset >> 4) * 4;


  *header_out = hdr;
  *data_out = packet->data + header_length;
  *length_out = packet->length - header_length;
  return 0;
}

// The send buffer chain is only touched by the task that owns the socket (the receive task just
// advances snd_una), so no locking is needed.
static U0 TcpSocketReapSendBufs(CTcpSocket* s) {
  F64 time = tS;

  while (s->send_buf_first) {
    CTcpSendBufHeader* sb = s->send_buf_first;

    // Acknowledged iff sb->seq_end <= snd_una (modular arithmetic)
    if (((s->snd_una - sb->seq_end) & 0xffffffff) >= 0x80000000)
      break;

    // Segments that were retransmitted say nothing about the round-trip time
    if (!sb->retries)
      s->srtt = (s->srtt * TCP_SRTT_ALPHA) + ((1.0 - TCP_SRTT_ALPHA) * (time - sb->time_sent));

    s->send_buf_first = sb->next;

    if (s->send_buf_first == NULL)
      s->send_buf_last = NULL;

    Free(sb);
  }
}

static U0 TcpSocketFreeSendBufs(CTcpSocket* s) {
  while (s->send_buf_first) {
    CTcpSendBufHeader* sb = s->send_buf_first;
    s->send_buf_first = sb->next;
    Free(sb);
  }

  s->send_buf_last = NULL;
}

// Free acknowledged segments and retransmit the oldest unacknowledged one when its timer runs out
// (exponential backoff; the connection is dropped after TCP_MAX_RETRIES).
static U0 TcpSocketCheckSendBufs(CTcpSocket* s) {
  TcpSocketReapSendBufs(s);

  CTcpSendBufHeader* sb = s->send_buf_first;

  if (!sb)
    return;

  F64 rto = TCP_RTO_BETA * s->srtt;

  if (rto < TCP_RTO_MIN) rto = TCP_RTO_MIN;
  rto *= 1 << sb->retries;
  if (rto > TCP_RTO_MAX) rto = TCP_RTO_MAX;

  if (tS < sb->time_sent + rto)
    return;

  if (sb->retries >= TCP_MAX_RETRIES) {
    s->state = TCP_STATE_CLOSED;
    return;
  }

  U8* frame;
  I64 index = IPv4PacketAlloc(&frame, IP_PROTO_TCP, s->local_addr, s->remote_addr, sb->length);

  if (index < 0)
    return;   // retry later I guess

  MemCpy(frame, (sb(U8*)) + sizeof(CTcpSendBufHeader), sb->length);
  IPv4PacketFinish(index);

  sb->time_sent = tS;
  sb->retries++;
  tcp_retransmits++;
}

I64 TcpSocketAccept(CTcpSocket* s, sockaddr* addr, I64 addrlen) {
  if (s->state != TCP_STATE_LISTEN)
    return -1;

  while (1) {
    // TODO: Thread safe?
    if (s->backlog_first) {
      CTcpSocket* new_socket = s->backlog_first;
      // "Retr %p\n", new_socket;

      s->backlog_first = s->backlog_first->backlog_next;
      if (!s->backlog_first)
        s->backlog_last = NULL;

      s->backlog_remaining++;

      // TODO: this should be done in a way that doesn't block on accept()
      I64 maxtime = cnts.jiffies + TCP_CONNECT_TIMEOUT * JIFFY_FREQ / 1000;

      while (cnts.jiffies < maxtime) {
        if (new_socket->state == TCP_STATE_ESTABLISHED || new_socket->state == TCP_STATE_CLOSED)
          break;
        else
          Yield;
      }

      if (new_socket->state != TCP_STATE_ESTABLISHED) {
        close(new_socket);
        return -1;
      }

      return new_socket;
    }
    else
      Yield;
  }

  no_warn addr;   // FIXME
  no_warn addrlen;
  return -1;
}

I64 TcpSocketBind(CTcpSocket* s, sockaddr* addr, I64 addrlen) {
  if (addrlen < sizeof(sockaddr_in))
    return -1;

  if (s->state != TCP_STATE_CLOSED)
    return -1;

  sockaddr_in* addr_in = addr;

  U16 local_port = ntohs(addr_in->sin_port);

  // TODO: address & stuff
  if (tcp_bound_sockets[local_port] != NULL)
    return -1;

  tcp_bound_sockets[local_port] = s;

  s->local_addr = IPv4GetAddress();
  s->local_port = local_port;

  return 0;
}

I64 TcpSocketClose(CTcpSocket* s) {
  /* https://tools.ietf.org/html/rfc793#section-3.5
    Case 1:  Local user initiates the close

    In this case, a FIN segment can be constructed and placed on the
    outgoing segment queue.  No further SENDs from the user will be
    accepted by the TCP, and it enters the FIN-WAIT-1 state.  RECEIVEs
    are allowed in this state.  All segments preceding and including FIN
    will be retransmitted until acknowledged.  When the other TCP has
    both acknowledged the FIN and sent a FIN of its own, the first TCP
    can ACK this FIN.  Note that a TCP receiving a FIN will ACK but not
    send its own FIN until its user has CLOSED the connection also.
  */
  I64 maxtime = cnts.jiffies + TCP_CLOSE_TIMEOUT * JIFFY_FREQ / 1000;

  if (s->state == TCP_STATE_ESTABLISHED || s->state == TCP_STATE_CLOSE_WAIT) {
    // The state must change before the FIN leaves, the peer's FIN can arrive in the same segment as its ACK
    if (s->state == TCP_STATE_ESTABLISHED)
      s->state = TCP_STATE_FIN_WAIT_1;
    else
      s->state = TCP_STATE_LAST_ACK;

    while (TcpSend2(s, TCP_FLAG_FIN | TCP_FLAG_ACK) < 0 && cnts.jiffies < maxtime) {
      TcpSocketCheckSendBufs(s);
      Yield;
    }

    // Wait until our FIN is acknowledged and, if we closed first, the peer's FIN has arrived.
    // Whatever the peer still sends meanwhile is discarded so its window cannot fill up.
    while (cnts.jiffies < maxtime && s->state != TCP_STATE_CLOSED && s->state != TCP_STATE_TIME_WAIT
        && !(s->state == TCP_STATE_LAST_ACK && s->snd_una == s->snd_nxt)) {
      TcpSocketCheckSendBufs(s);
      s->recv_buf_read_pos = s->recv_buf_write_pos;
      Yield;
    }
  }

  // Not shut down cleanly? RST it!
  if (TcpIsSynchronizedState(s->state) && s->state != TCP_STATE_TIME_WAIT
      && !(s->state == TCP_STATE_LAST_ACK && s->snd_una == s->snd_nxt)) {
    TcpSend2(s, TCP_FLAG_RST);
  }

  // Free backlog
  CTcpSocket* backlog = s->backlog_first;
  CTcpSocket* backlog2;

  while (backlog) {
    backlog2 = backlog->backlog_next;
    close(backlog);
    backlog = backlog2;
  }

  s->state = TCP_STATE_CLOSED;

  if (s->local_port)
    if (!RemoveTcpSocketFromList(s))
      tcp_bound_sockets[s->local_port] = NULL;

  TcpSocketFreeSendBufs(s);
  Free(s->recv_buf);
  Free(s);
  return 0;
}

I64 TcpSocketConnect(CTcpSocket* s, sockaddr* addr, I64 addrlen) {
  if (addrlen < sizeof(sockaddr_in))
    return -1;

  if (s->state != TCP_STATE_CLOSED)
    return -1;

  sockaddr_in* addr_in = addr;

  U16 local_port = 0x8000 + (tcp_next_source_port & 0x7fff);
  tcp_next_source_port++;

  // TODO: address & stuff
  if (tcp_bound_sockets[local_port] != NULL)
    return -1;

  tcp_bound_sockets[local_port] = s;

  s->local_addr = IPv4GetAddress();
  s->local_port = local_port;
  s->remote_addr = ntohl(addr_in->sin_addr.s_addr);
  s->remote_port = ntohs(addr_in->sin_port);

  s->snd_una = RandU32();
  s->snd_nxt = s->snd_una;
  s->snd_wnd = 0;
  s->mss = TCP_DEFAULT_MSS;

  s->rcv_nxt = 0;
  s->rcv_wnd = TCP_WINDOW_SIZE;

  s->conntime = tS;

  I64 maxtime = cnts.jiffies + TCP_CONNECT_TIMEOUT * JIFFY_FREQ / 1000;

  // The SYN-ACK is only accepted in SYN-SENT, so the state must be set before the SYN leaves
  s->state = TCP_STATE_SYN_SENT;

  while (TcpSend2(s, TCP_FLAG_SYN) < 0) {
    if (cnts.jiffies >= maxtime)
      return -1;

    Yield;
  }

  while (cnts.jiffies < maxtime) {
    if (s->state == TCP_STATE_ESTABLISHED || s->state == TCP_STATE_CLOSED)
      break;

    TcpSocketCheckSendBufs(s);
    Yield;
  }

  if (s->state != TCP_STATE_ESTABLISHED)
    return -1;

  return 0;
}

I64 TcpSocketListen(CTcpSocket* s, I64 backlog) {
  if (s->state != TCP_STATE_CLOSED)
    return -1;

  // Enter listen state. If a SYN packet arrives, it will be processed by TcpHandler,
  // which opens the connection and puts the new socket into the listening socket's accept backlog.
  s->state = TCP_STATE_LISTEN;
  s->backlog_remaining = backlog;

  return 0;
}

I64 TcpSocketRecvfrom(CTcpSocket* s, U8* buf, I64 len, I64 flags, sockaddr* src_addr, I64 addrlen) {
  no_warn flags;
  no_warn src_addr;   // FIXME
  no_warn addrlen;

  if (len == 0)
    return 0;

  I64 maxtime = 0;

  if (s->rcvtimeo_ms)
    maxtime = cnts.jiffies + s->rcvtimeo_ms * JIFFY_FREQ / 1000;

  // Block until there is data, the peer closed (0) or the connection broke / timed out (-1).
  // Data that arrived together with the FIN stays readable.
  while (s->recv_buf_read_pos == s->recv_buf_write_pos) {
    if (s->state != TCP_STATE_ESTABLISHED && s->state != TCP_STATE_FIN_WAIT_1
        && s->state != TCP_STATE_FIN_WAIT_2) {
      if (s->recv_buf_read_pos != s->recv_buf_write_pos)
        break;

      if (s->state == TCP_STATE_CLOSED)
        return -1;

      return 0;
    }

    if (maxtime && cnts.jiffies > maxtime)
      return -1;

    TcpSocketCheckSendBufs(s);
    Sleep(1);
  }

  I64 read_pos = s->recv_buf_read_pos;
  I64 write_pos = s->recv_buf_write_pos;

  I64 read_total = 0;
  I64 step;

  if (write_pos < read_pos) {
    // We can read up to the end of the buffer
    step = s->recv_buf_size - read_pos;

    if (step > len)
      step = len;

    MemCpy(buf, s->recv_buf + read_pos, step);
    buf += step;
    len -= step;
    read_pos = (read_pos + step) & (s->recv_buf_size - 1);
    read_total += step;

    // at this point, (len == 0 || read_pos == 0) must be true
  }

  if (len) {
    step = write_pos - read_pos;

    if (step > len)
      step = len;

    MemCpy(buf, s->recv_buf + read_pos, step);
    buf += step;
    len -= step;
    read_pos += step;
    read_total += step;
  }

  s->recv_buf_read_pos = read_pos;

  // Tell the peer when a closed (or nearly closed) window has opened up again
  if (s->state == TCP_STATE_ESTABLISHED || s->state == TCP_STATE_FIN_WAIT_1
      || s->state == TCP_STATE_FIN_WAIT_2 || s->state == TCP_STATE_CLOSE_WAIT) {
    I64 window = TcpRecvWindow(s);

    if (window - s->rcv_adv >= s->recv_buf_size / 4 || (s->rcv_adv < s->mss && window >= s->mss))
      TcpSend2(s, TCP_FLAG_ACK);
  }

  return read_total;
}

// This function blocks until at least some data is sent.
// Then it returns if the transmission window or outgoing buffers are full.
I64 TcpSocketSendto(CTcpSocket* s, U8* buf, I64 len, I64 flags, sockaddr_in* dest_addr, I64 addrlen) {
  no_warn dest_addr;    // TODO: should be validated instead, no?
  no_warn addrlen;
  no_warn flags;

  I64 sent_total = 0;
  I64 timeout = s->sndtimeo_ms * JIFFY_FREQ / 1000;
  I64 deadline = cnts.jiffies + timeout;
  F64 probe_time = tS + 1.0;

  // Sends everything, waiting for the peer's window. Gives up when the connection breaks or,
  // if a send timeout is set, when no byte could be sent for that long.
  while (len) {
    if (s->state != TCP_STATE_ESTABLISHED && s->state != TCP_STATE_CLOSE_WAIT)
      return -1;

    I64 in_flight = (s->snd_nxt - s->snd_una) & 0xffffffff;
    I64 can_send = s->snd_wnd - in_flight;

    if (can_send > len)
      can_send = len;

    if (can_send > s->mss)
      can_send = s->mss;

    if (can_send > 0 && TcpSendData2(s, TCP_FLAG_ACK | TCP_FLAG_PSH, buf, can_send) >= 0) {
      buf += can_send;
      len -= can_send;
      sent_total += can_send;
      deadline = cnts.jiffies + timeout;
      probe_time = tS + 1.0;
    }
    else {
      // Window full or no out-buffers available: wait for acknowledgements, re-transmit as needed
      if (timeout && cnts.jiffies > deadline)
        return -1;

      // A lost window update would stall us for ever, an ACK makes the peer repeat its window
      if (can_send <= 0 && tS > probe_time) {
        TcpSend2(s, TCP_FLAG_ACK);
        probe_time = tS + 1.0;
      }

      TcpSocketCheckSendBufs(s);
      Yield;
    }
  }

  return sent_total;
}

I64 TcpSocketSetsockopt(CTcpSocket* s, I64 level, I64 optname, U8* optval, I64 optlen) {
  if (level == SOL_SOCKET && optlen == 8) {
    if (optname == SO_RCVTIMEO_MS) {
      s->rcvtimeo_ms = *(optval(I64*));
      return 0;
    }

    if (optname == SO_SNDTIMEO_MS) {
      s->sndtimeo_ms = *(optval(I64*));
      return 0;
    }

    if (optname == SO_RCVBUF_BYTES && s->state == TCP_STATE_CLOSED) {
      I64 size = *(optval(I64*));

      if (size < 1024 || size > TCP_WINDOW_SIZE || (size & (size - 1)))
        return -1;

      Free(s->recv_buf);
      s->recv_buf_size = size;
      s->recv_buf = MAlloc(size);
      s->rcv_adv = size - 1;
      return 0;
    }
  }

  return -1;
}

CTcpSocket* TcpSocket(U16 domain, U16 type) {
  if (domain != AF_INET || type != SOCK_STREAM)
    return NULL;

  CTcpSocket* s =       CAlloc(sizeof(CTcpSocket));
  s->sock.accept =      &TcpSocketAccept;
  s->sock.bind =        &TcpSocketBind;
  s->sock.close =       &TcpSocketClose;
  s->sock.connect =     &TcpSocketConnect;
  s->sock.listen =      &TcpSocketListen;
  s->sock.recvfrom =    &TcpSocketRecvfrom;
  s->sock.sendto =      &TcpSocketSendto;
  s->sock.setsockopt =  &TcpSocketSetsockopt;

  s->state = TCP_STATE_CLOSED;

  s->send_buf_first = NULL;
  s->send_buf_last = NULL;

  s->recv_buf_size = TCP_WINDOW_SIZE;
  s->recv_buf = MAlloc(s->recv_buf_size);
  s->rcv_adv = TCP_WINDOW_SIZE - 1;
  s->recv_buf_read_pos = 0;
  s->recv_buf_write_pos = 0;

  s->backlog_next = NULL;
  s->backlog_first = NULL;
  s->backlog_last = NULL;
  s->backlog_remaining = 0;

  return s;
}

U0 TcpSocketHandle(CTcpSocket* s, CIPv4Packet* packet, CTcpHeader* hdr, U8* data, I64 length) {
  U32 seg_len = length;

  if (hdr->flags & TCP_FLAG_FIN) seg_len++;
  if (hdr->flags & TCP_FLAG_SYN) seg_len++;

  U32 seg_seq = ntohl(hdr->seq);

  if (s->state == TCP_STATE_LISTEN) {
    // A new connection is being opened.

    if ((hdr->flags & TCP_FLAG_SYN) && s->backlog_remaining > 0) {
      CTcpSocket* new_socket = TcpSocket(AF_INET, SOCK_STREAM);

      new_socket->local_addr = IPv4GetAddress();
      new_socket->local_port = s->local_port;
      new_socket->remote_addr = packet->source_ip;
      new_socket->remote_port = ntohs(hdr->source_port);

      new_socket->snd_una = 0;
      new_socket->snd_nxt = 0;
      new_socket->snd_wnd = 0;
      new_socket->mss = TCP_DEFAULT_MSS;

      new_socket->rcv_nxt = ++seg_seq;
      new_socket->rcv_wnd= TCP_WINDOW_SIZE;

      new_socket->conntime = tS;

      TcpSend2(new_socket, TCP_FLAG_SYN | TCP_FLAG_ACK);
      new_socket->state = TCP_STATE_SYN_RECEIVED;

      AddTcpSocketToList(new_socket);

      if (s->backlog_last)
        s->backlog_last->backlog_next = new_socket;
      else
        s->backlog_first = new_socket;

      s->backlog_last = new_socket;
      s->backlog_remaining--;
    }
    else {
      TcpSend(packet->dest_ip, ntohs(hdr->dest_port), packet->source_ip, ntohs(hdr->source_port),
          seg_seq + 1, seg_seq + 1, TCP_FLAG_ACK | TCP_FLAG_RST);
    }

    return;
  }

  if (s->state == TCP_STATE_CLOSED)
    return;

  Bool must_ack = FALSE;

  // Process SYN (a repeated SYN-ACK must not move rcv_nxt back)
  if (hdr->flags & TCP_FLAG_SYN) {
    if (s->state == TCP_STATE_SYN_SENT)
      s->rcv_nxt = ++seg_seq;

    must_ack = TRUE;
  }

  s->rcv_wnd = TcpRecvWindow(s);

  // Validate SEQ
  Bool valid_seq;

  if (seg_len == 0 && s->rcv_wnd == 0) {
    valid_seq = (seg_seq == s->rcv_nxt);
  }
  else {
    // At least one of these must be true:
    //   RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    //   RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    I64 rel_seq = ((seg_seq - s->rcv_nxt) & 0xffffffff);
    I64 rel_seq_end = ((seg_seq + seg_len - 1 - s->rcv_nxt) & 0xffffffff);

    if (rel_seq < s->rcv_wnd || rel_seq_end < s->rcv_wnd)
      valid_seq = TRUE;
    else
      valid_seq = FALSE;
  }

  // Process ACK
  if (hdr->flags & TCP_FLAG_ACK) {
    U32 seg_ack = ntohl(hdr->ack);
    // ACK is acceptable iff SND.UNA < SEG.ACK =< SND.NXT

    I64 rel_ack = ((seg_ack - s->snd_una) & 0xffffffff);
    I64 rel_nxt = ((s->snd_nxt - s->snd_una) & 0xffffffff);

    // RFC 793 is poorly worded in this regard, unacceptable ACK
    // is not the opposite of an acceptible (= new) ACK!
    // TODO: Instead of zero, we should compare rel_ack to some NEGATIVE_CONSTANT,
    // so that we don't unnecessarily try to correct every slightly delayed ACK
    if (/*0 < rel_ack &&*/ rel_ack <= rel_nxt) {
      // Accept ACK; the owner of the socket frees the acknowledged segments
      s->snd_una = seg_ack;

      if (valid_seq)
        s->snd_wnd = ntohs(hdr->window_size);

      if (s->state == TCP_STATE_SYN_SENT && (hdr->flags & TCP_FLAG_SYN)) {
        s->state = TCP_STATE_ESTABLISHED;
        s->srtt = tS - s->conntime;
      }
      else if (s->state == TCP_STATE_SYN_RECEIVED) {
        s->state = TCP_STATE_ESTABLISHED;
        s->srtt = tS - s->conntime;
      }
    }
    else {
      // Unacceptable ACK
      if (s->state == TCP_STATE_LISTEN || s->state == TCP_STATE_SYN_SENT
          || s->state == TCP_STATE_SYN_RECEIVED) {
        // Reset
        TcpSend(packet->dest_ip, ntohs(hdr->dest_port), packet->source_ip, ntohs(hdr->source_port),
            seg_ack, seg_seq + seg_len, TCP_FLAG_ACK | TCP_FLAG_RST);
      }
      else if (TcpIsSynchronizedState(s->state) && seg_len) {
        // Send a 'corrective' ACK
        must_ack = TRUE;
      }
    }
  }

  // Process RST
  if (hdr->flags & TCP_FLAG_RST) {
    if ((s->state == TCP_STATE_SYN_SENT)) {
      // If acknowledged
      if (s->snd_una == s->snd_nxt) {
        s->state = TCP_STATE_CLOSED;
        return;
      }
    }
    else if (valid_seq) {
      s->state = TCP_STATE_CLOSED;
      return;
    }
  }

  // Segments outside the window are dropped, but answered so the peer learns where we are
  if (!valid_seq) {
    tcp_dropped_segments++;

    if (!(hdr->flags & TCP_FLAG_RST))
      TcpSend2(s, TCP_FLAG_ACK);

    return;
  }

  if (s->state == TCP_STATE_ESTABLISHED || s->state == TCP_STATE_FIN_WAIT_1
      || s->state == TCP_STATE_FIN_WAIT_2) {
    I64 write_pos = s->recv_buf_write_pos;

    if (length)
      must_ack = TRUE;

    // Skip retransmitted bytes
    while (length && seg_seq != s->rcv_nxt) {
      seg_seq = (seg_seq + 1) & 0xffffffff;
      data++;
      length--;
    }

    // Only the next bytes in sequence are kept, anything after a gap has to be retransmitted
    Bool in_order = (seg_seq == s->rcv_nxt);

    // ugh!
    I64 i = 0;
    for (i = 0; i < length; i++) {
      I64 next_pos = (write_pos + 1) & (s->recv_buf_size - 1);

      if (next_pos == s->recv_buf_read_pos)
        break;

      s->recv_buf[write_pos] = data[i];
      write_pos = next_pos;
    }

    s->recv_buf_write_pos = write_pos;
    s->rcv_nxt += i;

    if ((hdr->flags & TCP_FLAG_FIN) && in_order && i == length) {
      must_ack = TRUE;
      s->rcv_nxt++;

      if (s->state == TCP_STATE_ESTABLISHED)
        s->state = TCP_STATE_CLOSE_WAIT;
      else
        s->state = TCP_STATE_TIME_WAIT;
    }
  }

  if (must_ack) {
    TcpSend2(s, TCP_FLAG_ACK);
  }
}

I64 TcpHandler(CIPv4Packet* packet) {
  CTcpHeader* hdr;
  U8* data;
  I64 length;

  I64 error = TcpParsePacket(&hdr, &data, &length, packet);

  if (error < 0)
    return error;

  U16 dest_port = ntohs(hdr->dest_port);

  CTcpSocket* s = GetTcpSocketFromList(packet, hdr);
  if (!s) {
    s = tcp_bound_sockets[dest_port];

    // Only a listening socket takes segments from anybody
    if (s && s->state != TCP_STATE_LISTEN
        && (s->remote_addr != packet->source_ip || s->remote_port != ntohs(hdr->source_port)))
      s = NULL;
  }

  // FIXME: should also check that bound address is INADDR_ANY,
  //        OR packet dest IP matches bound address
  if (s != NULL) {
    TcpSocketHandle(s, packet, hdr, data, length);
  }
  else if (!(hdr->flags & TCP_FLAG_RST)) {
    // RFC793/Reset-Generation, so the peer stops talking to a socket that is gone
    U32 seg_len = length;

    if (hdr->flags & TCP_FLAG_FIN) seg_len++;
    if (hdr->flags & TCP_FLAG_SYN) seg_len++;

    if (hdr->flags & TCP_FLAG_ACK)
      TcpSend(packet->dest_ip, dest_port, packet->source_ip, ntohs(hdr->source_port),
          ntohl(hdr->ack), 0, TCP_FLAG_RST);
    else
      TcpSend(packet->dest_ip, dest_port, packet->source_ip, ntohs(hdr->source_port),
          0, ntohl(hdr->seq) + seg_len, TCP_FLAG_RST | TCP_FLAG_ACK);
  }

  return error;
}

U0 TcpInit() {
  I64 i;
  tcp_bound_sockets = MAlloc(65536 * sizeof(CTcpSocket*));
  MemSet(tcp_bound_sockets, 0, 65536 * sizeof(CTcpSocket*));
  tcp_socket_list = MAlloc(65536 * sizeof(CTcpSocketListItem*));
  for (i=0; i<65536; i++)
  {
    tcp_socket_list[i] = CAlloc(sizeof(CTcpSocketListItem));
  }
}

TcpInit;
RegisterL4Protocol(IP_PROTO_TCP, &TcpHandler);
RegisterSocketClass(AF_INET, SOCK_STREAM, &TcpSocket);
