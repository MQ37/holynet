# Patches to the vendored Shrine network stack

Source: github.com/minexew/Shrine (Unlicense, `LICENSE-Shrine.txt`), commit 348386b, files `Adam/HwSupp/{Pci,PCNet}.HC`
and `Adam/Net/*.HC`. Not vendored: Http, Url, UrlParse, Socket (serial bridge helpers), SnailLib, MakeNet.
Every vendored file starts with a one-line derivation note. Includes now read `B:/src/Net/...`; the load order of
`MakeNet.HC` lives in `NetUp.HC`. Our own files: `Conn.HC`, `ConnTcp.HC`, `NetUp.HC`.

## All files
- Debug output (`"$FG,4$..."` prints to the terminal) and commented-out debug prints removed; errors are return codes.

## NetHandlerTask.HC
- The handler task is no longer spawned at load time; `NetUp` spawns it.

## PCNet.HC
- `pcnet_ready` flag set when the card is initialised, so `NetUp` knows when DHCP can start.
- Tx descriptor claim is serialised with a bit lock (`pcnet_tx_lock`): the receive task (ACKs) and the owner of a
  socket (data) both send, and two tasks could take the same descriptor.
- No MAC print; no allocation-failure prints.

## NativeSocket.HC
- Dropped `create_connection` (it queried DNS even for dotted quads and freed an uninitialised `res` when DNS failed,
  crashing the shell) and `SocketInit`; `ConnTcpOpen` replaces them.
- New socket options: `SO_SNDTIMEO_MS` (2), `SO_RCVBUF_BYTES` (3, before connect, tests).

## Icmp.HC
- `IcmpComputeChecksum` handles odd lengths (it read one byte past the end); echo replies get a real checksum
  (the `+0x0800` shortcut overflowed); `IcmpSendRequest` lost its unused parameter and now checksums the payload.
- `icmp_reply` holds flags, not pointers to a stack frame; new `IcmpPing(ip, timeout_ms)`.

## Dhcp / Netcfg.HC
- Dhcp: no Socket include. Netcfg: `Netcfg` removed, `DhcpConfigure` quiet, returns 0/-1; router/DNS/mask start at 0
  (an offer without a router option used stack garbage).

## Dns.HC
- Reply parser: bounds on label count and name buffer, compression pointers must point inside the packet and are
  followed at most 8 times (loop/overflow on hostile replies); frees the labels arrays (leak).
- The returned address came from the first answer instead of the matching A record; `*res` is set to NULL on failure.
- Removed the `Host` debug command.

## Udp.HC
- A receive timeout clears `recv_buf`, so a late datagram cannot be copied into a dead stack buffer.

## Tcp.HC (most work)
- `TcpSend2` / `TcpSendData2` returned garbage after SYN/FIN/data (no `return`): FIN was re-sent in a loop, sends
  "failed" at random. They return the driver result now.
- `TcpSocketSendto` never counted what it sent and could return 0 after sending everything: it sends all bytes and
  returns the count, or -1 when the connection breaks or no byte moved for `SO_SNDTIMEO_MS`. The peer window is
  read with `ntohs` (was byte-swapped), in-flight data is subtracted, a zero window is probed once a second.
- Receive window: advertised from the real free space of the ring (was a constant 4096 while the buffer was 8191);
  the buffer is 32 KiB (`TCP_WINDOW_SIZE`); the reader sends a window update when space opens up (silly-window safe).
- Receive path: a repeated SYN-ACK no longer resets `rcv_nxt`; FIN is only taken when all earlier bytes arrived in
  order (a FIN behind a gap moved `rcv_nxt` and corrupted the stream); data and FIN are also processed in
  FIN-WAIT-2 (the original closed forever there); out-of-window and duplicate segments are answered with an ACK;
  RST for segments to unknown sockets and for wrong remote addr/port; the corrective ACK is only sent for data.
- Send buffers: only the socket owner touches the chain (the receive task just advances `snd_una`), which removes
  a free-while-appending race; retransmit only the oldest unacked segment with exponential backoff, drop the
  connection after `TCP_MAX_RETRIES` (8); retransmitted segments do not update the RTT; the chain is freed on close.
- `TcpSocketConnect`: the state is set before the SYN leaves (a fast SYN-ACK was dropped), the SYN is retransmitted,
  random initial sequence number, failure to send the SYN returns -1.
- `TcpSocketRecvfrom`: `SO_RCVTIMEO_MS` timeout (-1), 0 on orderly EOF, -1 after RST/give-up; data that arrived
  together with the FIN stays readable; waits with `Sleep(1)` instead of spinning.
- `TcpSocketClose`: state changes before the FIN leaves, waits at most `TCP_CLOSE_TIMEOUT` (5 s) for the ACK and the
  peer's FIN (was for ever), discards data still arriving so the peer's window cannot jam it, RST only when the
  shutdown was not clean, frees send buffers.
- `TcpSocket` zero-initialises the socket (`local_port`, `srtt`, ... were garbage).
- Counters `tcp_retransmits`, `tcp_dropped_segments` for tests.
