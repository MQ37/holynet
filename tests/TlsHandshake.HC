// Handshake state machine tests against a fake in-memory TLS 1.3 server: message order, ChangeCipherSpec window,
// Finished MAC, and the happy path. The fake server derives real keys from the client's key share, so only the
// scenario knobs (order, CCS placement, bad MAC) differ between runs.
#include "B:/tests/Test"
#include "B:/src/Tls/Tls13"

class CSrv
{
  U8 in[4096];                // what the client wrote
  I64 inlen;
  U8 *out;                    // the flight, built on the first read
  I64 outlen, pos;
  U8 *order;                  // handshake message types, e.g. "\x08\x0b\x0f\x14"
  I64 ccs_before_sh, ccs_after_sh, ccs_after_fin;
  Bool bad_mac;
};

U0 SrvPut(CSrv *s, U8 *rec, I64 n)
{
  MemCpy(s->out + s->outlen, rec, n);
  s->outlen += n;
}

U0 SrvPlain(CSrv *s, I64 type, U8 *body, I64 n)
{
  U8 h[5];
  h[0] = type; h[1] = 3; h[2] = 3; h[3] = n >> 8; h[4] = n & 0xFF;
  SrvPut(s, h, 5);
  SrvPut(s, body, n);
}

U0 SrvSeal(CSrv *s, U8 *key, U8 *iv, I64 seq, I64 type, U8 *body, I64 n)
{
  U8 h[5], nonce[12], *buf = MAlloc(2 * n + 40);
  MemCpy(buf, body, n);
  buf[n] = type;
  h[0] = 23; h[1] = 3; h[2] = 3; h[3] = (n + 17) >> 8; h[4] = (n + 17) & 0xFF;
  TlsNonce(iv, seq, nonce);
  Chacha20Poly1305Seal(key, nonce, h, 5, buf, n + 1, buf + n + 1);
  SrvPut(s, h, 5);
  SrvPut(s, buf + n + 1, n + 17);
  Free(buf);
}

I64 SrvHello(U8 *m, U8 *sid, U8 *ks)
{
  U8 *p = m;
  I64 i;
  TlsPut(&p, 2, 1);
  TlsPut(&p, 0, 3);
  TlsPut(&p, 0x0303, 2);
  for (i = 0; i < 32; i++)
    *p++ = i + 1;
  TlsPut(&p, 32, 1);
  MemCpy(p, sid, 32);
  p += 32;
  TlsPut(&p, 0x1303, 2);
  TlsPut(&p, 0, 1);
  TlsPut(&p, 46, 2);
  TlsPut(&p, 0x002B, 2);
  TlsPut(&p, 2, 2);
  TlsPut(&p, 0x0304, 2);
  TlsPut(&p, 0x0033, 2);
  TlsPut(&p, 36, 2);
  TlsPut(&p, 0x001D, 2);
  TlsPut(&p, 32, 2);
  MemCpy(p, ks, 32);
  p += 32;
  i = p - m;
  m[2] = (i - 4) >> 8;
  m[3] = (i - 4) & 0xFF;
  return i;
}

U0 SrvHash(CSha256 *th, U8 *out32)
{
  CSha256 snap;
  MemCpy(&snap, th, sizeof(CSha256));
  Sha256Final(&snap, out32);
}

// Builds the server's whole first flight from the ClientHello the client has written.
U0 SrvBuildFlight(CSrv *s)
{
  U8 *ch = s->in + 5, spriv[32], spub[32], shared[32], sid[32], cpub[32], h[32];
  U8 sk[32], siv[12], ak[32], aiv[12], sh[128], msg[64], *p;
  CSha256 th;
  CTlsKs ks;
  I64 i, n, seq = 0, type;

  MemCpy(sid, ch + 39, 32);
  p = ch + 79;                       // first extension
  while (p < s->in + s->inlen) {
    if (p[0] == 0 && p[1] == 0x33) {
      MemCpy(cpub, p + 10, 32);
      break;
    }
    p += 4 + (p[2] << 8 | p[3]);
  }
  for (i = 0; i < 32; i++)
    spriv[i] = 40 + i;
  X25519Base(spub, spriv);
  X25519(shared, spriv, cpub);
  n = SrvHello(sh, sid, spub);
  Sha256Init(&th);
  Sha256Update(&th, ch, s->in[3] << 8 | s->in[4]);
  Sha256Update(&th, sh, n);
  SrvHash(&th, h);
  TlsKsHandshake(&ks, shared, h);
  TlsTrafficKeys(ks.s_hs, sk, siv);

  s->out = MAlloc(20000);
  if (s->ccs_before_sh)
    SrvPlain(s, 20, "\x01", 1);
  SrvPlain(s, 22, sh, n);
  for (i = 0; i < s->ccs_after_sh; i++)
    SrvPlain(s, 20, "\x01", 1);
  for (i = 0; i < StrLen(s->order); i++) {
    type = s->order[i];
    MemSet(msg, 0, 64);
    msg[0] = type;
    n = 4;
    if (type == 8)
      n = 6;                          // EncryptedExtensions: empty extension list
    else if (type == 11 || type == 15)
      n = 8;                          // Certificate: empty list / CertificateVerify: empty signature
    else if (type == 20)
      n = 36;
    msg[3] = n - 4;
    if (type == 15)
      msg[4] = 8, msg[5] = 4;
    if (type == 20) {
      SrvHash(&th, h);
      TlsFinishedMac(ks.s_hs, h, msg + 4);
      if (s->bad_mac)
        msg[10] ^= 1;
    }
    SrvSeal(s, sk, siv, seq++, 22, msg, n);
    Sha256Update(&th, msg, n);
  }
  SrvHash(&th, h);
  TlsKsApp(&ks, h);
  if (s->ccs_after_fin)
    SrvPlain(s, 20, "\x01", 1);
  TlsTrafficKeys(ks.s_ap, ak, aiv);
  SrvSeal(s, ak, aiv, 0, 23, "hi", 2);
}

I64 SrvRead(CConn *c, U8 *buf, I64 len)
{
  CSrv *s = c->priv;
  I64 n;
  if (!s->out)
    SrvBuildFlight(s);
  n = s->outlen - s->pos;
  if (n <= 0)
    return 0;
  if (n > len)
    n = len;
  MemCpy(buf, s->out + s->pos, n);
  s->pos += n;
  return n;
}

I64 SrvWrite(CConn *c, U8 *buf, I64 len)
{
  CSrv *s = c->priv;
  if (s->inlen + len > 4096)
    return -1;
  MemCpy(s->in + s->inlen, buf, len);
  s->inlen += len;
  return len;
}

U0 SrvClose(CConn *c)
{
}

// Returns the connection (NULL when the handshake failed); *err gets tls_err.
CConn *Scenario(U8 *order, I64 before, I64 after, I64 after_fin, Bool bad_mac, CSrv **out)
{
  CConn *tcp = CAlloc(sizeof(CConn));
  CSrv *s = CAlloc(sizeof(CSrv));
  s->order = order;
  s->ccs_before_sh = before;
  s->ccs_after_sh = after;
  s->ccs_after_fin = after_fin;
  s->bad_mac = bad_mac;
  tcp->priv = s;
  tcp->read = &SrvRead;
  tcp->write = &SrvWrite;
  tcp->close = &SrvClose;
  *out = s;
  return ConnTlsOver(tcp, "example.test");
}

Bool Refused(U8 *order, I64 before, I64 after, I64 after_fin, Bool bad_mac, U8 *what)
{
  CSrv *s;
  CConn *c = Scenario(order, before, after, after_fin, bad_mac, &s);
  U8 buf[16];
  Bool ok;
  if (after_fin)                     // a stray CCS after Finished shows up on the first read
    ok = c && c->read(c, buf, 16) < 0;
  else
    ok = !c;
  TestCheck(ok, what);
  if (!ok && c)
    SerPrint("  accepted: %s\n", what);
  else if (tls_err)
    SerPrint("  %s: %s\n", what, tls_err);
  return ok;
}

U0 HappyPath(U8 *what, I64 after_sh)
{
  CSrv *s;
  U8 buf[16];
  CConn *c = Scenario("\x08\x0b\x0f\x14", 0, after_sh, 0, FALSE, &s);
  TestCheck(c != NULL, what);
  if (!c) {
    SerPrint("  err=%s\n", tls_err);
    return;
  }
  TestCheck(c->read(c, buf, 16) == 2 && !MemCmp(buf, "hi", 2), "application data from the server flight");
  // client flight: ClientHello record, dummy CCS, protected Finished
  TestCheck(s->in[0] == 22 && s->in[5 + (s->in[3] << 8 | s->in[4])] == 20, "client sends a compat ChangeCipherSpec before Finished");
  c->close(c);
}

HappyPath("handshake with no CCS", 0);
HappyPath("handshake with one compat CCS after ServerHello", 1);
Refused("\x08\x0f\x14", 0, 0, 0, FALSE, "Certificate missing");
Refused("\x08\x0b\x14", 0, 0, 0, FALSE, "CertificateVerify missing");
Refused("\x08\x08\x0b\x0f\x14", 0, 0, 0, FALSE, "EncryptedExtensions twice");
Refused("\x0b\x08\x0f\x14", 0, 0, 0, FALSE, "Certificate before EncryptedExtensions");
Refused("\x08\x0b\x14\x0f", 0, 0, 0, FALSE, "Finished before CertificateVerify");
Refused("\x08\x0b\x0f\x0f\x14", 0, 0, 0, FALSE, "CertificateVerify twice");
Refused("\x08\x0b\x0f", 0, 0, 0, FALSE, "no Finished (app data arrives instead)");
Refused("\x08\x0b\x0f\x14", 0, 2, 0, FALSE, "two ChangeCipherSpec records");
Refused("\x08\x0b\x0f\x14", 1, 0, 0, FALSE, "ChangeCipherSpec before ServerHello");
Refused("\x08\x0b\x0f\x14", 0, 0, 1, FALSE, "ChangeCipherSpec after server Finished");
Refused("\x08\x0b\x0f\x14", 0, 0, 0, TRUE, "bad server Finished MAC");
TestDone;
