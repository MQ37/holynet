// TLS 1.3 unit tests: key schedule against RFC 8448 section 3 (TLS_AES_128_GCM_SHA256 / x25519; the SHA-256 secrets
// are suite independent), ServerHello parsing, and the record layer over an in-memory pipe.
#include "B:/tests/Test"
#include "B:/src/Tls/Tls13"

I64 THexVal(I64 c)
{
  if (c >= 'a')
    return c - 'a' + 10;
  return c - '0';
}

U8 *THex(U8 *hex, I64 *n)
{
  U8 *out = MAlloc(StrLen(hex) / 2 + 1);
  I64 len = 0, hi = -1;
  while (*hex) {
    if (*hex != ' ') {
      if (hi < 0)
        hi = THexVal(*hex);
      else {
        out[len++] = hi << 4 | THexVal(*hex);
        hi = -1;
      }
    }
    hex++;
  }
  if (n)
    *n = len;
  return out;
}

U0 TestHexEq(U8 *got, U8 *hex, U8 *what)
{
  I64 n;
  U8 *want = THex(hex, &n);
  TestBytes(got, want, n, what);
  Free(want);
}

U0 KeyScheduleTests()
{
  U8 *cpriv = THex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005", NULL);
  U8 *spub = THex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f", NULL);
  U8 *h_hello = THex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8", NULL);
  U8 *h_fin = THex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13", NULL);
  U8 pub[32], shared[32], out[32], key[32], iv[12];
  CTlsKs ks;

  X25519Base(pub, cpriv);
  TestHexEq(pub, "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c", "rfc8448 client public key");
  X25519(shared, cpriv, spub);
  // the shared secret itself is checked through the published handshake secret derived from it below

  TlsKsHandshake(&ks, shared, h_hello);
  TestHexEq(ks.hs, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac", "handshake secret");
  TestHexEq(ks.c_hs, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21", "client hs traffic secret");
  TestHexEq(ks.s_hs, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38", "server hs traffic secret");
  TestHexEq(ks.master, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919", "master secret");

  TlsTrafficKeys(ks.s_hs, key, iv);
  // (RFC 8448 key is 16 bytes for AES-128; our ChaCha key is 32 bytes with a different HKDF label length)
  TestHexEq(iv, "5d313eb2671276ee13000b30", "server hs write iv");

  TlsKsApp(&ks, h_fin);
  TestHexEq(ks.c_ap, "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5", "client app traffic secret");
  TestHexEq(ks.s_ap, "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643", "server app traffic secret");

  TlsFinishedMac(ks.c_hs, h_fin, out);
  TestHexEq(out, "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61", "client Finished verify_data");
}

// Synthetic ServerHello (88+ bytes) with a given suite / key share group; returns total length.
I64 MakeServerHello(U8 *m, U8 *sid, I64 suite, I64 group, U8 *ks, Bool hrr)
{
  U8 *p = m;
  I64 i;
  TlsPut(&p, 2, 1);
  TlsPut(&p, 0, 3);              // length patched below
  TlsPut(&p, 0x0303, 2);
  for (i = 0; i < 32; i++)
    *p++ = i + 1;
  if (hrr) {
    p -= 32;
    MemCpy(p, "\xCF\x21\xAD\x74\xE5\x9A\x61\x11", 8);
    p += 32;
  }
  TlsPut(&p, 32, 1);
  MemCpy(p, sid, 32);
  p += 32;
  TlsPut(&p, suite, 2);
  TlsPut(&p, 0, 1);
  TlsPut(&p, 6 + 40, 2);
  TlsPut(&p, 0x002B, 2);
  TlsPut(&p, 2, 2);
  TlsPut(&p, 0x0304, 2);
  TlsPut(&p, 0x0033, 2);
  TlsPut(&p, 36, 2);
  TlsPut(&p, group, 2);
  TlsPut(&p, 32, 2);
  MemCpy(p, ks, 32);
  p += 32;
  i = p - m;
  m[1] = 0;
  m[2] = (i - 4) >> 8;
  m[3] = (i - 4) & 0xFF;
  return i;
}

U0 ServerHelloTests()
{
  CTls *t = CAlloc(sizeof(CTls));
  U8 sid[32], ks[32], got[32], other[32];
  I64 i, n;
  t->hs = MAlloc(512);
  for (i = 0; i < 32; i++) {
    sid[i] = 100 + i;
    ks[i] = 7 * i + 1;
  }
  n = MakeServerHello(t->hs, sid, 0x1303, 0x001D, ks, FALSE);
  TestCheck(TlsParseServerHello(t, n, sid, got), "ServerHello parses");
  TestBytes(got, ks, 32, "ServerHello key share");
  n = MakeServerHello(t->hs, sid, 0x1301, 0x001D, ks, FALSE);
  TestCheck(!TlsParseServerHello(t, n, sid, got), "other suite rejected");
  n = MakeServerHello(t->hs, sid, 0x1303, 0x0017, ks, FALSE);
  TestCheck(!TlsParseServerHello(t, n, sid, got), "other group rejected");
  n = MakeServerHello(t->hs, sid, 0x1303, 0x001D, ks, TRUE);
  TestCheck(!TlsParseServerHello(t, n, sid, got), "HelloRetryRequest rejected");
  TestCheck(tls_err && !StrCmp(tls_err, "HelloRetryRequest not supported"), "HRR message");
  n = MakeServerHello(t->hs, sid, 0x1303, 0x001D, ks, FALSE);
  MemCpy(other, sid, 32);
  other[5] ^= 1;
  TestCheck(!TlsParseServerHello(t, n, other, got), "session id mismatch rejected");
  for (i = 0; i < n; i++) {          // truncations never crash
    n = MakeServerHello(t->hs, sid, 0x1303, 0x001D, ks, FALSE);
    TlsParseServerHello(t, i, sid, got);
  }
  TestCheck(TRUE, "truncated ServerHello survived");
  Free(t->hs);
  Free(t);
}

// ---- record layer over a pipe ----
class CPipe
{
  U8 *buf;
  I64 len, pos, frag;
};

class CDuplex
{
  CPipe *in, *out;
};

CPipe *PipeNew(I64 frag)
{
  CPipe *p = CAlloc(sizeof(CPipe));
  p->buf = MAlloc(200000);
  p->frag = frag;
  return p;
}

I64 PipeRead(CConn *c, U8 *buf, I64 len)
{
  CPipe *p = (c->priv(CDuplex *))->in;
  I64 n = p->len - p->pos;
  if (n <= 0)
    return 0;
  if (p->frag && n > p->frag)
    n = p->frag;
  if (n > len)
    n = len;
  MemCpy(buf, p->buf + p->pos, n);
  p->pos += n;
  return n;
}

I64 PipeWrite(CConn *c, U8 *buf, I64 len)
{
  CPipe *p = (c->priv(CDuplex *))->out;
  MemCpy(p->buf + p->len, buf, len);
  p->len += len;
  return len;
}

U0 PipeClose(CConn *c)
{
}

// A TLS endpoint reading `in`, writing `out`, protected with the secrets sw (write) and sr (read).
CConn *TlsEndpoint(CPipe *in, CPipe *out, U8 *sw, U8 *sr)
{
  CConn *tcp = CAlloc(sizeof(CConn)), *c = CAlloc(sizeof(CConn));
  CDuplex *d = CAlloc(sizeof(CDuplex));
  CTls *t = CAlloc(sizeof(CTls));
  d->in = in;
  d->out = out;
  tcp->priv = d;
  tcp->write = &PipeWrite;
  tcp->read = &PipeRead;
  tcp->close = &PipeClose;
  t->tcp = tcp;
  t->cbuf = MAlloc(TLS_CT_MAX);
  t->pt = MAlloc(TLS_CT_MAX);
  t->wbuf = MAlloc(5 + TLS_REC_MAX + 17);
  t->hs = MAlloc(TLS_HS_MAX);
  TlsSetWriteKeys(t, sw);
  TlsSetReadKeys(t, sr);
  c->read = &TlsRead;
  c->write = &TlsWrite;
  c->close = &TlsClose;
  c->priv = t;
  return c;
}

U8 *Pattern(I64 n, I64 seed)
{
  U8 *b = MAlloc(n);
  I64 i;
  for (i = 0; i < n; i++)
    b[i] = (i * 31 + i / 251 + seed) & 0xFF;
  return b;
}

// Reads exactly n bytes with small buffers of mixed sizes; FALSE on a short or failed read.
Bool ReadAll(CConn *c, U8 *dst, I64 n)
{
  I64 got = 0, r, ask = 1;
  while (got < n) {
    ask = ask * 3 % 7001 + 1;
    if (ask > n - got)
      ask = n - got;
    r = c->read(c, dst + got, ask);
    if (r <= 0)
      return FALSE;
    got += r;
  }
  return TRUE;
}

U0 RoundTrip(I64 frag, U8 *what)
{
  U8 sa[32], sb[32], *m1 = Pattern(5, 1), *m2 = Pattern(40000, 2), *m3 = Pattern(16384, 3), *back;
  CPipe *ab = PipeNew(frag), *ba = PipeNew(frag);
  CConn *a, *b;
  I64 i;
  for (i = 0; i < 32; i++) {
    sa[i] = i;
    sb[i] = 200 - i;
  }
  a = TlsEndpoint(ba, ab, sa, sb);
  b = TlsEndpoint(ab, ba, sb, sa);
  TestCheck(a->write(a, m1, 5) == 5, what);
  TestCheck(a->write(a, m2, 40000) == 40000, what);
  TestCheck(a->write(a, m3, 16384) == 16384, what);
  TestCheck(a->write(a, m1, 0) == 0, what);
  back = MAlloc(40000);
  TestCheck(ReadAll(b, back, 5) && !MemCmp(back, m1, 5), what);
  TestCheck(ReadAll(b, back, 40000) && !MemCmp(back, m2, 40000), what);
  TestCheck(ReadAll(b, back, 16384) && !MemCmp(back, m3, 16384), what);
  // reply the other way, then a clean close
  TestCheck(b->write(b, m2, 100) == 100 && ReadAll(a, back, 100) && !MemCmp(back, m2, 100), what);
  b->close(b);
  TestCheck(a->read(a, back, 10) == 0, "close_notify reads as EOF");
  TestCheck(a->read(a, back, 10) == 0, "EOF is sticky");
  Free(m1); Free(m2); Free(m3); Free(back);
}

U0 RecordTests()
{
  RoundTrip(0, "roundtrip whole");
  RoundTrip(1, "roundtrip 1-byte tcp reads");
  RoundTrip(7, "roundtrip 7-byte tcp reads");
  RoundTrip(5000, "roundtrip 5000-byte tcp reads");
}

CTls *Priv(CConn *c)
{
  return c->priv;
}

U0 Secrets(U8 *sa, U8 *sb)
{
  I64 i;
  for (i = 0; i < 32; i++) {
    sa[i] = i + 9;
    sb[i] = 77 - i;
  }
}

U0 EdgeTests()
{
  U8 sa[32], sb[32], nonce[12], hdr[5], *buf = MAlloc(40000), ku[5], ticket[8];
  CPipe *ab, *ba;
  CConn *a, *b;
  CTls *ta, *tb;
  U8 expect[32];
  I64 i;
  Secrets(sa, sb);

  // padded record: inner content "hello" + type 23 + three zero bytes
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  ta = Priv(a);
  MemCpy(buf, "hello\x17\0\0\0", 9);
  hdr[0] = 23; hdr[1] = 3; hdr[2] = 3; hdr[3] = 0; hdr[4] = 25;
  TlsNonce(ta->wiv, 0, nonce);
  Chacha20Poly1305Seal(ta->wkey, nonce, hdr, 5, buf, 9, buf + 100);
  MemCpy(ab->buf, hdr, 5);
  MemCpy(ab->buf + 5, buf + 100, 25);
  ab->len = 30;
  TestCheck(b->read(b, buf + 200, 100) == 5 && !MemCmp(buf + 200, "hello", 5), "padding stripped");

  // tampered record
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  a->write(a, "abcdef", 6);
  ab->buf[8] ^= 1;
  TestCheck(b->read(b, buf, 100) < 0, "tampered record rejected");

  // records must not be replayed or reordered: sequence numbers
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  a->write(a, "one", 3);
  a->write(a, "two", 3);
  i = ab->len / 2;
  MemCpy(buf, ab->buf + i, ab->len - i);          // second record only
  MemCpy(ab->buf, buf, ab->len - i);
  ab->len -= i;
  TestCheck(b->read(b, buf, 100) < 0, "skipped record rejected");

  // fatal alert
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  ku[0] = 2; ku[1] = 40;
  TlsRecWrite(Priv(a), TLS_ST_ALERT, ku, 2, TRUE);
  TestCheck(b->read(b, buf, 100) < 0, "fatal alert is an error");

  // truncated record, oversized record header, garbage
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  a->write(a, "abcdef", 6);
  ab->len -= 3;
  TestCheck(b->read(b, buf, 100) < 0, "truncated record is an error");
  ab = PipeNew(0); ba = PipeNew(0);
  b = TlsEndpoint(ab, ba, sb, sa);
  ab->buf[0] = 23; ab->buf[1] = 3; ab->buf[2] = 3; ab->buf[3] = 0xFF; ab->buf[4] = 0xFF; ab->len = 5;
  TestCheck(b->read(b, buf, 100) < 0, "oversized record header rejected");
  ab = PipeNew(0); ba = PipeNew(0);
  b = TlsEndpoint(ab, ba, sb, sa);
  RandFill(ab->buf, 3000);
  ab->buf[3] = 0; ab->buf[4] = 40;
  ab->len = 3000;
  TestCheck(b->read(b, buf, 100) < 0, "garbage rejected");
  ab = PipeNew(0); ba = PipeNew(0);
  b = TlsEndpoint(ab, ba, sb, sa);
  TestCheck(b->read(b, buf, 100) < 0, "TCP close without close_notify is an error, not EOF");
  TestCheck(tls_err && !StrCmp(tls_err, "connection closed without close_notify"), "truncation message");
  TestCheck(b->read(b, buf, 100) < 0 && b->write(b, "x", 1) < 0, "errors are sticky");
  TestCheck(ba->len == 0, "no alert for a transport error");

  // data then truncation: data is delivered first, then the error
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  a->write(a, "abc", 3);
  TestCheck(b->read(b, buf, 100) == 3 && b->read(b, buf, 100) < 0, "data, then truncation error");

  // record overflow: 2^14 + 1 inner bytes is the limit
  for (i = 16384; i <= 16385; i++) {
    ab = PipeNew(0); ba = PipeNew(0);
    a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
    ta = Priv(a);
    MemSet(buf, 1, 20000);
    buf[i] = 23;                     // content type after i content bytes: inner length i + 1
    hdr[0] = 23; hdr[1] = 3; hdr[2] = 3; hdr[3] = (i + 17) >> 8; hdr[4] = (i + 17) & 0xFF;
    TlsNonce(ta->wiv, 0, nonce);
    Chacha20Poly1305Seal(ta->wkey, nonce, hdr, 5, buf, i + 1, buf + 20000);
    MemCpy(ab->buf, hdr, 5);
    MemCpy(ab->buf + 5, buf + 20000, i + 17);
    ab->len = 5 + i + 17;
    if (i == 16384)
      TestCheck(b->read(b, buf, 20000) == 16384, "record with 2^14 content bytes accepted");
    else {
      TestCheck(b->read(b, buf, 20000) < 0 && !StrCmp(tls_err, "record overflow"), "record over 2^14 + 1 inner bytes rejected");
      TestCheck(ba->len > 0, "fatal alert sent on overflow");
    }
  }

  // a fatal error sends an alert and kills the connection
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  a->write(a, "abcdef", 6);
  ab->buf[8] ^= 1;
  TestCheck(b->read(b, buf, 100) < 0 && ba->len == 24, "bad MAC: alert record (5 + 2 + 1 + 16 bytes) written");
  TestCheck(a->read(a, buf, 100) < 0, "the alert is fatal for the peer");
  TestCheck(b->read(b, buf, 100) < 0 && b->write(b, "x", 1) < 0, "dead connection: read and write fail");

  // NewSessionTicket ignored; KeyUpdate answered; keys roll in both directions
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  ta = Priv(a); tb = Priv(b);
  ticket[0] = 4; ticket[1] = 0; ticket[2] = 0; ticket[3] = 4; ticket[4] = ticket[5] = ticket[6] = ticket[7] = 0;
  TlsRecWrite(ta, TLS_ST_HS, ticket, 8, TRUE);
  ku[0] = 24; ku[1] = 0; ku[2] = 0; ku[3] = 1; ku[4] = 1;
  TlsRecWrite(ta, TLS_ST_HS, ku, 5, TRUE);
  TlsKeyUpdateNext(ta->wsec);
  TlsSetWriteKeys(ta, ta->wsec);
  a->write(a, "after", 5);
  TestCheck(b->read(b, buf, 100) == 5 && !MemCmp(buf, "after", 5), "data after NewSessionTicket and KeyUpdate");
  MemCpy(expect, sa, 32);
  TlsKeyUpdateNext(expect);
  TestBytes(tb->rsec, expect, 32, "KeyUpdate read secret");
  MemCpy(expect, sb, 32);
  TlsKeyUpdateNext(expect);
  TestBytes(tb->wsec, expect, 32, "KeyUpdate answer rolled write secret");
  b->write(b, "reply", 5);
  TestCheck(a->read(a, buf, 100) == 5 && !MemCmp(buf, "reply", 5), "reply under rolled keys");

  // unknown post-handshake message
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  ticket[0] = 13;
  TlsRecWrite(Priv(a), TLS_ST_HS, ticket, 8, TRUE);
  TestCheck(b->read(b, buf, 100) < 0, "unexpected handshake message rejected");

  // handshake message split over two records
  ab = PipeNew(0); ba = PipeNew(0);
  a = TlsEndpoint(ba, ab, sa, sb); b = TlsEndpoint(ab, ba, sb, sa);
  ticket[0] = 4;
  TlsRecWrite(Priv(a), TLS_ST_HS, ticket, 3, TRUE);
  TlsRecWrite(Priv(a), TLS_ST_HS, ticket + 3, 5, TRUE);
  a->write(a, "x", 1);
  TestCheck(b->read(b, buf, 100) == 1, "split handshake message reassembled");
  Free(buf);
}

KeyScheduleTests;
ServerHelloTests;
RecordTests;
EdgeTests;
TestDone;
