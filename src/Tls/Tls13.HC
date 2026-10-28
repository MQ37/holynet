// TLS 1.3 client (RFC 8446) for the HolyC Apify client.
//
// !!! DEMO ONLY: THE SERVER CERTIFICATE IS NOT VALIDATED !!!
// The Certificate and CertificateVerify messages are parsed past and ignored: no chain building, no host
// name check, no signature check, no revocation. The server Finished MAC IS verified, so the handshake is
// bound to the key exchange, but anybody who can sit between this client and the server can impersonate
// it. Do not send secrets you care about over this in anything but a demo. The randomness is demo grade
// too (see src/Crypto/Rand.HC).
//
// Exactly one configuration is offered: TLS 1.3 only, TLS_CHACHA20_POLY1305_SHA256 (0x1303), x25519.
// No PSK, 0-RTT, resumption or HelloRetryRequest (an HRR aborts with an error). NewSessionTicket is
// ignored, KeyUpdate is honoured. After a failed ConnTlsOpen, tls_err points to a short reason.
#ifndef TLS13_HC
#define TLS13_HC

#include "B:/src/Net/ConnTcp"
#include "B:/src/Crypto/Sha256"
#include "B:/src/Crypto/Hmac"
#include "B:/src/Crypto/Hkdf"
#include "B:/src/Crypto/Chacha20Poly1305"
#include "B:/src/Crypto/X25519"
#include "B:/src/Crypto/Rand"

#define TLS_REC_MAX   16384     // plaintext bytes per record
#define TLS_CT_MAX    16640     // ciphertext bytes per record (RFC 8446 5.2)
#define TLS_HS_MAX    65536     // largest handshake message we reassemble
#define TLS_ST_CCS    20
#define TLS_ST_ALERT  21
#define TLS_ST_HS     22
#define TLS_ST_APP    23

U8 *tls_err = NULL;

// Key schedule results (RFC 8446 7.1). Kept apart from CTls so the tests can drive it with RFC 8448 values.
class CTlsKs
{
  U8 hs[32], master[32];       // handshake secret, master secret
  U8 c_hs[32], s_hs[32];       // handshake traffic secrets
  U8 c_ap[32], s_ap[32];       // application traffic secrets
};

class CTls
{
  CConn *tcp;
  Bool rdec, eof, dead;        // dead: a fatal error happened, every call fails from now on
  Bool wprot;                  // write keys installed
  Bool ccs_window;             // a compat ChangeCipherSpec may arrive (after ServerHello, before server Finished)
  Bool ccs_seen;
  U8 wkey[32], wiv[12], rkey[32], riv[12];
  U8 wsec[32], rsec[32];       // current application traffic secrets (for KeyUpdate)
  I64 wseq, rseq;
  U8 *cbuf;                    // received ciphertext
  U8 *pt;                      // decrypted record payload; pt[pos..plen) is unread application data
  I64 pos, plen;
  U8 *wbuf;                    // outgoing record
  U8 *hs;                      // handshake reassembly
  I64 hslen;
  CSha256 th;                  // transcript hash
};

// ---- key schedule -------------------------------------------------------------------------------------

// HKDF-Expand-Label (RFC 8446 7.1) with the "tls13 " prefix.
U0 TlsExpandLabel(U8 *secret, U8 *label, U8 *ctx, I64 clen, U8 *out, I64 olen)
{
  U8 info[96];
  I64 ll = StrLen(label), n = 0;
  info[n++] = olen >> 8;
  info[n++] = olen & 0xFF;
  info[n++] = 6 + ll;
  MemCpy(info + n, "tls13 ", 6);
  n += 6;
  MemCpy(info + n, label, ll);
  n += ll;
  info[n++] = clen;
  MemCpy(info + n, ctx, clen);
  n += clen;
  HkdfExpand(secret, info, n, out, olen);
}

U0 TlsDeriveSecret(U8 *secret, U8 *label, U8 *hash32, U8 *out32)
{
  TlsExpandLabel(secret, label, hash32, 32, out32, 32);
}

// From the shared secret and H(ClientHello..ServerHello): handshake secret, both handshake traffic secrets
// and the master secret.
U0 TlsKsHandshake(CTlsKs *ks, U8 *shared32, U8 *h_hello)
{
  U8 zeros[32], empty[32], early[32], derived[32];
  MemSet(zeros, 0, 32);
  Sha256(zeros, 0, empty);
  HkdfExtract(zeros, 0, zeros, 32, early);
  TlsDeriveSecret(early, "derived", empty, derived);
  HkdfExtract(derived, 32, shared32, 32, ks->hs);
  TlsDeriveSecret(ks->hs, "c hs traffic", h_hello, ks->c_hs);
  TlsDeriveSecret(ks->hs, "s hs traffic", h_hello, ks->s_hs);
  TlsDeriveSecret(ks->hs, "derived", empty, derived);
  HkdfExtract(derived, 32, zeros, 32, ks->master);
}

// From H(ClientHello..server Finished): application traffic secrets.
U0 TlsKsApp(CTlsKs *ks, U8 *h_fin)
{
  TlsDeriveSecret(ks->master, "c ap traffic", h_fin, ks->c_ap);
  TlsDeriveSecret(ks->master, "s ap traffic", h_fin, ks->s_ap);
}

U0 TlsTrafficKeys(U8 *secret, U8 *key32, U8 *iv12)
{
  TlsExpandLabel(secret, "key", NULL, 0, key32, 32);
  TlsExpandLabel(secret, "iv", NULL, 0, iv12, 12);
}

// verify_data = HMAC(finished_key, transcript hash)
U0 TlsFinishedMac(U8 *traffic_secret, U8 *hash32, U8 *out32)
{
  U8 fkey[32];
  TlsExpandLabel(traffic_secret, "finished", NULL, 0, fkey, 32);
  HmacSha256(fkey, 32, hash32, 32, out32);
}

// ---- record layer -------------------------------------------------------------------------------------

U0 TlsNonce(U8 *iv, I64 seq, U8 *nonce)
{
  I64 i;
  MemCpy(nonce, iv, 12);
  for (i = 0; i < 8; i++)
    nonce[11 - i] ^= (seq >> (8 * i)) & 0xFF;
}

// Reads exactly n bytes; returns the count (< n on EOF) or -1 on a transport error.
I64 TlsTcpFull(CTls *t, U8 *buf, I64 n)
{
  I64 got = 0, r;
  while (got < n) {
    r = t->tcp->read(t->tcp, buf + got, n - got);
    if (r < 0)
      return -1;
    if (!r)
      break;
    got += r;
  }
  return got;
}

// Sends one record of up to TLS_REC_MAX bytes, protected with the write keys if `protect`.
Bool TlsRecWrite(CTls *t, I64 type, U8 *data, I64 len, Bool protect)
{
  U8 nonce[12], *w = t->wbuf;
  I64 clen;
  w[1] = 3;
  w[2] = 3;
  if (!protect) {
    w[0] = type;
    w[3] = len >> 8;
    w[4] = len & 0xFF;
    MemCpy(w + 5, data, len);
    clen = len;
  } else {
    clen = len + 17;
    w[0] = TLS_ST_APP;
    w[3] = clen >> 8;
    w[4] = clen & 0xFF;
    MemCpy(w + 5, data, len);
    w[5 + len] = type;
    TlsNonce(t->wiv, t->wseq, nonce);
    Chacha20Poly1305Seal(t->wkey, nonce, w, 5, w + 5, len + 1, w + 5);
    t->wseq++;
  }
  return t->tcp->write(t->tcp, w, 5 + clen) == 5 + clen;
}

Bool TlsFail(CTls *t, I64 alert, U8 *why)
{
  U8 al[2];
  tls_err = why;
  if (!t->dead) {
    t->dead = TRUE;
    if (alert && t->tcp) {          // best effort fatal alert, no error handling on purpose
      al[0] = 2;
      al[1] = alert;
      TlsRecWrite(t, TLS_ST_ALERT, al, 2, t->wprot);
    }
  }
  return FALSE;
}

// Reads one record. Returns the payload length (payload at *data, inner type in *type), -1 on error
// (tls_err set), -2 on a TCP close at a record boundary.
I64 TlsRecRead(CTls *t, I64 *type, U8 **data)
{
  U8 h[5], nonce[12];
  I64 len, n;

  n = TlsTcpFull(t, h, 5);
  if (!n)
    return -2;
  if (n != 5) {
    TlsFail(t, 0, "connection lost reading record header");
    return -1;
  }
  len = h[3] << 8 | h[4];
  if (len > TLS_CT_MAX) {
    TlsFail(t, 22, "record too large");
    return -1;
  }
  if (TlsTcpFull(t, t->cbuf, len) != len) {
    TlsFail(t, 0, "connection lost inside record");
    return -1;
  }
  if (!t->rdec || h[0] == TLS_ST_CCS) {
    if (len > TLS_REC_MAX) {
      TlsFail(t, 22, "plaintext record too large");
      return -1;
    }
    *type = h[0];
    *data = t->cbuf;
    return len;
  }
  if (h[0] != TLS_ST_APP || len < 17) {
    TlsFail(t, 10, "unexpected unprotected record");
    return -1;
  }
  if (len - 16 > TLS_REC_MAX + 1) {
    TlsFail(t, 22, "record overflow");
    return -1;
  }
  TlsNonce(t->riv, t->rseq, nonce);
  if (!Chacha20Poly1305Open(t->rkey, nonce, h, 5, t->cbuf, len, t->pt)) {
    TlsFail(t, 20, "bad record MAC");
    return -1;
  }
  t->rseq++;
  n = len - 16;
  while (n > 0 && !t->pt[n - 1])
    n--;
  if (!n) {
    TlsFail(t, 10, "record without content type");
    return -1;
  }
  *type = t->pt[n - 1];
  *data = t->pt;
  return n - 1;
}

U0 TlsSetWriteKeys(CTls *t, U8 *secret)
{
  MemCpy(t->wsec, secret, 32);
  TlsTrafficKeys(secret, t->wkey, t->wiv);
  t->wseq = 0;
  t->wprot = TRUE;
}

U0 TlsSetReadKeys(CTls *t, U8 *secret)
{
  MemCpy(t->rsec, secret, 32);
  TlsTrafficKeys(secret, t->rkey, t->riv);
  t->rseq = 0;
  t->rdec = TRUE;
}

// ---- handshake messages -------------------------------------------------------------------------------

U0 TlsTranscript(CTls *t, U8 *msg, I64 len)
{
  Sha256Update(&t->th, msg, len);
}

// Hash of the transcript so far; the running state is untouched (plain copy = snapshot).
U0 TlsTranscriptHash(CTls *t, U8 *out32)
{
  CSha256 s;
  MemCpy(&s, &t->th, sizeof(CSha256));
  Sha256Final(&s, out32);
}

Bool TlsHsAppend(CTls *t, U8 *d, I64 n)
{
  if (t->hslen + n > TLS_HS_MAX)
    return TlsFail(t, 50, "handshake message too large");
  MemCpy(t->hs + t->hslen, d, n);
  t->hslen += n;
  return TRUE;
}

// Length of the first complete message in the buffer (header included), 0 if incomplete, -1 if too big.
I64 TlsHsComplete(CTls *t)
{
  I64 need;
  if (t->hslen < 4)
    return 0;
  need = 4 + (t->hs[1] << 16 | t->hs[2] << 8 | t->hs[3]);
  if (need > TLS_HS_MAX)
    return -1;
  if (t->hslen < need)
    return 0;
  return need;
}

U0 TlsHsDrop(CTls *t, I64 n)
{
  I64 i;
  t->hslen -= n;
  for (i = 0; i < t->hslen; i++)
    t->hs[i] = t->hs[i + n];
}

// Blocks until a whole handshake message is buffered; returns its length or -1 (tls_err set).
I64 TlsHsNext(CTls *t)
{
  I64 m, n, type;
  U8 *d;
  while (TRUE) {
    m = TlsHsComplete(t);
    if (m < 0) {
      TlsFail(t, 50, "handshake message too large");
      return -1;
    }
    if (m)
      return m;
    n = TlsRecRead(t, &type, &d);
    if (n < 0) {
      if (n == -2)
        TlsFail(t, 0, "connection closed during handshake");
      return -1;
    }
    if (type == TLS_ST_CCS) {
      if (n != 1 || d[0] != 1 || !t->ccs_window || t->ccs_seen) {
        TlsFail(t, 10, "bad or unexpected ChangeCipherSpec");
        return -1;
      }
      t->ccs_seen = TRUE;
    } else if (type == TLS_ST_ALERT) {
      TlsFail(t, 0, "server sent an alert during handshake");
      return -1;
    } else if (type != TLS_ST_HS || !n) {
      TlsFail(t, 10, "unexpected record during handshake");
      return -1;
    } else if (!TlsHsAppend(t, d, n))
      return -1;
  }
}

U0 TlsPut(U8 **p, I64 v, I64 n)
{
  U8 *q = *p;
  while (n > 0) {
    n--;
    *q++ = (v >> (8 * n)) & 0xFF;
  }
  *p = q;
}

Bool TlsIsIpLiteral(U8 *host)
{
  while (*host) {
    if ((*host < '0' || *host > '9') && *host != '.')
      return FALSE;
    host++;
  }
  return TRUE;
}

Bool TlsSendHello(CTls *t, U8 *sni, U8 *xpub, U8 *sid)
{
  U8 *msg = MAlloc(512), *p = msg + 5;
  I64 hl = StrLen(sni), ext, ok;
  Bool use_sni = hl && hl < 256 && !TlsIsIpLiteral(sni);
  U8 rnd[32];

  RandFill(rnd, 32);
  ext = 7 + 8 + 42 + 14;
  if (use_sni)
    ext += 9 + hl;
  TlsPut(&p, 1, 1);            // ClientHello
  TlsPut(&p, 75 + ext, 3);
  TlsPut(&p, 0x0303, 2);
  MemCpy(p, rnd, 32);
  p += 32;
  TlsPut(&p, 32, 1);
  MemCpy(p, sid, 32);
  p += 32;
  TlsPut(&p, 2, 2);
  TlsPut(&p, 0x1303, 2);
  TlsPut(&p, 0x0100, 2);       // one compression method: null
  TlsPut(&p, ext, 2);
  if (use_sni) {
    TlsPut(&p, 0x0000, 2);
    TlsPut(&p, hl + 5, 2);
    TlsPut(&p, hl + 3, 2);
    TlsPut(&p, 0, 1);
    TlsPut(&p, hl, 2);
    MemCpy(p, sni, hl);
    p += hl;
  }
  TlsPut(&p, 0x002B, 2);       // supported_versions: TLS 1.3 only
  TlsPut(&p, 3, 2);
  TlsPut(&p, 2, 1);
  TlsPut(&p, 0x0304, 2);
  TlsPut(&p, 0x000A, 2);       // supported_groups: x25519
  TlsPut(&p, 4, 2);
  TlsPut(&p, 2, 2);
  TlsPut(&p, 0x001D, 2);
  TlsPut(&p, 0x0033, 2);       // key_share
  TlsPut(&p, 38, 2);
  TlsPut(&p, 36, 2);
  TlsPut(&p, 0x001D, 2);
  TlsPut(&p, 32, 2);
  MemCpy(p, xpub, 32);
  p += 32;
  TlsPut(&p, 0x000D, 2);       // signature_algorithms (offered so any server finds a certificate; not verified)
  TlsPut(&p, 10, 2);
  TlsPut(&p, 8, 2);
  TlsPut(&p, 0x0804, 2);
  TlsPut(&p, 0x0805, 2);
  TlsPut(&p, 0x0403, 2);
  TlsPut(&p, 0x0807, 2);
  ext = p - msg;
  msg[0] = TLS_ST_HS;
  msg[1] = 3;
  msg[2] = 1;                  // legacy record version 0x0301 on the first flight (RFC 8446 5.1)
  msg[3] = (ext - 5) >> 8;
  msg[4] = (ext - 5) & 0xFF;
  TlsTranscript(t, msg + 5, ext - 5);
  ok = t->tcp->write(t->tcp, msg, ext) == ext;
  Free(msg);
  return ok;
}

Bool TlsAllZero(U8 *p, I64 n)
{
  I64 i, acc = 0;
  for (i = 0; i < n; i++)
    acc |= p[i];
  return !acc;
}

// Parses ServerHello (message of length m in t->hs); on success fills the server key share.
Bool TlsParseServerHello(CTls *t, I64 m, U8 *sid, U8 *spub)
{
  U8 *p = t->hs, *e = t->hs + m, hrr[8];
  I64 n, type, len, got_ver = 0, got_ks = 0;

  hrr[0] = 0xCF; hrr[1] = 0x21; hrr[2] = 0xAD; hrr[3] = 0x74;
  hrr[4] = 0xE5; hrr[5] = 0x9A; hrr[6] = 0x61; hrr[7] = 0x11;
  if (p[0] != 2)
    return TlsFail(t, 10, "expected ServerHello");
  p += 4;
  if (e - p < 2 + 32 + 1 || (p[0] << 8 | p[1]) != 0x0303)
    return TlsFail(t, 50, "bad ServerHello");
  p += 2;
  if (!MemCmp(p, hrr, 8))
    return TlsFail(t, 10, "HelloRetryRequest not supported");
  p += 32;
  n = *p++;
  if (n != 32 || e - p < n + 2 + 1 + 2 || MemCmp(p, sid, 32))
    return TlsFail(t, 47, "bad session id echo");
  p += n;
  if ((p[0] << 8 | p[1]) != 0x1303)
    return TlsFail(t, 47, "server chose another cipher suite");
  if (p[2])
    return TlsFail(t, 47, "compression selected");
  n = p[3] << 8 | p[4];
  p += 5;
  if (e - p != n)
    return TlsFail(t, 50, "bad ServerHello extensions");
  while (p < e) {
    if (e - p < 4)
      return TlsFail(t, 50, "bad extension");
    type = p[0] << 8 | p[1];
    len = p[2] << 8 | p[3];
    p += 4;
    if (e - p < len)
      return TlsFail(t, 50, "bad extension");
    if (type == 0x002B) {
      if (len != 2 || (p[0] << 8 | p[1]) != 0x0304)
        return TlsFail(t, 70, "server did not pick TLS 1.3");
      got_ver = 1;
    } else if (type == 0x0033) {
      if (len != 36 || (p[0] << 8 | p[1]) != 0x001D || (p[2] << 8 | p[3]) != 32)
        return TlsFail(t, 47, "server key share is not x25519");
      MemCpy(spub, p + 4, 32);
      got_ks = 1;
    } else
      return TlsFail(t, 10, "unexpected ServerHello extension");
    p += len;
  }
  if (!got_ver || !got_ks)
    return TlsFail(t, 109, "ServerHello lacks version or key share");
  return TRUE;
}

Bool TlsSameMac(U8 *a, U8 *b, I64 n)
{
  I64 i, acc = 0;
  for (i = 0; i < n; i++)
    acc |= a[i] ^ b[i];
  return !acc;
}

U0 TlsFree(CTls *t)
{
  if (!t)
    return;
  MemSet(t->wkey, 0, 32);
  MemSet(t->rkey, 0, 32);
  MemSet(t->wsec, 0, 32);
  MemSet(t->rsec, 0, 32);
  Free(t->cbuf);
  Free(t->pt);
  Free(t->wbuf);
  Free(t->hs);
  Free(t);
}

Bool TlsHandshake(CTls *t, U8 *sni)
{
  U8 xsec[32], xpub[32], spub[32], shared[32], sid[32], h[32], mac[32], fin[36];
  CTlsKs ks;
  U8 want[4], ccs[1];
  I64 m, step;
  Bool ok = FALSE;

  RandFill(xsec, 32);
  X25519Base(xpub, xsec);
  RandFill(sid, 32);
  Sha256Init(&t->th);
  if (!TlsSendHello(t, sni, xpub, sid))
    return TlsFail(t, 0, "sending ClientHello failed");

  m = TlsHsNext(t);
  if (m < 0 || !TlsParseServerHello(t, m, sid, spub))
    goto done;
  TlsTranscript(t, t->hs, m);
  TlsHsDrop(t, m);
  t->ccs_window = TRUE;
  if (t->hslen) {
    TlsFail(t, 10, "data after ServerHello");
    goto done;
  }
  X25519(shared, xsec, spub);
  if (TlsAllZero(shared, 32)) {
    TlsFail(t, 47, "degenerate x25519 shared secret");
    goto done;
  }
  TlsTranscriptHash(t, h);
  TlsKsHandshake(&ks, shared, h);
  TlsSetReadKeys(t, ks.s_hs);
  TlsSetWriteKeys(t, ks.c_hs);

  want[0] = 8;     // EncryptedExtensions, Certificate, CertificateVerify, Finished: each exactly once, in this order
  want[1] = 11;    // (Certificate and CertificateVerify are not validated)
  want[2] = 15;
  want[3] = 20;
  for (step = 0; step < 4; step++) {
    m = TlsHsNext(t);
    if (m < 0)
      goto done;
    if (t->hs[0] != want[step]) {
      TlsFail(t, 10, "unexpected handshake message order (CertificateRequest/HRR not supported)");
      goto done;
    }
    if (step == 3) {
      if (m != 36) {
        TlsFail(t, 50, "bad Finished");
        goto done;
      }
      TlsTranscriptHash(t, h);
      TlsFinishedMac(ks.s_hs, h, mac);
      if (!TlsSameMac(mac, t->hs + 4, 32)) {
        TlsFail(t, 51, "server Finished MAC mismatch");
        goto done;
      }
      t->ccs_window = FALSE;
    }
    TlsTranscript(t, t->hs, m);
    TlsHsDrop(t, m);
  }
  if (t->hslen) {
    TlsFail(t, 10, "data after server Finished");
    goto done;
  }

  TlsTranscriptHash(t, h);
  TlsKsApp(&ks, h);
  TlsFinishedMac(ks.c_hs, h, mac);
  fin[0] = 20;
  fin[1] = 0;
  fin[2] = 0;
  fin[3] = 32;
  MemCpy(fin + 4, mac, 32);
  ccs[0] = 1;
  if (!TlsRecWrite(t, TLS_ST_CCS, ccs, 1, FALSE) || !TlsRecWrite(t, TLS_ST_HS, fin, 36, TRUE)) {   // dummy CCS: RFC 8446 D.4
    TlsFail(t, 0, "sending client Finished failed");
    goto done;
  }
  TlsSetReadKeys(t, ks.s_ap);
  TlsSetWriteKeys(t, ks.c_ap);
  ok = TRUE;
done:
  MemSet(xsec, 0, 32);
  MemSet(shared, 0, 32);
  MemSet(&ks, 0, sizeof(CTlsKs));
  return ok;
}

// ---- post-handshake and the CConn interface -----------------------------------------------------------

// Replaces the traffic secret with the next one (RFC 8446 7.2).
U0 TlsKeyUpdateNext(U8 *secret)
{
  U8 next[32];
  TlsExpandLabel(secret, "traffic upd", NULL, 0, next, 32);
  MemCpy(secret, next, 32);
  MemSet(next, 0, 32);
}

// Handles complete post-handshake messages. Returns FALSE on a fatal error.
Bool TlsPostHandshake(CTls *t)
{
  I64 m;
  U8 ku[5];
  while ((m = TlsHsComplete(t))) {
    if (m < 0)
      return TlsFail(t, 50, "handshake message too large");
    switch (t->hs[0]) {
      case 4:     // NewSessionTicket: no resumption, ignore
        break;
      case 24:    // KeyUpdate
        if (m != 5 || t->hs[4] > 1)
          return TlsFail(t, 47, "bad KeyUpdate");
        TlsKeyUpdateNext(t->rsec);
        TlsSetReadKeys(t, t->rsec);
        if (t->hs[4] == 1) {
          ku[0] = 24; ku[1] = 0; ku[2] = 0; ku[3] = 1; ku[4] = 0;
          if (!TlsRecWrite(t, TLS_ST_HS, ku, 5, TRUE))
            return TlsFail(t, 0, "sending KeyUpdate failed");
          TlsKeyUpdateNext(t->wsec);
          TlsSetWriteKeys(t, t->wsec);
        }
        break;
      default:
        return TlsFail(t, 10, "unexpected post-handshake message");
    }
    TlsHsDrop(t, m);
  }
  return TRUE;
}

I64 TlsRead(CConn *c, U8 *buf, I64 len)
{
  CTls *t = c->priv;
  I64 n, type, take;
  U8 *d;

  if (len <= 0)
    return 0;
  if (t->dead)
    return -1;
  while (t->pos >= t->plen) {
    if (t->eof)
      return 0;
    n = TlsRecRead(t, &type, &d);
    if (n == -2) {      // a TCP close without close_notify may be a truncation attack: an error, not EOF
      TlsFail(t, 0, "connection closed without close_notify");
      return -1;
    }
    if (n < 0)
      return -1;
    if (type == TLS_ST_APP) {
      t->pos = 0;
      t->plen = n;
      t->pos = 0;
      t->plen = n;
    } else if (type == TLS_ST_HS) {
      if (!TlsHsAppend(t, d, n) || !TlsPostHandshake(t))
        return -1;
    } else if (type == TLS_ST_ALERT) {
      if (n == 2 && d[1] == 0) {        // close_notify
        t->eof = TRUE;
        return 0;
      }
      TlsFail(t, 0, "server sent a fatal alert");
      return -1;
    } else {
      TlsFail(t, 10, "unexpected record type");
      return -1;
    }
  }
  take = t->plen - t->pos;
  if (take > len)
    take = len;
  MemCpy(buf, t->pt + t->pos, take);
  t->pos += take;
  return take;
}

I64 TlsWrite(CConn *c, U8 *buf, I64 len)
{
  CTls *t = c->priv;
  I64 done = 0, n;
  if (t->dead)
    return -1;
  while (done < len) {
    n = len - done;
    if (n > TLS_REC_MAX)
      n = TLS_REC_MAX;
    if (!TlsRecWrite(t, TLS_ST_APP, buf + done, n, TRUE)) {
      TlsFail(t, 0, "write failed");
      return -1;
    }
    done += n;
  }
  return len;
}

U0 TlsClose(CConn *c)
{
  CTls *t = c->priv;
  U8 bye[2];
  bye[0] = 1;
  bye[1] = 0;
  if (!t->dead)
    TlsRecWrite(t, TLS_ST_ALERT, bye, 2, TRUE);   // close_notify; a dead socket just makes this fail
  t->tcp->close(t->tcp);
  TlsFree(t);
  Free(c);
}

// TLS handshake over an already connected stream (takes ownership of tcp: closed again on failure).
CConn *ConnTlsOver(CConn *tcp, U8 *sni)
{
  CConn *c;
  CTls *t = CAlloc(sizeof(CTls));
  t->tcp = tcp;
  t->cbuf = MAlloc(TLS_CT_MAX);
  t->pt = MAlloc(TLS_CT_MAX);
  t->wbuf = MAlloc(5 + TLS_REC_MAX + 17);
  t->hs = MAlloc(TLS_HS_MAX);
  tls_err = NULL;
  if (!TlsHandshake(t, sni)) {
    tcp->close(tcp);
    TlsFree(t);
    return NULL;
  }
  c = CAlloc(sizeof(CConn));
  c->read = &TlsRead;
  c->write = &TlsWrite;
  c->close = &TlsClose;
  c->sock = tcp->sock;
  c->priv = t;
  return c;
}

// Like ConnTlsOpen but the TLS server name can differ from the address that is connected to.
CConn *ConnTlsOpenSni(U8 *host, I64 port, U8 *sni)
{
  CConn *tcp = ConnTcpOpen(host, port);
  if (!tcp) {
    tls_err = "TCP connect failed";
    return NULL;
  }
  return ConnTlsOver(tcp, sni);
}

CConn *ConnTlsOpen(U8 *host, I64 port)
{
  return ConnTlsOpenSni(host, port, host);
}

#endif
