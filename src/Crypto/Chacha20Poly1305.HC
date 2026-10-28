// ChaCha20-Poly1305 AEAD (RFC 8439). 32-bit words live in I64 and are masked after every
// add/shift; Poly1305 uses 26-bit limbs so every product sum stays below 2^63 (donna-32 layout).
// In-place use is supported: Seal with out == pt and Open with out == ct both work.

#define CHA_M32  0xFFFFFFFF
#define POLY_M26 0x3FFFFFF

I64 ChaLe32(U8 *p)
{
  return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

U0 ChaPutLe32(U8 *p, I64 v)
{
  p[0] = v;
  p[1] = v >> 8;
  p[2] = v >> 16;
  p[3] = v >> 24;
}

I64 ChaRotl(I64 v, I64 n)
{
  return ((v << n) | (v >> (32 - n))) & CHA_M32;
}

U0 ChaQr(I64 *x, I64 a, I64 b, I64 c, I64 d)
{
  x[a] = (x[a] + x[b]) & CHA_M32;  x[d] = ChaRotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) & CHA_M32;  x[b] = ChaRotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) & CHA_M32;  x[d] = ChaRotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) & CHA_M32;  x[b] = ChaRotl(x[b] ^ x[c], 7);
}

// One 64-byte keystream block (RFC 8439 2.3).
U0 Chacha20Block(U8 *key32, I64 counter, U8 *nonce12, U8 *out64)
{
  I64 s[16], x[16], i;
  s[0] = 0x61707865;  s[1] = 0x3320646e;  s[2] = 0x79622d32;  s[3] = 0x6b206574;
  for (i = 0; i < 8; i++)
    s[4 + i] = ChaLe32(key32 + 4 * i);
  s[12] = counter & CHA_M32;
  for (i = 0; i < 3; i++)
    s[13 + i] = ChaLe32(nonce12 + 4 * i);
  for (i = 0; i < 16; i++)
    x[i] = s[i];
  for (i = 0; i < 10; i++) {
    ChaQr(x, 0, 4, 8, 12);  ChaQr(x, 1, 5, 9, 13);
    ChaQr(x, 2, 6, 10, 14); ChaQr(x, 3, 7, 11, 15);
    ChaQr(x, 0, 5, 10, 15); ChaQr(x, 1, 6, 11, 12);
    ChaQr(x, 2, 7, 8, 13);  ChaQr(x, 3, 4, 9, 14);
  }
  for (i = 0; i < 16; i++)
    ChaPutLe32(out64 + 4 * i, (x[i] + s[i]) & CHA_M32);
}

// XOR len bytes of in with the keystream starting at block `counter`. out may equal in.
U0 Chacha20Xor(U8 *key32, I64 counter, U8 *nonce12, U8 *in, I64 len, U8 *out)
{
  U8 ks[64];
  I64 i, n;
  while (len > 0) {
    Chacha20Block(key32, counter++, nonce12, ks);
    n = len;
    if (n > 64)
      n = 64;
    for (i = 0; i < n; i++)
      out[i] = in[i] ^ ks[i];
    in += n;
    out += n;
    len -= n;
  }
}

class CPoly1305 { I64 r[5], h[5], pad[4]; };

U0 Poly1305Init(CPoly1305 *p, U8 *key32)
{
  p->r[0] = ChaLe32(key32) & POLY_M26;
  p->r[1] = (ChaLe32(key32 + 3) >> 2) & 0x3FFFF03;
  p->r[2] = (ChaLe32(key32 + 6) >> 4) & 0x3FFC0FF;
  p->r[3] = (ChaLe32(key32 + 9) >> 6) & 0x3F03FFF;
  p->r[4] = (ChaLe32(key32 + 12) >> 8) & 0x00FFFFF;
  MemSet(p->h, 0, 5 * sizeof(I64));
  p->pad[0] = ChaLe32(key32 + 16);
  p->pad[1] = ChaLe32(key32 + 20);
  p->pad[2] = ChaLe32(key32 + 24);
  p->pad[3] = ChaLe32(key32 + 28);
}

// Absorb whole 16-byte blocks; hibit is 1<<24 for a full block, 0 for the padded final one.
U0 Poly1305Blocks(CPoly1305 *p, U8 *m, I64 len, I64 hibit)
{
  I64 r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
  I64 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
  I64 h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
  I64 d0, d1, d2, d3, d4, c;
  while (len >= 16) {
    h0 += ChaLe32(m) & POLY_M26;
    h1 += (ChaLe32(m + 3) >> 2) & POLY_M26;
    h2 += (ChaLe32(m + 6) >> 4) & POLY_M26;
    h3 += (ChaLe32(m + 9) >> 6) & POLY_M26;
    h4 += (ChaLe32(m + 12) >> 8) | hibit;
    d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    c = d0 >> 26;  h0 = d0 & POLY_M26;
    d1 += c;  c = d1 >> 26;  h1 = d1 & POLY_M26;
    d2 += c;  c = d2 >> 26;  h2 = d2 & POLY_M26;
    d3 += c;  c = d3 >> 26;  h3 = d3 & POLY_M26;
    d4 += c;  c = d4 >> 26;  h4 = d4 & POLY_M26;
    h0 += c * 5;  c = h0 >> 26;  h0 &= POLY_M26;
    h1 += c;
    m += 16;
    len -= 16;
  }
  p->h[0] = h0;  p->h[1] = h1;  p->h[2] = h2;  p->h[3] = h3;  p->h[4] = h4;
}

U0 Poly1305Finish(CPoly1305 *p, U8 *tag16)
{
  I64 h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
  I64 g0, g1, g2, g3, g4, c, mask, f;
  c = h1 >> 26;  h1 &= POLY_M26;
  h2 += c;  c = h2 >> 26;  h2 &= POLY_M26;
  h3 += c;  c = h3 >> 26;  h3 &= POLY_M26;
  h4 += c;  c = h4 >> 26;  h4 &= POLY_M26;
  h0 += c * 5;  c = h0 >> 26;  h0 &= POLY_M26;
  h1 += c;
  g0 = h0 + 5;  c = g0 >> 26;  g0 &= POLY_M26;
  g1 = h1 + c;  c = g1 >> 26;  g1 &= POLY_M26;
  g2 = h2 + c;  c = g2 >> 26;  g2 &= POLY_M26;
  g3 = h3 + c;  c = g3 >> 26;  g3 &= POLY_M26;
  g4 = h4 + c - (1 << 26);
  mask = ((g4 >> 63) & 1) - 1;  // all ones when h >= p (g4 did not go negative)
  g0 &= mask;  g1 &= mask;  g2 &= mask;  g3 &= mask;  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;  h1 = (h1 & mask) | g1;  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;  h4 = (h4 & mask) | g4;
  h0 = (h0 | h1 << 26) & CHA_M32;
  h1 = (h1 >> 6 | h2 << 20) & CHA_M32;
  h2 = (h2 >> 12 | h3 << 14) & CHA_M32;
  h3 = (h3 >> 18 | h4 << 8) & CHA_M32;
  f = h0 + p->pad[0];  ChaPutLe32(tag16, f);
  f = h1 + p->pad[1] + (f >> 32);  ChaPutLe32(tag16 + 4, f);
  f = h2 + p->pad[2] + (f >> 32);  ChaPutLe32(tag16 + 8, f);
  f = h3 + p->pad[3] + (f >> 32);  ChaPutLe32(tag16 + 12, f);
}

// One-shot Poly1305 (RFC 8439 2.5): partial last block gets the 0x01 terminator.
U0 Poly1305Mac(U8 *key32, U8 *msg, I64 len, U8 *tag16)
{
  CPoly1305 p;
  U8 last[16];
  I64 full = len & ~15, rem = len & 15;
  Poly1305Init(&p, key32);
  Poly1305Blocks(&p, msg, full, 1 << 24);
  if (rem) {
    MemSet(last, 0, 16);
    MemCpy(last, msg + full, rem);
    last[rem] = 1;
    Poly1305Blocks(&p, last, 16, 0);
  }
  Poly1305Finish(&p, tag16);
}

// AEAD pad16(x): zero-extended last block counts as a full block.
U0 ChaPolyFeed(CPoly1305 *p, U8 *data, I64 len)
{
  U8 last[16];
  I64 full = len & ~15, rem = len & 15;
  Poly1305Blocks(p, data, full, 1 << 24);
  if (rem) {
    MemSet(last, 0, 16);
    MemCpy(last, data + full, rem);
    Poly1305Blocks(p, last, 16, 1 << 24);
  }
}

// Tag over aad || pad || ct || pad || le64(alen) || le64(clen) with the key from block 0.
U0 ChaPolyTag(U8 *key32, U8 *nonce12, U8 *aad, I64 alen, U8 *ct, I64 clen, U8 *tag16)
{
  CPoly1305 p;
  U8 otk[64], lens[16];
  Chacha20Block(key32, 0, nonce12, otk);
  Poly1305Init(&p, otk);
  ChaPolyFeed(&p, aad, alen);
  ChaPolyFeed(&p, ct, clen);
  ChaPutLe32(lens, alen);  ChaPutLe32(lens + 4, alen >> 32);
  ChaPutLe32(lens + 8, clen);  ChaPutLe32(lens + 12, clen >> 32);
  Poly1305Blocks(&p, lens, 16, 1 << 24);
  Poly1305Finish(&p, tag16);
  MemSet(otk, 0, 64);
}

U0 Chacha20Poly1305Seal(U8 *key32, U8 *nonce12, U8 *aad, I64 alen, U8 *pt, I64 plen, U8 *out)
{
  Chacha20Xor(key32, 1, nonce12, pt, plen, out);
  ChaPolyTag(key32, nonce12, aad, alen, out, plen, out + plen);
}

Bool Chacha20Poly1305Open(U8 *key32, U8 *nonce12, U8 *aad, I64 alen, U8 *ct, I64 clen, U8 *out)
{
  U8 tag[16];
  I64 i, diff = 0, plen = clen - 16;
  if (plen < 0)
    return FALSE;
  ChaPolyTag(key32, nonce12, aad, alen, ct, plen, tag);
  for (i = 0; i < 16; i++)
    diff |= tag[i] ^ ct[plen + i];
  if (diff)
    return FALSE;
  Chacha20Xor(key32, 1, nonce12, ct, plen, out);
  return TRUE;
}
