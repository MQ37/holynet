// SHA-256 (FIPS 180-4). 32-bit words are kept in I64 and masked, rotates are done by hand.

class CSha256 { U32 h[8]; U8 buf[64]; I64 buflen, total; };

U32 sha256_k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

I64 Sha256Rotr(I64 x, I64 n)
{
  return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF;
}

U0 Sha256Block(CSha256 *s, U8 *p)
{
  I64 w[64], i, a, b, c, d, e, f, g, h, t1, t2, s0, s1;
  for (i = 0; i < 16; i++)
    w[i] = p[4 * i] << 24 | p[4 * i + 1] << 16 | p[4 * i + 2] << 8 | p[4 * i + 3];
  for (i = 16; i < 64; i++) {
    s0 = Sha256Rotr(w[i - 15], 7) ^ Sha256Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    s1 = Sha256Rotr(w[i - 2], 17) ^ Sha256Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF;
  }
  a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
  e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
  for (i = 0; i < 64; i++) {
    s1 = Sha256Rotr(e, 6) ^ Sha256Rotr(e, 11) ^ Sha256Rotr(e, 25);
    t1 = h + s1 + ((e & f) ^ (~e & g)) + sha256_k[i] + w[i];
    s0 = Sha256Rotr(a, 2) ^ Sha256Rotr(a, 13) ^ Sha256Rotr(a, 22);
    t2 = s0 + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e;
    e = (d + t1) & 0xFFFFFFFF;
    d = c; c = b; b = a;
    a = (t1 + t2) & 0xFFFFFFFF;
  }
  s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
  s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

U0 Sha256Init(CSha256 *s)
{
  s->h[0] = 0x6a09e667; s->h[1] = 0xbb67ae85; s->h[2] = 0x3c6ef372; s->h[3] = 0xa54ff53a;
  s->h[4] = 0x510e527f; s->h[5] = 0x9b05688c; s->h[6] = 0x1f83d9ab; s->h[7] = 0x5be0cd19;
  s->buflen = 0;
  s->total = 0;
}

U0 Sha256Update(CSha256 *s, U8 *data, I64 len)
{
  I64 n;
  s->total += len;
  if (s->buflen) {
    n = 64 - s->buflen;
    if (n > len)
      n = len;
    MemCpy(s->buf + s->buflen, data, n);
    s->buflen += n;
    data += n;
    len -= n;
    if (s->buflen < 64)
      return;
    Sha256Block(s, s->buf);
    s->buflen = 0;
  }
  while (len >= 64) {
    Sha256Block(s, data);
    data += 64;
    len -= 64;
  }
  if (len) {
    MemCpy(s->buf, data, len);
    s->buflen = len;
  }
}

U0 Sha256Final(CSha256 *s, U8 *out32)
{
  I64 bits = s->total << 3, i;
  U8 pad[72];
  I64 padlen = 56 - s->buflen;
  if (padlen <= 0)
    padlen += 64;
  MemSet(pad, 0, 72);
  pad[0] = 0x80;
  for (i = 0; i < 8; i++)
    pad[padlen + i] = bits >> (56 - 8 * i);
  Sha256Update(s, pad, padlen + 8);
  for (i = 0; i < 8; i++) {
    out32[4 * i] = s->h[i] >> 24;
    out32[4 * i + 1] = s->h[i] >> 16;
    out32[4 * i + 2] = s->h[i] >> 8;
    out32[4 * i + 3] = s->h[i];
  }
}

U0 Sha256(U8 *data, I64 len, U8 *out32)
{
  CSha256 s;
  Sha256Init(&s);
  Sha256Update(&s, data, len);
  Sha256Final(&s, out32);
}
