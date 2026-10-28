// X25519 (RFC 7748) after TweetNaCl: a field element is 16 limbs of 16 bits in I64 (HolyC has no
// 128-bit math; products of two 17-bit limbs summed 16 times stay far below 2^63).
// Limbs may be slightly negative or above 2^16 between carries; arithmetic >> on I64 floors.
// Low-order input points give an all-zero output; callers must reject an all-zero shared secret.

U0 X25519Set(I64 *o, I64 *a)
{
  I64 i;
  for (i = 0; i < 16; i++)
    o[i] = a[i];
}

U0 X25519Carry(I64 *o)
{
  I64 i, c;
  for (i = 0; i < 16; i++) {
    o[i] += 1 << 16;
    c = o[i] >> 16;
    if (i < 15)
      o[i + 1] += c - 1;
    else
      o[0] += 38 * (c - 1);
    o[i] -= c << 16;
  }
}

// Swap p and q when bit is 1, with no branch on bit.
U0 X25519Cswap(I64 *p, I64 *q, I64 bit)
{
  I64 i, t, mask = -bit;
  for (i = 0; i < 16; i++) {
    t = mask & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

U0 X25519Add(I64 *o, I64 *a, I64 *b)
{
  I64 i;
  for (i = 0; i < 16; i++)
    o[i] = a[i] + b[i];
}

U0 X25519Sub(I64 *o, I64 *a, I64 *b)
{
  I64 i;
  for (i = 0; i < 16; i++)
    o[i] = a[i] - b[i];
}

// 2^256 = 38 mod p, so the upper limbs fold back times 38.
U0 X25519Mul(I64 *o, I64 *a, I64 *b)
{
  I64 t[32], i, j;
  for (i = 0; i < 32; i++)
    t[i] = 0;
  for (i = 0; i < 16; i++)
    for (j = 0; j < 16; j++)
      t[i + j] += a[i] * b[j];
  for (i = 0; i < 16; i++)
    o[i] = t[i] + 38 * t[i + 16];
  X25519Carry(o);
  X25519Carry(o);
}

// a^(p-2) by square-and-multiply; the exponent is public so the branch is fine.
U0 X25519Invert(I64 *o, I64 *a)
{
  I64 c[16], i;
  X25519Set(c, a);
  for (i = 253; i >= 0; i--) {
    X25519Mul(c, c, c);
    if (i != 2 && i != 4)
      X25519Mul(c, c, a);
  }
  X25519Set(o, c);
}

U0 X25519Unpack(I64 *o, U8 *in)
{
  I64 i;
  for (i = 0; i < 16; i++)
    o[i] = in[2 * i] + (in[2 * i + 1] << 8);
  o[15] &= 0x7fff;
}

// Fully reduce mod p, then write 32 little-endian bytes.
U0 X25519Pack(U8 *out, I64 *a)
{
  I64 t[16], m[16], i, j, b;
  X25519Set(t, a);
  X25519Carry(t);
  X25519Carry(t);
  X25519Carry(t);
  for (j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    X25519Cswap(t, m, 1 - b);
  }
  for (i = 0; i < 16; i++) {
    out[2 * i] = t[i] & 0xff;
    out[2 * i + 1] = t[i] >> 8;
  }
}

U0 X25519(U8 *out32, U8 *scalar32, U8 *point32)
{
  U8 z[32];
  I64 x[16], a[16], b[16], c[16], d[16], e[16], f[16], k[16], i, r, swap = 0;
  for (i = 0; i < 32; i++)
    z[i] = scalar32[i];
  z[0] &= 248;
  z[31] = (z[31] & 127) | 64;
  X25519Unpack(x, point32);
  for (i = 0; i < 16; i++) {
    a[i] = 0;
    c[i] = 0;
    k[i] = 0;
  }
  X25519Set(b, x);
  for (i = 1; i < 16; i++)
    d[i] = 0;
  a[0] = 1;
  d[0] = 1;
  k[0] = 121665;
  for (i = 254; i >= 0; i--) {
    r = (z[i >> 3] >> (i & 7)) & 1;
    X25519Cswap(a, b, swap ^ r);
    X25519Cswap(c, d, swap ^ r);
    swap = r;
    X25519Add(e, a, c);
    X25519Sub(a, a, c);
    X25519Add(c, b, d);
    X25519Sub(b, b, d);
    X25519Mul(d, e, e);
    X25519Mul(f, a, a);
    X25519Mul(a, c, a);
    X25519Mul(c, b, e);
    X25519Add(e, a, c);
    X25519Sub(a, a, c);
    X25519Mul(b, a, a);
    X25519Sub(c, d, f);
    X25519Mul(a, c, k);
    X25519Add(a, a, d);
    X25519Mul(c, c, a);
    X25519Mul(a, d, f);
    X25519Mul(d, b, x);
    X25519Mul(b, e, e);
  }
  X25519Cswap(a, b, swap);
  X25519Cswap(c, d, swap);
  X25519Invert(c, c);
  X25519Mul(a, a, c);
  X25519Pack(out32, a);
}

U0 X25519Base(U8 *out32, U8 *scalar32)
{
  U8 nine[32];
  I64 i;
  for (i = 1; i < 32; i++)
    nine[i] = 0;
  nine[0] = 9;
  X25519(out32, scalar32, nine);
}
