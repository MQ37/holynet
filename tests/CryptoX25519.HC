#include "B:/tests/Test"
#include "B:/src/Crypto/X25519"

I64 X25519TestNib(I64 c)
{
  if (c >= 'a')
    return c - 'a' + 10;
  return c - '0';
}

U0 X25519TestHex(U8 *hex, U8 *out)
{
  I64 i;
  for (i = 0; hex[2 * i]; i++)
    out[i] = (X25519TestNib(hex[2 * i]) << 4) | X25519TestNib(hex[2 * i + 1]);
}

// scalar * point must equal want (all hex, 32 bytes).
U0 X25519TestVec(U8 *scalar, U8 *point, U8 *want, U8 *what)
{
  U8 s[32], p[32], w[32], o[32];
  X25519TestHex(scalar, s);
  X25519TestHex(point, p);
  X25519TestHex(want, w);
  X25519(o, s, p);
  TestBytes(o, w, 32, what);
}

// RFC 7748 5.2 iterated test: k = u = 9, then repeat (k, u) = (X25519(k, u), k).
U0 X25519TestIter(I64 n, U8 *want, U8 *what)
{
  U8 k[32], u[32], r[32], w[32];
  I64 i;
  X25519TestHex("0900000000000000000000000000000000000000000000000000000000000000", k);
  MemCpy(u, k, 32);
  for (i = 0; i < n; i++) {
    X25519(r, k, u);
    MemCpy(u, k, 32);
    MemCpy(k, r, 32);
  }
  X25519TestHex(want, w);
  TestBytes(k, w, 32, what);
}

U0 X25519TestZero(U8 *point, U8 *what)
{
  U8 s[32], p[32], z[32], o[32];
  X25519TestHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", s);
  X25519TestHex(point, p);
  MemSet(z, 0, 32);
  X25519(o, s, p);
  TestBytes(o, z, 32, what);
}

U0 X25519TestDh()
{
  U8 a[32], b[32], pa[32], pb[32], w[32], k1[32], k2[32];
  X25519TestHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a);
  X25519TestHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b);
  X25519Base(pa, a);
  X25519TestHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", w);
  TestBytes(pa, w, 32, "alice public");
  X25519Base(pb, b);
  X25519TestHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", w);
  TestBytes(pb, w, 32, "bob public");
  X25519(k1, a, pb);
  X25519(k2, b, pa);
  X25519TestHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", w);
  TestBytes(k1, w, 32, "shared alice");
  TestBytes(k2, w, 32, "shared bob");
}

U0 X25519TestMain()
{
  F64 t0;
  X25519TestVec("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", "rfc vector 1");
  X25519TestVec("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", "rfc vector 2");
  X25519TestIter(1, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", "iter 1");
  t0 = tS;
  X25519TestIter(1000, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", "iter 1000");
  SerPrint("1000 X25519 calls: %.3f s\n", tS - t0);
  X25519TestDh;
  // low-order points (u = 0, 1, order-8 points, p-1, p, p+1) all yield the all-zero output
  X25519TestZero("0000000000000000000000000000000000000000000000000000000000000000", "u=0");
  X25519TestZero("0100000000000000000000000000000000000000000000000000000000000000", "u=1");
  X25519TestZero("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "order 8 a");
  X25519TestZero("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", "order 8 b");
  X25519TestZero("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "u=p-1");
  X25519TestZero("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "u=p");
  X25519TestZero("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "u=p+1");
}

X25519TestMain;
TestDone;
