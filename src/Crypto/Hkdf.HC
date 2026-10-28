// HKDF-SHA-256 (RFC 5869).
#include "B:/src/Crypto/Hmac"

U0 HkdfExtract(U8 *salt, I64 slen, U8 *ikm, I64 ilen, U8 *prk32)
{
  U8 zeros[32];
  if (!slen) {
    MemSet(zeros, 0, 32);
    salt = zeros;
    slen = 32;
  }
  HmacSha256(salt, slen, ikm, ilen, prk32);
}

U0 HkdfExpand(U8 *prk32, U8 *info, I64 ilen, U8 *out, I64 olen)
{
  if (olen > 255 * 32)
    return;
  U8 t[32], *in = MAlloc(32 + ilen + 1);
  I64 n = 0, i = 1, take;
  while (olen > 0) {
    MemCpy(in, t, n);
    MemCpy(in + n, info, ilen);
    in[n + ilen] = i++;
    HmacSha256(prk32, 32, in, n + ilen + 1, t);
    n = 32;
    take = olen;
    if (take > 32)
      take = 32;
    MemCpy(out, t, take);
    out += take;
    olen -= take;
  }
  Free(in);
}
