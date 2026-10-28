// HMAC-SHA-256 (RFC 2104 / RFC 4231).
#include "B:/src/Crypto/Sha256"

U0 HmacSha256(U8 *key, I64 klen, U8 *msg, I64 mlen, U8 *out32)
{
  U8 k[64], pad[64], inner[32];
  CSha256 s;
  I64 i;
  MemSet(k, 0, 64);
  if (klen > 64)
    Sha256(key, klen, k);
  else
    MemCpy(k, key, klen);
  for (i = 0; i < 64; i++)
    pad[i] = k[i] ^ 0x36;
  Sha256Init(&s);
  Sha256Update(&s, pad, 64);
  Sha256Update(&s, msg, mlen);
  Sha256Final(&s, inner);
  for (i = 0; i < 64; i++)
    pad[i] = k[i] ^ 0x5c;
  Sha256Init(&s);
  Sha256Update(&s, pad, 64);
  Sha256Update(&s, inner, 32);
  Sha256Final(&s, out32);
}
