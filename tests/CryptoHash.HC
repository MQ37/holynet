#include "B:/tests/Test"
#include "B:/src/Crypto/Hkdf"
#include "B:/src/Crypto/Rand"

I64 HexVal(I64 c)
{
  if (c >= 'a') return c - 'a' + 10;
  return c - '0';
}

// hex string -> bytes, returns byte count
I64 Unhex(U8 *hex, U8 *out)
{
  I64 n = 0;
  while (*hex) {
    out[n++] = HexVal(hex[0]) << 4 | HexVal(hex[1]);
    hex += 2;
  }
  return n;
}

U0 TestHex(U8 *got, I64 n, U8 *hex, U8 *what)
{
  U8 *want = MAlloc(n + 1);
  TestCheck(Unhex(hex, want) == n, what);
  TestBytes(got, want, n, what);
  Free(want);
}

U0 TestSha()
{
  U8 d[32], *m, *big;
  CSha256 s, snap;
  I64 i, chunk;
  Sha256("", 0, d);
  TestHex(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha empty");
  Sha256("abc", 3, d);
  TestHex(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha abc");
  m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  Sha256(m, StrLen(m), d);
  TestHex(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "sha 448 bit");
  big = MAlloc(1000000);
  MemSet(big, 'a', 1000000);
  Sha256(big, 1000000, d);
  TestHex(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "sha million a one shot");
  for (chunk = 1; chunk <= 1000000; chunk = chunk * 7 + 3) {
    Sha256Init(&s);
    for (i = 0; i < 1000000; i += chunk)
      Sha256Update(&s, big + i, Min(chunk, 1000000 - i));
    Sha256Final(&s, d);
    TestHex(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "sha million a chunked");
  }
  Free(big);
  // snapshot by MemCpy: hash "ab", snapshot, then both continue
  Sha256Init(&s);
  Sha256Update(&s, "a", 1);
  Sha256Update(&s, "b", 1);
  MemCpy(&snap, &s, sizeof(CSha256));
  Sha256Update(&s, "c", 1);
  Sha256Final(&s, d);
  TestHex(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha clone original");
  Sha256Update(&snap, "c", 1);
  Sha256Final(&snap, d);
  TestHex(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha clone copy");
  // lengths around the padding boundaries must agree with chunked feeding
  big = MAlloc(200);
  for (i = 0; i < 200; i++)
    big[i] = i;
  for (i = 50; i < 140; i++) {
    U8 d2[32];
    Sha256(big, i, d);
    Sha256Init(&s);
    Sha256Update(&s, big, i / 2);
    Sha256Update(&s, big + i / 2, i - i / 2);
    Sha256Final(&s, d2);
    TestBytes(d, d2, 32, "sha split lengths");
  }
  Free(big);
}

U0 TestHmac()
{
  U8 key[131], msg[160], d[32];
  I64 kl, ml;
  kl = Unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", key);
  HmacSha256(key, kl, "Hi There", 8, d);
  TestHex(d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "hmac 1");
  HmacSha256("Jefe", 4, "what do ya want for nothing?", 28, d);
  TestHex(d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "hmac 2");
  MemSet(key, 0xaa, 20);
  MemSet(msg, 0xdd, 50);
  HmacSha256(key, 20, msg, 50, d);
  TestHex(d, 32, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", "hmac 3");
  kl = Unhex("0102030405060708090a0b0c0d0e0f10111213141516171819", key);
  MemSet(msg, 0xcd, 50);
  HmacSha256(key, kl, msg, 50, d);
  TestHex(d, 32, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", "hmac 4");
  MemSet(key, 0xaa, 131);
  ml = StrLen("Test Using Larger Than Block-Size Key - Hash Key First");
  HmacSha256(key, 131, "Test Using Larger Than Block-Size Key - Hash Key First", ml, d);
  TestHex(d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "hmac 6");
  ml = StrLen("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
  HmacSha256(key, 131, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", ml, d);
  TestHex(d, 32, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", "hmac 7");
}

U0 TestHkdf()
{
  U8 ikm[80], salt[80], info[80], prk[32], okm[82];
  I64 il, sl, nl;
  il = Unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm);
  sl = Unhex("000102030405060708090a0b0c", salt);
  nl = Unhex("f0f1f2f3f4f5f6f7f8f9", info);
  HkdfExtract(salt, sl, ikm, il, prk);
  TestHex(prk, 32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "hkdf 1 prk");
  HkdfExpand(prk, info, nl, okm, 42);
  TestHex(okm, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "hkdf 1 okm");
  il = Unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", ikm);
  sl = Unhex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", salt);
  nl = Unhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", info);
  HkdfExtract(salt, sl, ikm, il, prk);
  TestHex(prk, 32, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", "hkdf 2 prk");
  HkdfExpand(prk, info, nl, okm, 82);
  TestHex(okm, 82, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87", "hkdf 2 okm");
  il = Unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm);
  HkdfExtract(NULL, 0, ikm, il, prk);
  TestHex(prk, 32, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "hkdf 3 prk");
  HkdfExpand(prk, NULL, 0, okm, 42);
  TestHex(okm, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", "hkdf 3 okm");
  MemSet(okm, 0x5A, 82);
  HkdfExpand(prk, NULL, 0, okm, 255 * 32 + 1);          // over the RFC 5869 limit: refused, nothing written
  TestCheck(okm[0] == 0x5A && okm[81] == 0x5A, "hkdf rejects olen > 255*32");
}

U0 TestRand()
{
  U8 *b = MAlloc(32 * 1000), z[32];
  I64 i, j, dup = 0, zero = 0;
  MemSet(z, 0, 32);
  for (i = 0; i < 1000; i++) {
    RandFill(b + 32 * i, 32);
    if (!MemCmp(b + 32 * i, z, 32))
      zero++;
  }
  for (i = 0; i < 1000; i++)
    for (j = 0; j < i; j++)
      if (!MemCmp(b + 32 * i, b + 32 * j, 32))
        dup++;
  TestCheck(!zero, "rand no zero block");
  TestCheck(!dup, "rand no repeated block");
  RandFill(b, 37);   // odd length must not overrun
  Free(b);
}

U0 TestSpeed()
{
  U8 *big = MAlloc(1000000), d[32];
  F64 t0;
  MemSet(big, 'a', 1000000);
  t0 = tS;
  Sha256(big, 1000000, d);
  SerPrint("sha256 1 MB: %d ms\n", ToI64((tS - t0) * 1000));
  Free(big);
}

TestSha;
TestHmac;
TestHkdf;
TestRand;
TestSpeed;
TestDone;
