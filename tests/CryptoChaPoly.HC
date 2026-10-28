// ChaCha20-Poly1305 tests: RFC 8439 vectors (2.1.1, 2.3.2, 2.4.2, 2.5.2, 2.6.2, 2.8.2, A.1-A.5), tamper, round trips, speed.
#include "B:/tests/Test"
#include "B:/src/Crypto/Chacha20Poly1305"

I64 THexVal(I64 c)
{
  if (c >= 'a')
    return c - 'a' + 10;
  if (c >= 'A')
    return c - 'A' + 10;
  return c - '0';
}

// Decodes hex (spaces ignored) into a fresh buffer; *n gets the byte count.
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

U8 *T_KEY = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
U8 *T_PT = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
U8 *T_IETF = "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
U8 *T_JABBER = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";

U0 TestQuarterRound()
{
  I64 x[16];
  x[0] = 0x11111111; x[1] = 0x01020304; x[2] = 0x9b8d6f43; x[3] = 0x01234567;
  ChaQr(x, 0, 1, 2, 3);
  TestCheck(x[0] == 0xea2a92f4 && x[1] == 0xcb1cf8ce && x[2] == 0x4581472e && x[3] == 0x5881c4bb, "2.1.1 quarter round");
}

U0 TestKeystream(U8 *keyhex, U8 *noncehex, I64 ctr, U8 *wanthex, U8 *what)
{
  U8 *key = THex(keyhex, NULL), *nonce = THex(noncehex, NULL), out[64];
  Chacha20Block(key, ctr, nonce, out);
  TestHexEq(out, wanthex, what);
  Free(key);
  Free(nonce);
}

U0 TestChaCha()
{
  U8 *key = THex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", NULL);
  U8 *nonce = THex("000000000000004a00000000", NULL), *ct;
  I64 n = StrLen(T_PT);
  TestKeystream("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000090000004a00000000", 1,
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    "2.3.2 block function");
  ct = MAlloc(n);
  Chacha20Xor(key, 1, nonce, T_PT, n, ct);
  TestHexEq(ct, "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d", "2.4.2 encryption");
  Chacha20Xor(key, 1, nonce, ct, n, ct);
  TestBytes(ct, T_PT, n, "2.4.2 in-place decrypt");
  Free(ct);
  Free(key);
  Free(nonce);

  TestKeystream("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", 0,
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", "A.1 #1");
  TestKeystream("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", 1,
    "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f", "A.1 #2");
  TestKeystream("0000000000000000000000000000000000000000000000000000000000000001", "000000000000000000000000", 1,
    "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0", "A.1 #3");
  TestKeystream("00ff000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", 2,
    "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096", "A.1 #4");
  TestKeystream("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000002", 0,
    "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d", "A.1 #5");
}

U0 TestPolyVec(U8 *keyhex, U8 *msg, I64 mlen, U8 *taghex, U8 *what)
{
  U8 *key = THex(keyhex, NULL), tag[16];
  Poly1305Mac(key, msg, mlen, tag);
  TestHexEq(tag, taghex, what);
  Free(key);
}

U0 TestPolyHex(U8 *keyhex, U8 *msghex, U8 *taghex, U8 *what)
{
  I64 n;
  U8 *msg = THex(msghex, &n);
  TestPolyVec(keyhex, msg, n, taghex, what);
  Free(msg);
}

U0 TestPoly()
{
  U8 *z64 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
  TestPolyVec("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", "Cryptographic Forum Research Group", 34,
    "a8061dc1305136c6c22b8baf0c0127a9", "2.5.2 poly1305");
  TestPolyHex("0000000000000000000000000000000000000000000000000000000000000000", z64, "00000000000000000000000000000000", "A.3 #1");
  TestPolyVec("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e", T_IETF, StrLen(T_IETF), "36e5f6b5c5e06070f0efca96227a863e", "A.3 #2");
  TestPolyVec("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000", T_IETF, StrLen(T_IETF), "f3477e7cd95417af89a6b8794c310cf0", "A.3 #3");
  TestPolyVec("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", T_JABBER, StrLen(T_JABBER), "4541669a7eaaee61e708dc7cbcc5eb62", "A.3 #4");
  // Edge cases for the final reduction (A.3 #5-#11)
  TestPolyHex("0200000000000000000000000000000000000000000000000000000000000000", "ffffffffffffffffffffffffffffffff", "03000000000000000000000000000000", "A.3 #5");
  TestPolyHex("02000000000000000000000000000000ffffffffffffffffffffffffffffffff", "02000000000000000000000000000000", "03000000000000000000000000000000", "A.3 #6");
  TestPolyHex("0100000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff f0ffffffffffffffffffffffffffffff 11000000000000000000000000000000", "05000000000000000000000000000000", "A.3 #7");
  TestPolyHex("0100000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff fbfefefefefefefefefefefefefefefe 01010101010101010101010101010101", "00000000000000000000000000000000", "A.3 #8");
  TestPolyHex("0200000000000000000000000000000000000000000000000000000000000000", "fdffffffffffffffffffffffffffffff", "faffffffffffffffffffffffffffffff", "A.3 #9");
  TestPolyHex("0100000000000000040000000000000000000000000000000000000000000000",
    "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000",
    "14000000000000005500000000000000", "A.3 #10");
  TestPolyHex("0100000000000000040000000000000000000000000000000000000000000000",
    "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000",
    "13000000000000000000000000000000", "A.3 #11");
}

U0 TestKeyGen()
{
  U8 *key = THex(T_KEY, NULL), *nonce = THex("000000000001020304050607", NULL), out[64];
  Chacha20Block(key, 0, nonce, out);
  TestHexEq(out, "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646", "2.6.2 poly key gen");
  Free(key);
  Free(nonce);
  TestKeystream("0000000000000000000000000000000000000000000000000000000000000001", "000000000000000000000002", 0,
    "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739", "A.4 #2 poly key gen");
}

U0 TestAead()
{
  U8 *key = THex(T_KEY, NULL), *nonce = THex("070000004041424344454647", NULL), *aad, *want;
  U8 *out, *back, *bad, *key2, *nonce2, *aad2, *tamper;
  I64 n = StrLen(T_PT), alen, wlen, i, b;
  Bool ok;
  aad = THex("50515253c0c1c2c3c4c5c6c7", &alen);
  want = THex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    "1ae10b594f09e26a7e902ecbd0600691", &wlen);
  out = MAlloc(n + 16);
  back = MAlloc(n + 16);
  Chacha20Poly1305Seal(key, nonce, aad, alen, T_PT, n, out);
  TestBytes(out, want, wlen, "2.8.2 seal");
  TestCheck(wlen == n + 16, "2.8.2 length");
  TestCheck(Chacha20Poly1305Open(key, nonce, aad, alen, out, n + 16, back), "2.8.2 open");
  TestBytes(back, T_PT, n, "2.8.2 plaintext");

  // Tamper: every byte of ct, tag, aad and nonce; out must stay untouched on failure.
  bad = MAlloc(n + 16);
  tamper = MAlloc(n + 16);
  ok = TRUE;
  for (i = 0; i < n + 16; i++) {
    MemCpy(tamper, out, n + 16);
    tamper[i] ^= 1 << (i & 7);
    MemSet(bad, 0xAA, n + 16);
    if (Chacha20Poly1305Open(key, nonce, aad, alen, tamper, n + 16, bad))
      ok = FALSE;
    for (b = 0; b < n; b++)
      if (bad[b] != 0xAA)
        ok = FALSE;
  }
  TestCheck(ok, "tamper ct/tag: Open FALSE, no plaintext released");
  ok = TRUE;
  aad2 = MAlloc(alen);
  for (i = 0; i < alen; i++) {
    MemCpy(aad2, aad, alen);
    aad2[i] ^= 0x80;
    if (Chacha20Poly1305Open(key, nonce, aad2, alen, out, n + 16, back))
      ok = FALSE;
  }
  TestCheck(ok, "tamper aad");
  if (Chacha20Poly1305Open(key, nonce, aad, alen - 1, out, n + 16, back))
    ok = FALSE;
  if (Chacha20Poly1305Open(key, nonce, aad, alen, out, n + 15, back))
    ok = FALSE;
  TestCheck(ok, "truncated aad / ct");
  ok = TRUE;
  nonce2 = MAlloc(12);
  for (i = 0; i < 12; i++) {
    MemCpy(nonce2, nonce, 12);
    nonce2[i] ^= 1;
    if (Chacha20Poly1305Open(key, nonce2, aad, alen, out, n + 16, back))
      ok = FALSE;
  }
  TestCheck(ok, "tamper nonce");
  ok = TRUE;
  key2 = MAlloc(32);
  for (i = 0; i < 32; i++) {
    MemCpy(key2, key, 32);
    key2[i] ^= 1;
    if (Chacha20Poly1305Open(key2, nonce, aad, alen, out, n + 16, back))
      ok = FALSE;
  }
  TestCheck(ok, "tamper key");
  TestCheck(!Chacha20Poly1305Open(key, nonce, aad, alen, out, 15, back), "clen < 16");

  // In place: Seal with out == pt, Open with out == ct.
  MemCpy(tamper, T_PT, n);
  Chacha20Poly1305Seal(key, nonce, aad, alen, tamper, n, tamper);
  TestBytes(tamper, want, wlen, "in-place seal");
  TestCheck(Chacha20Poly1305Open(key, nonce, aad, alen, tamper, n + 16, tamper), "in-place open");
  TestBytes(tamper, T_PT, n, "in-place open plaintext");
  Free(key); Free(nonce); Free(aad); Free(want); Free(out); Free(back); Free(bad);
  Free(tamper); Free(aad2); Free(nonce2); Free(key2);
}

U0 TestA5()
{
  U8 *key = THex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", NULL);
  U8 *nonce = THex("000000000102030405060708", NULL), *aad, *ct, *pt;
  I64 alen, clen;
  U8 *want = "Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time.";
  aad = THex("f33388860000000000004e91", &alen);
  ct = THex("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b"
    "eead9d67890cbb22392336fea1851f38", &clen);
  pt = MAlloc(clen);
  TestCheck(clen == 281, "A.5 ct length");
  TestCheck(Chacha20Poly1305Open(key, nonce, aad, alen, ct, clen, pt), "A.5 open");
  TestBytes(pt, want, StrLen(want), "A.5 plaintext");
  Free(key); Free(nonce); Free(aad); Free(ct); Free(pt);
}

// A.2 #2 and #3: decrypt the RFC ciphertext, compare with the known text.
U0 TestA2()
{
  U8 *key = THex("0000000000000000000000000000000000000000000000000000000000000001", NULL);
  U8 *nonce = THex("000000000000000000000002", NULL), *ct, *pt;
  I64 n;
  ct = THex("a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221", &n);
  pt = MAlloc(n);
  Chacha20Xor(key, 1, nonce, ct, n, pt);
  TestCheck(n == StrLen(T_IETF), "A.2 #2 length");
  TestBytes(pt, T_IETF, n, "A.2 #2 decrypt");
  Free(ct); Free(pt); Free(key); Free(nonce);
  key = THex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", NULL);
  nonce = THex("000000000000000000000002", NULL);
  ct = THex("62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a553205571" "6ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1", &n);
  pt = MAlloc(n);
  Chacha20Xor(key, 0x2a, nonce, ct, n, pt);
  TestCheck(n == StrLen(T_JABBER), "A.2 #3 length");
  TestBytes(pt, T_JABBER, n, "A.2 #3 decrypt");
  Free(ct); Free(pt); Free(key); Free(nonce);
}

// Independent check of the AEAD framing: build aad|pad|ct|pad|lens explicitly and use the one-shot MAC.
U0 TestFraming(U8 *key, U8 *nonce, U8 *aad, I64 alen, U8 *ct, I64 clen, U8 *tag, U8 *what)
{
  U8 otk[64], want[16], *buf;
  I64 ap = (alen + 15) & ~15, cp = (clen + 15) & ~15;
  buf = CAlloc(ap + cp + 16);
  MemCpy(buf, aad, alen);
  MemCpy(buf + ap, ct, clen);
  ChaPutLe32(buf + ap + cp, alen);
  ChaPutLe32(buf + ap + cp + 8, clen);
  Chacha20Block(key, 0, nonce, otk);
  Poly1305Mac(otk, buf, ap + cp + 16, want);
  TestBytes(tag, want, 16, what);
  Free(buf);
}

U0 TestRoundTrips()
{
  U8 key[32], nonce[12], *aad, *pt, *ct, *back;
  I64 len, i, alen;
  Bool ok = TRUE, framing = TRUE;
  for (i = 0; i < 32; i++)
    key[i] = i * 7 + 3;
  for (i = 0; i < 12; i++)
    nonce[i] = i * 13 + 1;
  aad = MAlloc(64);
  pt = MAlloc(16384);
  ct = MAlloc(16384 + 16);
  back = MAlloc(16384 + 16);
  for (i = 0; i < 64; i++)
    aad[i] = i * 5;
  for (i = 0; i < 16384; i++)
    pt[i] = i * 31 + (i >> 8);
  for (len = 0; len <= 130; len++) {
    alen = (len * 7) % 41;
    Chacha20Poly1305Seal(key, nonce, aad, alen, pt, len, ct);
    MemSet(back, 0, len + 1);
    if (!Chacha20Poly1305Open(key, nonce, aad, alen, ct, len + 16, back) || MemCmp(back, pt, len))
      ok = FALSE;
    Chacha20Poly1305Seal(key, nonce, aad, alen, pt, len, back);
    if (MemCmp(back, ct, len + 16))
      ok = FALSE;
    TestFraming(key, nonce, aad, alen, ct, len, ct + len, "framing 0..130");
  }
  TestCheck(ok, "round trip lengths 0..130");
  Chacha20Poly1305Seal(key, nonce, aad, 13, pt, 16384, ct);
  TestCheck(Chacha20Poly1305Open(key, nonce, aad, 13, ct, 16384 + 16, back) && !MemCmp(back, pt, 16384), "round trip 16 KB");
  TestFraming(key, nonce, aad, 13, ct, 16384, ct + 16384, "framing 16 KB");
  Free(aad); Free(pt); Free(ct); Free(back);
}

U0 TestSpeed()
{
  U8 key[32], nonce[12], *pt, *out;
  F64 t0, dt;
  I64 i;
  MemSet(key, 7, 32);
  MemSet(nonce, 9, 12);
  pt = CAlloc(16384);
  out = MAlloc(16384 + 16);
  t0 = tS;
  for (i = 0; i < 20; i++)
    Chacha20Poly1305Seal(key, nonce, NULL, 0, pt, 16384, out);
  dt = (tS - t0) / 20;
  SerPrint("seal 16 KB: %d us\n", ToI64(dt * 1000000));
  TestCheck(dt < 1.0, "seal 16 KB under 1 s");
  Free(pt); Free(out);
}

TestQuarterRound;
TestChaCha;
TestPoly;
TestKeyGen;
TestAead;
TestA5;
TestA2;
TestRoundTrips;
TestSpeed;
TestDone;
