// RandFill: DEMO-GRADE randomness, NOT a vetted CSPRNG.
// A pool is re-hashed with SHA-256 together with the CPU timestamp counter, the jiffies counter and
// TempleOS RandU64 (a plain PRNG seeded from the clock). TempleOS has no hardware RNG driver and a
// VM has little real jitter, so an attacker who can guess boot time and timing can narrow the
// output down. Good enough for a demo client, not for keys that must stay secret.
#include "B:/src/Crypto/Sha256"

U8 rand_pool[32];
I64 rand_ctr;

U0 RandFill(U8 *buf, I64 n)
{
  I64 seed[5], take;
  U8 out[32];
  CSha256 s;
  while (n > 0) {
    seed[0] = GetTSC;
    seed[1] = cnts.jiffies;
    seed[2] = RandU64;
    seed[3] = RandU64;
    seed[4] = rand_ctr++;
    Sha256Init(&s);
    Sha256Update(&s, rand_pool, 32);
    Sha256Update(&s, seed, 40);
    Sha256Final(&s, out);
    MemCpy(rand_pool, out, 32);
    // hash again so the pool state is never handed out
    Sha256(out, 32, out);
    take = n;
    if (take > 32)
      take = 32;
    MemCpy(buf, out, take);
    buf += take;
    n -= take;
  }
}
