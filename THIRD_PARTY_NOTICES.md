# Third-party notices

## TempleOS and HolyC

TempleOS and HolyC were created by Terry A. Davis and released into the public domain. The lab downloads the stock ISO separately; it is not distributed in this repository.

## Shrine network stack

Source: <https://github.com/minexew/Shrine>, commit `348386b`.

The network files identified in `src/Net/PATCHES.md` are derived from Shrine and retain the Unlicense. The full notice is in `src/Net/LICENSE-Shrine.txt`. Shrine itself builds on TempleOS. No license is granted here for original project code.

## Cryptographic implementation references

- `src/Crypto/X25519.HC` follows the field arithmetic and Montgomery ladder of TweetNaCl, a public-domain implementation by Daniel J. Bernstein and collaborators: <https://tweetnacl.cr.yp.to/>.
- `src/Crypto/Chacha20Poly1305.HC` uses the 26-bit Poly1305 limb layout of Andrew M. / floodyberry's poly1305-donna: <https://github.com/floodyberry/poly1305-donna>. That project offers MIT and public-domain terms.
- Crypto and TLS tests refer to FIPS 180-4 and RFCs 4231, 5869, 7748, 8439, 8446 and 8448. These publications are specifications, not a certification of this implementation.

The poly1305-donna reference is used under its public-domain option.
