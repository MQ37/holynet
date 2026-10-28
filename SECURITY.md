# Experimental security model

HolyNet is an experimental networking library for an operating system without a built-in network stack. It is not suitable for sensitive workloads.

## TLS does not authenticate the server

The TLS 1.3 implementation negotiates X25519 with ChaCha20-Poly1305. It checks the handshake Finished MAC and authenticated record tags, but does **not** verify the certificate chain or CertificateVerify signature. An active attacker can impersonate the server. SNI is a routing hint, not identity verification.

`RandFill` mixes the timestamp counter, jiffies and TempleOS random output. It is experimental entropy, not a cryptographically validated random generator. Passing known-answer tests is not a security audit of the implementation or compiler.

Use disposable credentials and non-sensitive data only. Revoke the token after the session. Do not embed credentials in source files, scripts or commits. The lab accepts runtime secrets through its `TOS_SECRET_` environment mechanism. Guest memory, host environment and lab artifacts are not a secret vault.

## Isolation

The lab runs QEMU inside a read-only rootless Podman container, with capabilities dropped, no privilege escalation, and KVM access. The source and ISO mounts are read-only; output is writable and should remain on RAM-backed storage. Rootless containers and virtual machines reduce exposure but are not a guarantee against escape.

Guest forwarding is restricted by default. `--net apify` allows raw TCP forwards to the public API; `--net open` enables general outbound guest networking. The container's own network remains available for relays. Plain HTTP mode is for the local mock only.
