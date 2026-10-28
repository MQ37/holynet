# HolyNet scope

A HolyC networking library for stock TempleOS V5.03, targeting QEMU's virtual AMD PCnet adapter.

The library owns Ethernet/IPv4/TCP/UDP, DHCP/DNS/ICMP, cryptography, TLS 1.3, HTTP/1.1 and JSON. The Apify adapter is a separate application in sibling holyapify.

The lab runs QEMU only inside rootless Podman, stages source over serial into B:/src/ and runs tests in fresh live-CD guests. Optional application trees are read-only mounts staged alongside the library; guest-path collisions fail. VM artifacts live in RAM.

TLS is experimental and does not verify server certificates or CertificateVerify. No claim of production security is made. Existing third-party terms remain; no license is granted for original project code.
