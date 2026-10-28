# Validation status

## Repository split: current checks

All execution below took place in rootless Podman. HolyC checks ran in fresh stock TempleOS V5.03 VMs inside the container. The official ISO was downloaded in a container to RAM and matched the README's expected SHA-256.

| Check | Result |
|---|---|
| HolyNet TLS mock | 12 checks, TOS-DONE fail=0 |
| TLS handshake negative cases | 17 checks, TOS-DONE fail=0 |
| HolyApify plain API mock using the separate dependency | 22 checks, TOS-DONE fail=0 |
| HolyApify frontend using the separate dependency | 3 checks, TOS-DONE fail=0 |
| Frontend with deliberately unavailable TLS fixture | 3 failed checks and exit 1, as expected |
| Shared runner with a stub failing entry | Old runner exited 0; fixed runner exits 1 |
| Shared runner with all stub entries passing after a failure | Exit 0; stale failure markers cleared |
| Both container-control wrappers | Entry/mode arguments and readonly application mount verified with a stub |
| Shell and Python syntax | Passed |
| Repository content and preview | Local Markdown links, owner-name scan, absence of project license, embedded image and dedication checked |

The full VM suite has not been repeated after the split. The checks above exercise the modified staging path, the new full-library loader, and client integration. No authenticated production Actor run was made.

## Previous implementation session

The original combined project reported all 17 entries passing, including crypto vectors, HTTP/JSON, TLS, TCP/DNS and unauthenticated real-API requests. That is recorded session history, not a new full-suite result.

Real API tests returned expected HTTP 401 responses. A successful authenticated Actor run remains unverified. Some RFC vector values were transcribed through a summarizing fetch tool and have not all been checked byte-for-byte against the original publications. The TLS review was a source review, not an independent cryptographic audit.
