# Validation status

## README replication checks

The README container image built successfully. A fresh download from its TempleOS URL matched the documented SHA-256. Tests ran from fresh local clones with the pending changes applied, inside stock TempleOS VMs. The shell launchers ran inside a separate container controlling rootless Podman; that test harness omitted `--group-add keep-groups`, which Podman's remote client does not support. The shipped launcher retains it for local Podman.

The TLS mock passed 12 checks, the HolyApify frontend passed 3, and the new runnable Actor example passed 2 using a runtime mock token. The client suite passed 23 plain-mock checks, 3 frontend checks and 4 real-API checks with an invalid token. The real API returned HTTP 401 for both account lookup and Actor submission.

The same runnable example also passed both checks with a real token supplied at runtime: authenticated account lookup followed by a one-page `apify/website-content-crawler` run against `https://example.com`. The dataset contained one item with title `Example Domain`. HTTPS, token authentication and the Actor request ran in HolyC inside the guest; the host relay copied TCP bytes. No token, account identifier, real-run screenshot or raw log was added to the repository.

All 14 HolyNet test entries passed. Three entries initially failed during parallel container creation with a runtime UID-mapping error, before any guest code ran; each passed when retried serially. The remaining entries passed in the parallel run.

Actor calls now raise the socket read timeout from 60 to 310 seconds. A regression uses a 100 ms transport timeout and a mock response delayed by 500 ms: it passes with the fix and fails without it.

Gitleaks 8.30.1 found no secrets in either repository's reachable committed history or working tree. A separate content scan found no owner names, personal paths or private infrastructure details; the README repository URLs intentionally contain the account handle. Logo PNGs contain no text or EXIF metadata. Git author/committer identity was inspected and deliberately retained at the owner's request.

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
