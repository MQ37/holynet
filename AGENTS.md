# HolyNet

Read README.md, SPEC.md and docs/ARCHITECTURE.md before changing code.

- All project execution, builds, rendering and tests run inside rootless Podman or a VM. Never execute QEMU, HolyC, test scripts, Python or downloaded code directly on the host. Host launchers only orchestrate containers.
- Scratch and VM artifacts are RAM-only. Use a separate TOS_OUT under /dev/shm for each run. Do not install host packages.
- This is the network library and shared lab. The Apify client lives in sibling holyapify; application overlays use TOS_APP_DIR. Guest includes are B:/src/... and tests are B:/tests/....
- Preserve the third-party notices and Shrine's existing Unlicense. No license is granted for original project code. Do not add a project license or the owner's name.
- No secrets, personal paths, private hosts or credentials in the public tree. Pass disposable credentials at runtime through TOS_SECRET_ globals. The TLS implementation does not authenticate servers.
- Two-space HolyC indentation. Prefer short functions and module-prefixed public names. No debug prints in library code.
- Tests print TOS-DONE fail=N over serial using tests/Test.HC. Run through the containerized lab; a feature is not verified until its VM test passes.
- The public logo belongs under assets/. Do not ignore it with the artifact rules.
- Branch: master. No push or publication without explicit authorization. The lead handles commits; do not change git identity or add attribution.
