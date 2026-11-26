# 5GNexusGuard — BPF Reconstruction Checkpoint
**Date:** 2026-11-25  
**Branch:** `feature/bpf-reconstruction-v2`  
**Latest Commit:** `c2eb837`

## Current State
- ✅ 3 BPF TC programs compiled: `health_control`, `wg_ingress`, `resource_ingress`
- ✅ 4 BPF maps defined: `auth_map`, `renewal_state`, `resource_map`, `health_state`
- ✅ All 17 tests pass (9 original + 8 struct alignment tests)
- ✅ BPF loads into kernel (Docker `--privileged`, Ubuntu 24.04)
- ✅ TC attachment works — all 3 programs attached as jited direct-action filters
- ✅ Dynamic peer_key derivation from source IP in all classifiers
- ✅ 2 local commits ready

## Compiled Environment
- **BPF Compile:** `clang-18 -target bpf -c -g -O2 -Wall -I/usr/include/aarch64-linux-gnu`
- **Loader Compile:** `gcc -I/usr/include/bpf -lbpf -lelf -lz` (host libbpf 1.3+)
- **Test Container:** `ubuntu:24.04` with libbpf 1.3.0, TC API `bpf_tc_hook_create/attach`
- **Host:** Polaris — `kernel.unprivileged_bpf_disabled=2` (requires `--privileged` Docker)

## Loader (loader_v2.c)
- Uses host libbpf 1.3 headers (`/usr/include/bpf/libbpf.h`)
- Explicit `bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS)` for `tc/*` sections
- Sets `hook.sz = sizeof(hook)` and `opts.sz = sizeof(opts)` (required by libbpf 1.3)
- Uses `bpf_tc_hook_create` + `bpf_tc_attach` (single shared hook, all 3 programs share ingress)

## Remaining Work
- [x] Push commits to GitHub remote `feature/bpf-reconstruction-v2` — done (c2eb837)
- [ ] Test attachment on non-loopback interface (e.g., docker0, eth0) in privileged Docker
- [ ] Add integration test with packet injection (scapy) to verify program logic
- [ ] Verify BPF verifier passes with `bpftool prog dump xlated` or `verifier` log

## Key Files
- `scripts/ipsec-dual/kernel_gate_v2.bpf.c` — BPF programs (TC classifiers + maps)
- `scripts/ipsec-dual/loader_v2.c` — libbpf 1.3 TC attachment loader
- `scripts/ipsec-dual/test_bpf_struct_alignment.py` — struct/alignment tests
- `scripts/ipsec-dual/kernel_gate_publisher_v2.py` — publisher reference (struct definitions)
- `BPF_RECONSTRUCTION_CHECKPOINT.md` — this file

## Known Issues
- `build_peer_key` function defined but unused (unused only, still compiled)
- `__force` macro produces warnings on clang 18 (non-fatal, accepted)