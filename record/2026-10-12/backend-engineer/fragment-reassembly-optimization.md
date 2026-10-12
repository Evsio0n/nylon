# Change Record: per-hop fragmentation and reassembly optimization

## Request Summary
Publish the previously deployed opt-in per-hop fragmentation support and the profiled reassembly optimization through the nightly APT build, while preserving runtime routing configuration.

## Agent Role
Backend Engineer

## Scope And Intent
Port the deployment-tested fragmentation implementation to the current fork main without replacing unrelated upstream changes. The wire version, fragment headers, per-peer opt-in allowlist, and default disabled behavior are unchanged. No profiling listener is included in this commit.

## Files Changed
- core/nylon_fragment.go, core/nylon.go, core/nylon_tc.go
- polyamide/device/traffic_control.go
- configuration validation, examples, reference documentation
- fragment correctness, race, batch-ownership and multi-hop integration tests

## Behavior Changed
- Use the existing periodic expiry task, plus an O(1) target-entry expiry check, instead of a full-map scan for every fragment.
- Use exact byte-coverage bitsets with popcount, preserving overlapping/duplicate fragment semantics.
- Transfer completed buffer ownership instead of cloning it.
- Reuse the final fragment's element and receive batch with bounded in-place TC reprocessing; eliminate recursive per-packet TCState allocation and individual TUN writes.
- Validate truncated inner headers and bound repeated decapsulation.

## Verification Performed
Go 1.25.4:
- go test ./core ./state ./polyamide/device -count=1: passed.
- go test -race ./core ./polyamide/device -run 'TestFragment|TestTCReprocess' -count=1: passed.
- go test -tags integration ./integration -run TestPerHopFragmentation -count=3 -timeout=90s: passed.
- Exhaustive bit-boundary/overlap and concurrent expiry tests: passed on old and new implementations.
- Synthetic 1024-pending reassembly benchmark: 22435 ns/op to 638.5 ns/op (not a whole-link throughput claim).
- Matched live baseline/candidate matrices: 32 tests each. Memory allocation estimates in matched profiling windows fell about 73%; download throughput remained variable.
- Source archive reproduces the tested static amd64 executable byte-for-byte with -trimpath -buildvcs=false -ldflags='-s -w'.

## API, Data, Deployment, And Rollback Notes
The added TC action is internal, not a wire protocol change. Existing non-fragmenting peers remain supported; enable fragmentation only for upgraded peers. Retain the original executable before activation. Restart deployment tooling must restore previously active dependent services after restarting the daemon.

## Risks And Follow-Up
Global reassembly locking and the 30-second expiry policy remain. There is no new capacity limit for partial assemblies. The improvement does not establish a zero-loss network or fix external link loss. Browser verification is not relevant to this dataplane change.

## Timestamp And Project Path
2026-10-12T12:58:54+08:00
Repository: Evsio0n/nylon
