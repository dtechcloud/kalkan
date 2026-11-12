---
name: memory-safety-and-binary
title: Memory safety, binaries, and kernel code
classes: memory-safety
when_to_use: The target handles untrusted bytes in memory-unsafe or privileged code: C, C++, Objective-C, Rust unsafe, FFI, kernel modules, parsers, daemons, loaders, runtimes, or JITs.
sources: third_party/security-audit-skill/skills/security-audit/MEMORY-SAFETY-AND-BINARY.md
---

# Memory safety, binaries, and kernel code

Split a large target by parser, allocator and lifetime, FFI, concurrency, loader, runtime, and privileged interface. Related pack: `protocols-rpc-and-messaging` (protocol authorization and state machines).

## Core discipline

- Derive every bound and lifetime again from the attacker-controlled inputs and from all callers. Check the worst accepted case, not a typical test vector.
- A panic, sanitizer report, or crash proves a defect only when a realistic untrusted input reaches it. Do not infer memory corruption, code execution, or a shared outage from a label alone.
- State the violated invariant and the observable effect. Never develop post-corruption techniques.
- Assembly, JIT code, custom allocators, accesses inside one object, and foreign libraries can escape sanitizer coverage. Name what the sanitizer instruments.
- Use `needs_validation` when ABI, allocator, architecture, build feature, deployment, or reachability facts stay unknown.

## Attack classes

### Out-of-bounds read or write

- **Check:** lengths, offsets, indexes, and terminators that reach a buffer without a correct bound. Recompute the free space after prefixes, alignment, padding, and terminators. Check the source and the destination capacity, and whether code reads a short input before it trusts the declared length.
- **Not a finding:** a copy bounded by the destination size after a validated length.

### Integer overflow, underflow, truncation, and signedness

- **Check:** attacker-controlled arithmetic before allocation, copy, loop, index, and pointer operations. Common shapes: `a - b` with `b > a`, `count * element_size`, additions near the type maximum, negative values converted to unsigned, 64-bit lengths narrowed to 32 bits, and a `-1` sentinel that becomes a huge size.
- **Not a finding:** values bounded by a small constant, or overflow-checked helpers whose result code checks.

### Unit and pointer-depth confusion

- **Check:** code that mixes bytes, elements, code units, pages, words, wire units, or nested pointer element sizes. Compare the unit at parse, validation, allocation, API boundary, and copy.
- **Not a finding:** one consistent unit at every step. A bounds check that uses the same wrong unit as the allocation is still wrong.

### Uninitialized or partially initialized data

- **Check:** buffers, padding, struct fields, or vector capacity that code returns, compares, hashes, serializes, or sends across a trust boundary before initialization. Name the consumer and a realistic output length.
- **Not a finding:** a stack allocation alone, or a struct that code zeroes before a partial fill.

### Use-after-free, stale view, and double free

- **Check:** owners released while callbacks, wait queues, timers, iterators, borrowed slices, or cached raw pointers can still use them. Review every error, cancel, close, and `realloc` path. Every free path must drain or detach all observers.
- **Not a finding:** a pointer set to null after free on the only path, when later paths check for null.

### Type confusion and invalid downcast

- **Check:** a tag, vtable, union discriminator, object kind, or foreign handle that code checks differently from the representation that it reads later. Look for unchecked dynamic casts, stale tags after reuse, and serialized types whose validated element differs from the consumed one.
- **Not a finding:** a downcast guarded by a check of the same discriminator on the same object.

### Reference-count, ownership, and shared-state races

- **Check:** non-atomic retain and release, a check followed by an unlocked use, and different ownership rules across threads. Check parser streams, global caches, lazy initialization, signal handlers, and teardown that invalidate bounds, policy, or pointers established earlier. Compare fast, error, shutdown, and compatibility paths.
- **Not a finding:** an interleaving without a security-relevant state change. Keep it `needs_validation` when only a deterministic schedule can decide it.

### Lock order, deadlock, and starvation

- **Check:** externally reachable operations that take locks in different orders or hold them across callbacks and blocking I/O.
- **Not a finding:** a deadlock that no bounded external input can trigger. Report a reachable one under `dos-redos`.

### Pointer-length and ownership contract mismatch

- **Check:** callers and callees that disagree on who allocates, frees, pins, or changes a buffer, how long a pointer stays valid, or whether a length counts bytes or elements. Trace both sides of every `extern` declaration, CGo, JNI, Python C extension, and generated wrapper. Check null, zero length, aliasing, and callback retention.
- **Not a finding:** a contract documented and honored on both sides.

### Layout, alignment, and enum disagreement

- **Check:** structs, bitfields, packed records, callback signatures, integer widths, enums, or calling conventions that differ by architecture or build flag across an FFI boundary. Check `repr`, packing, alignment, endianness, and ABI-specific types.
- **Not a finding:** a mismatch that only an opaque foreign implementation could show. Use `needs_validation` for it.

### Unwind, exception, and thread-affinity violations

- **Check:** exceptions or panics that cross an ABI that forbids unwinding, callbacks that run after teardown, and thread-bound APIs called from another thread.
- **Not a finding:** a clean abort with no shared impact.

### Library, plugin, and executable search-order trust

- **Check:** a privileged process that loads a library, plugin, runtime image, or helper from a path that a less trusted principal can write, or that resolves a bare name through an attacker-influenced working directory or environment variable.
- **Not a finding:** a user who loads a plugin into the user's own process.

### Missing artifact identity or signature binding

- **Check:** a loader that verifies one file or metadata record and then maps a different image, because path resolution, file replacement, architecture slices, or embedded resources are not bound to the check.
- **Not a finding:** a check and a map that use the same open descriptor.

### Malformed metadata, JIT consistency, and teardown

- **Check:** offsets, counts, sections, relocations, symbols, bytecode, or debug metadata trusted before range and overlap checks. Check validators, interpreters, optimizers, and generated code that disagree about types, bounds, or lifetime. Check function pointers, callbacks, and threads that survive a module unload or runtime reset.
- **Not a finding:** a malformed file that the parser rejects safely, or output variance within language semantics.

### User-copy bounds and repeated reads (kernel)

- **Check:** syscalls, ioctls, drivers, or kernel parsers that derive a trusted fact from user memory and then read the same mutable address again (double fetch). Check size, direction, and access checks at each user-copy primitive.
- **Not a finding:** a request copied once into kernel memory and used only from that copy.

### Privileged object lifecycle and dispatch consistency

- **Check:** externally reachable objects with unbalanced retain and release, teardown without observer drain, unchecked selector or table indexes, and duplicated compatibility paths that omit a guard. Compare each dispatch and free path side by side.
- **Not a finding:** an index bounded against the table size on every path.

### Under-authorized powerful interfaces

- **Check:** a device node, admin socket, helper, or management API that validates the request shape but not the caller's authority over the resource. Establish who can open the interface.
- **Not a finding:** a claim that depends on permissions or sandbox policy outside the repository. Use `needs_validation` for it.

## Universal moves

- Audit fixes and duplicated paths for the same source-to-sink shape. A check in one caller, architecture, protocol role, feature flag, or compatibility path does not protect its siblings.
- Build a table for every parser or FFI boundary: accepted length and type, checked representation, allocation owner, consumer, thread, and teardown. Most native findings are one disagreement in that table.
- Name the input property that triggers the effect. A PoC uses an existing corpus or a small generated fixture, a sanitizer build, and strict resource limits.

## Validation rules

1. Establish a realistic untrusted entry point and the exact operation that breaks a bounds, type, lifetime, ABI, concurrency, loader, or authority invariant.
2. Classify the effect: invalid read, invalid write, stale alias, wrong object, uninitialized output, unauthorized image load, deadlock, or safe termination. Do not claim a stronger effect than the evidence shows.
3. The narrowest local check is a harness, an existing test, a sanitizer build, or a fuzz target. Record the architecture, the build conditions, and the sanitizer coverage of the faulting operation.
4. For concurrency, describe a deterministic schedule or a sanitizer trace. For binary loading, prove that the checked identity differs from the mapped identity and name the lower-trust writer.
5. A confirmed claim needs the exact input shape and source trace. Otherwise report `needs_validation` with the unresolved reachability, ABI, build, deployment, or runtime fact.

## Sources

- `third_party/security-audit-skill/skills/security-audit/MEMORY-SAFETY-AND-BINARY.md`, from cloudflare/security-audit-skill at commit `c1c8a8c` (MIT License, Copyright (c) 2025-2026 Cloudflare, Inc.).
- kalkan condensed and rewrote the text, adapted it to the kalkan verdict model, and removed the agent-orchestration instructions.
