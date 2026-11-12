---
slug: memory-safety
title_en: Memory safety
title_tr: Bellek güvenliği (memory safety)
cwe: CWE-787, CWE-416, CWE-119, CWE-120, CWE-121, CWE-122, CWE-125, CWE-129, CWE-131, CWE-134, CWE-190, CWE-191, CWE-415, CWE-476, CWE-681, CWE-843
owasp:
sources: security-audit-skill, codecrucible, open-code-review
---

## Summary

Untrusted bytes reach memory-unsafe code and break a bound, lifetime, type or initialization rule. The code is C, C++, Rust `unsafe`, a foreign function interface (FFI), a kernel module or a native parser. Report the sink line, the attacker input, the resolved numbers and the primitive that you can show. Never claim code execution from a crash alone.

## What it is

- **Out-of-bounds write or read (CWE-787, CWE-125, CWE-120).** A length, offset or index from input reaches a copy, loop or array access without a correct bound. Off-by-one loops (`i <= len`) and parsers that read a field before they check the remaining length are common.
- **Integer errors (CWE-190, CWE-191, CWE-681).** Size math wraps before an allocation (`count * size`, `len + 1`). `total - used` underflows. A negative `int` becomes a huge `size_t`. A 64-bit length is cut to 32 bits.
- **Unit confusion (CWE-131).** The check, the allocation and the copy use different units: bytes, elements, characters or pages.
- **Lifetime errors (CWE-416, CWE-415).** A pointer, iterator, borrowed slice or callback outlives its object. Error paths free twice. `p = realloc(p, n)` loses the old pointer on failure.
- **Type confusion (CWE-843).** Code reads a union member or downcasts an object without a check of the tag.
- **Uninitialized memory.** A struct with padding or unfilled fields leaves the process or the kernel and leaks stack or heap data.
- **Format strings and NULL (CWE-134, CWE-476).** `printf(user)` uses input as the format. An unchecked allocation or lookup result on an input path gives a crash.
- **Kernel boundaries.** A double fetch from user memory, `copy_to_user` of an uninitialized struct, a missing reference count, a free while a timer, work item or RCU reader still holds the pointer.
- **Rust `unsafe` and FFI.** `from_raw_parts` with an unchecked length, `get_unchecked`, `assume_init` on partial data, `transmute`, a false `unsafe impl Send/Sync`, a panic across `extern "C"`. Caller and callee disagree about length units, ownership, lifetime or layout.

## What it is not

- A panic, exception or `unwrap` failure in a memory-safe language → `dos-redos` when input reaches it, else `code-quality`. A C or C++ NULL dereference stays here.
- A data race without memory corruption, including a Go `concurrent map writes` crash → `race-condition`.
- A leak that an attacker repeats until memory runs out → `dos-redos`. A leak without an attacker trigger → `code-quality`.
- `system()` or `popen()` with input → `os-command-injection`. A symlink race on a path → `path-traversal` or `race-condition`.
- Overflow in money or quantity values in a memory-safe language → `business-logic`. In Solidity or Vyper → `smart-contract`.
- `rand()` for tokens → `crypto`. Object deserialization (pickle, Java serialization) → `deserialization`.
- A privileged process that loads a library from a path that a lower-trust user can write → `mobile-desktop-ipc`. Unsigned updates or plugins → `supply-chain-cicd`.

## Where to look

Build a table for each parser or FFI boundary: accepted length and type, checked value, allocation size and owner, consumer, thread and teardown. Most native bugs are one mismatch in that table.

### C and C++
- Copy sinks: `memcpy`, `memmove`, `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`, `read()` into fixed buffers. `strncpy` adds no NUL on truncation. A `snprintf` return value can exceed the buffer size.
- Parsers: TLV and option loops, length-prefixed messages, image size math (width, height, depth), archive entries, packet headers.
- Allocation math before `malloc`, `realloc` and `new[]`. Every `goto` cleanup label and error path.
- C++ lifetimes: iterators after `erase` or `push_back`, references into a vector that grows, `c_str()` or `string_view` of a temporary, lambdas that capture by reference and run later.
- Setuid binaries and daemons: environment, `argv`, inherited file descriptors, IPC message lengths.

### Linux kernel and drivers
- `copy_from_user`, `get_user`, ioctl argument structs, sockopt values, netlink messages, `skb` length checks.
- Stack structs copied out with `copy_to_user`. They need `kzalloc` or zeroing first.
- Every `*_get` and `*_put` pair on every return path. `del_timer_sync`, `cancel_work_sync` and `synchronize_rcu` before a free.

### Rust
- Every `unsafe` block and `unsafe fn`: which invariant it assumes, and whether every caller keeps it. A missing `# Safety` comment is a hint, not a finding.
- `slice::from_raw_parts(_mut)`, `ptr::copy_nonoverlapping`, `get_unchecked(_mut)`, `MaybeUninit::assume_init`, `mem::transmute`, `static mut`, `Box::from_raw`.
- `extern "C"` functions: lengths and pointers from C, panics that cross the boundary.
- `as` casts in length math. Release builds wrap on overflow unless `overflow-checks` is on. `rkyv` access to untrusted bytes without validation.

### Go, Python, Java and Node.js native code
- Go: `unsafe.Pointer`, `unsafe.Slice`, `C.GoBytes(ptr, n)` with an untrusted `n`, C buffers freed while Go code still holds them.
- `ctypes` and `cffi` calls with lengths from input, JNI array regions with untrusted offsets, Node-API buffers in native addons.

## Safe patterns

- Check the length against the destination size at the copy site, with the resolved number. Compute the remaining length as `end - cur`.
- Use overflow-safe size math: `calloc`, `reallocarray`, `__builtin_mul_overflow`, kernel `array_size` and `check_mul_overflow`, Rust `checked_*` and `try_into()`.
- Copy a user-space struct once, then use only the kernel copy.
- Free each allocation on exactly one path, then set the pointer to NULL. Cancel timers, callbacks and readers before the free. In C++, use RAII and `std::unique_ptr`.
- Zero a struct before a partial fill when it leaves the process. Use literal format strings.
- In Rust, keep `unsafe` small, write the `# Safety` contract, check lengths from FFI, and wrap exported functions in `catch_unwind`.

## Weak mitigations

- `strncpy` without a manual NUL. `strlcpy` truncation that changes the meaning.
- A bound check on another variable, in another caller or feature path, before a second fetch, or in the same wrong unit as the allocation.
- `assert()` with `NDEBUG`, Rust `debug_assert!`, overflow checks in debug builds only.
- A signed length checked with `len < MAX` but not with `len >= 0`.
- Stack canaries, ASLR, `_FORTIFY_SOURCE` and CFI. They make exploitation harder, but they do not fix the bug.

## Verification checklist

- **attacker_control:** Name the untrusted entry: file, packet, IPC message, syscall argument, `argv` or environment of a setuid binary, FFI caller. Quote the line that reads the length, index or pointer, and the sink line.
- **privilege_boundary:** Name the boundary: remote client to daemon, local user to kernel or root process, untrusted document to the user's process. A tool that handles only its own trusted input refutes it.
- **unmitigated:** Quote the missing or wrong bound. Resolve named constants to numbers and do the arithmetic: largest accepted input against buffer size. A check on another variable, before a second fetch, or in another caller does not refute.
- Name the primitive that you can show (info leak, out-of-bounds read or write, use after free, double free, NULL dereference) and the build conditions it needs. Do not claim more.
- For Rust, show that safe code reaches the `unsafe` block with a value that breaks its invariant.
- If ABI, allocator, architecture or reachability facts stay unknown, the result is `needs_validation`.

## Examples

### C and C++
```c
/* Vulnerable: len comes from the packet, name has 64 bytes */
uint16_t len = read_u16(pkt);
char name[64];
memcpy(name, pkt + 2, len);

/* Secure: check the packet and the destination, then terminate */
if (pkt_len < 2 || len > pkt_len - 2 || len >= sizeof(name)) return -1;
memcpy(name, pkt + 2, len);
name[len] = '\0';
```

```c
/* Vulnerable: n * sizeof *v wraps when size_t has 32 bits */
uint32_t n = read_u32(hdr);
struct item *v = malloc(n * sizeof *v);

/* Secure: cap the count, and calloc checks the product */
if (n > MAX_ITEMS) return -1;
struct item *v = calloc(n, sizeof *v);
```

### Linux kernel and drivers
```c
/* Vulnerable: the length is fetched twice from user memory */
if (get_user(len, &uarg->len) || len > sizeof(kbuf)) return -EINVAL;
if (copy_from_user(&req, uarg, sizeof(req))) return -EFAULT;
if (copy_from_user(kbuf, u64_to_user_ptr(req.data), req.len)) return -EFAULT;

/* Secure: copy once, then check the copy */
if (copy_from_user(&req, uarg, sizeof(req))) return -EFAULT;
if (req.len > sizeof(kbuf)) return -EINVAL;
if (copy_from_user(kbuf, u64_to_user_ptr(req.data), req.len)) return -EFAULT;
```

### Rust
```rust
// Vulnerable: off and len come from the input, and nothing checks them
pub fn field(buf: &[u8], off: usize, len: usize) -> &[u8] {
    unsafe { std::slice::from_raw_parts(buf.as_ptr().add(off), len) }
}

// Secure: checked math and a checked slice
pub fn field(buf: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    buf.get(off..off.checked_add(len)?)
}
```

## Dynamic test hints

- Build the target or a small harness with AddressSanitizer and UndefinedBehaviorSanitizer (`-fsanitize=address,undefined -g -O1`). Use MemorySanitizer for uninitialized reads, ThreadSanitizer for races.
- Rust: run `cargo miri test` on the `unsafe` code with the trigger input, or `cargo fuzz` with an existing target. Kernel code: use KASAN or KMSAN only in a local VM.
- Feed the minimal trigger: the exact bytes of a file, packet or message. Add boundary cases: size, size + 1, 0 and the type maximum.
- Reuse existing fuzz targets and corpora. Save the sanitizer report.
- Stop at the sanitizer report. Do not build an exploit, a ROP chain or heap grooming.
- Without a compiler in the sandbox image, keep the finding `needs_validation` and write down the harness and the command.

## False positive traps

- A bound exists once you resolve the constant: the input is capped at 256 bytes before a copy into `buf[PATH_MAX]`.
- The destination was allocated from the same checked length.
- The value comes from a constant, an internal enum, or configuration that only root writes.
- The code is compiled out on supported platforms, or it is test, benchmark or fuzz-harness code.
- The kernel path needs root or `CAP_SYS_ADMIN` and gives no further privilege.
- The Rust invariant follows from the types, for example a length taken from `buf.len()`.
- The type sizes make the overflow impossible: a sum of two `u16` values in a 64-bit `usize`.
- A pointer set to NULL after the free cannot be freed twice. A leak at program exit is harmless.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/MEMORY-SAFETY-AND-BINARY.md` (MIT, Cloudflare): bounds, integer, lifetime, FFI and kernel classes, validation rules.
- `block/codecrucible@b5c8086: prompts/exploit-proof-c-userland/`, `exploit-proof-c-kernel/`, `exploit-proof-rust/`, `core/audit_families.yaml` (Apache-2.0, Block): per-CWE checks, false positive indicators, the memory family rules.
- `block/codecrucible@b5c8086: prompts/nano-analyzer/` (Apache-2.0, Block, adapted from weareaisle/nano-analyzer, Apache-2.0, AISLE): five questions, resolved constants.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/c.md`, `cpp.md`, `rust.md` (Apache-2.0, alibaba/open-code-review contributors): unsafe and FFI boundaries, allocation pairing.
- Sanitizer flags, Miri and KASAN usage come from general knowledge.
