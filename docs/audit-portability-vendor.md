# Vendor portability review

Status: IN PROGRESS, reconciled with the current source on 2026-11-06.
The earlier findings in this document described an older source revision.
The current implementation and remaining acceptance requirements are below;
this record does not certify the complete vendor implementation.

## Current source reconciliation

| Area | Current implementation | Remaining proof |
| --- | --- | --- |
| sntrup761 generic helper symbols | `kex/sntrup761_optblocker.c` defines all three zero-initialized volatile objects, and `CMakeLists.txt` includes it in the library sources. The former missing-definition item is resolved in source. | Exercise the generic helpers and their arithmetic/width assumptions independently of the native assembly paths. Linking the object on x86_64 does not exercise those paths. |
| sntrup761 unused annotations | `CRYPTOINT_MAYBE_UNUSED` selects the GNU/Clang attribute, the MSVC warning pragma or an empty fallback. | Native Windows and other compiler acceptance retain their own scope; compiler recognition does not establish constant-time behavior. |
| libcrux population count | The current glue selects MSVC, GNU-compatible or portable C code. The portable branch counts the bits in a `uint8_t` using bounded masks and shifts. The former absent-fallback item is resolved in source. | Exercise compiler branches, including the portable implementation; inspect generated code for the supported compiler/target combinations. |
| libcrux inclusion | A conventional `LIBCRUX_MLKEM768_SHA3_H` outer guard replaces the former pragma. | Complete the generated header and upstream/local-delta review. |
| ML-KEM byte encoding | `core_num__u64_9__to_le_bytes`, `core_num__u64_9__from_le_bytes` and `core_num__u32_8__from_le_bytes` explicitly assemble or emit octets. `mlkem768.c` no longer selects byte order through compiler macros. | Finish all other arithmetic, object-layout and width assumptions. Current-host vectors alone do not establish other-target execution. |

## Generated ML-KEM header reading boundary

`kex/libcrux_mlkem768_sha3.h` contains 11,651 lines. The contiguous reading
boundary is now line 1,172, covering the license/provenance, slice glue,
byte conversions, fixed-size wrapper types, padding helpers, comparison and
selection helpers, initial Keccak operations/state initialization and the
72-byte block loader. A separate reading of the ML-KEM decapsulation block at
lines 10,343–10,447 checks the ciphertext/secret slices passed to those helpers.
The intervening generated code has not thereby been read.

The byte-conversion shifts are bounded by the eight/four-byte loops and use
unsigned widened operands. The wrapping helpers intentionally convert to the
destination unsigned width. The nonzero helper operates on an octet, and the
selection mask chooses 32 bytes without a source-level secret-dependent branch.
This is a source observation, not a generated-code timing result.

The generated slice macros do not validate lengths. Establish their bounds
from every reachable caller, including multiplication/addition, array conversion,
padding, equal-length comparison and split operations. The inspected ML-KEM
decapsulation splits the fixed 2,400-byte secret into 1,152/1,184/32/32-byte
regions; its comparison receives two 1,088-byte ciphertext slices and its
selection receives two 32-byte secret slices. Other caller chains remain open.
The block loader's nine octet groups fit its 72-byte input and 5-by-5 state,
subject to proving the callers supply that full block.

## Remaining cross-file acceptance

Finish the whole generated header, arithmetic and reduction bounds, shift and
signed-conversion assumptions, 16-bit integer/size behavior, stack use, secret
intermediate lifetime, generic-path behavior, upstream correspondence and
independent positive/negative vectors. Check the wrappers and both providers
against the exact protocol and validation contracts. Preserve the distinction
between source inspection, native execution and other-platform evidence.

Existing historical conversion/parity test results remain recorded in
`release-1.0-audit.md`; no new test execution is claimed by this documentation
reconciliation. Native Windows testing remains the final CI stage after the
local audit and validation requirements are complete.
