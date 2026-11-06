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

## Generated ML-KEM source review

The implementation in all 11,651 lines of `kex/libcrux_mlkem768_sha3.h`
has now been read. Generated block annotations were omitted from the code view
with source line numbers preserved; substantive descriptions/preconditions were
then read separately, and repetitive Rust implementation/type annotations were
indexed. The 256-row rejection table is checked in full against an independent
mask-to-byte-index construction. Reading completion does not close the remaining
correctness, portability, cleanup, provenance or execution requirements.

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
The SHA3-512/256 block loaders use72/136-byte rates; final absorption derives
its remainder with the same modulus, below the rate. SHAKE256 uses136 bytes
and delimiter31, while SHA3 uses delimiter6. The reachable incremental SHAKE128
path absorbs fixed34-byte matrix seeds, initially emits504 bytes and later168
bytes. All rate blocks fit the 5-by-5 state and use explicit little-endian
conversion. NTT table indices/loop scheduling, arithmetic intermediate bounds
and all secret cleanup remain separate obligations.

The compiler's macro-expanded AST of the production `mlkem768.c` translation
unit indexes502 function definitions, with345 reached from the three private
wrappers and no reached indirect calls. External calls are `dssh_random`,
`dssh_cleanse`, `memcpy`, `memcmp` and `abort`. The reached `memcmp` occurs in
public-key canonical validation; `abort` occurs in three unwrap helpers whose
conversion glue unconditionally assigns the success tag. The generic buffered
XOF routines, NEON stubs, private-key-validation helper and11-bit ring serializer
are outside that native wrapper call closure. These are scoped native compiler
observations, not other-platform or argument-invariant proofs. The compact
compiler index and command/diagnostics remain in build-audit-logs.

## Direct glue corrections and acceptance

The private range helper now follows unsigned half-open range semantics even
when start exceeds end. The private11-bit polynomial serializer uses its full
352-byte result extent. Neither changes an installed declaration, export or
supported algorithm. `test/test_vendor_glue.c` checks empty/reversed/maximum
ranges;3329 full256-coefficient encodings against scalar rounding/bit packing,
including outer guards; all256 shuffle rows; and all128 NTT constants against
modular exponentiation and seven-bit reversal.

The standalone target deliberately has no provider/library dependency. Nine
sequential configure/build/test stages pass, one selected CTest each on the
ASan/UBSan, Botan-build and TSAN configurations, with one build/test job on
CPUs0–7. ASan leak detection is disabled because this native runtime does not
support it; the initial unsupported-setting failure is retained separately.
No sanitizer diagnostics or skipped cases occur in the accepted executions.
The [hash-bound validation record](release-1.0-evidence/vendor-glue-validation.json)
binds exact sources, executables, commands and logs. These checks establish the
reported glue/model scope, not production provider/module/peer acceptance.

## Remaining cross-file acceptance

Finish arithmetic and reduction bounds, shift and
signed-conversion assumptions, 16-bit integer/size behavior, stack use, secret
intermediate lifetime, generic-path behavior, upstream correspondence and
independent positive/negative vectors. Check the wrappers and both providers
against the exact protocol and validation contracts. Preserve the distinction
between source inspection, native execution and other-platform evidence.

Existing historical conversion/parity test results remain recorded in
`release-1.0-audit.md` with their original source/provider scope.
Native Windows testing remains the final CI stage after the
local audit and validation requirements are complete.
