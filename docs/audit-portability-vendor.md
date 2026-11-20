# Bundled cryptography and portability review

The v1.0 production review includes the bundled sntrup761 and ML-KEM-768
implementations, their callers, both provider integrations and failure cleanup.
This replaces the earlier progress log, whose open items predated the later
source corrections. The corrections and their regressions remain in Git
history; current production and test sources are linked below.

## sntrup761

[sntrup761.c](../kex/sntrup761.c) identifies its OpenSSH/SUPERCOP origin and
public-domain authorship. Local adaptations use the selected backend's random
and hash APIs with checked error propagation. Signed reconstruction and floor
shifts use bounded arithmetic rather than out-of-range signed conversions;
packing, division, sampler and field intermediates were reviewed with their
callers. The forced-generic path uses the separately linked
[optblocker objects](../kex/sntrup761_optblocker.c).

[Native/generic arithmetic tests](../test/test_sntrup_arithmetic.c) compile the
canonical source and compare reviewed domains with independent arithmetic
models. [Known-answer tests](../test/sntrup_kat_cases.h) retain published
response, seeded-generation and independently derived rejection controls in
[test/vectors](../test/vectors). Scratch retirement and failure behavior are
checked in [test_sntrup.c](../test/test_sntrup.c).

Relevant corrections include `b477786` (integer operations), `df88084`
(scratch retirement), `83d2a3e` (in-place sample decoding), `efb6997`
(official responses), `4119658` (seeded generation) and `1522a26`
(rejection answers).

## ML-KEM-768 and SHA-3/SHAKE

[mlkem768.c](../kex/mlkem768.c) wraps the bundled
[libcrux implementation](../kex/libcrux_mlkem768_sha3.h). Both provider builds
use that reviewed implementation; their adapters supply randomness, X25519 and
transcript hashing. The generated implementation is included in the source
review: reachable slice/array extents, encoding, NTT and polynomial arithmetic,
selection, hash scheduling, caller-owned outputs and secret scratch retirement.
The former vendor-code exemption in the early module audit does not apply.

| Area | Retained regression coverage |
| --- | --- |
| Defined signed operations, reductions, constants, shuffle tables and encodings | [test_vendor_glue.c](../test/test_vendor_glue.c), [test_mlkem_poly.c](../test/test_mlkem_poly.c), [test_mlkem_encoding.c](../test/test_mlkem_encoding.c) |
| Key generation, encapsulation, decapsulation and invalid-input answers | [test_mlkem_acvp.c](../test/test_mlkem_acvp.c), [pinned ACVP provenance](../test/data/mlkem_acvp_sources.json) |
| SHA3/SHAKE answers and scratch handling | [test_mlkem_hash.c](../test/test_mlkem_hash.c), [pinned vector provenance](../test/data/mlkem_hash_sources.json) |
| Wrapper output bounds, failure handling and retirement | [test_mlkem_wrapper.c](../test/test_mlkem_wrapper.c) |
| Fixed-path selection behavior | [test_mlkem_selection.c](../test/test_mlkem_selection.c) |

Relevant corrections include `52ea27f` (signed reductions), `9b4339c`
(CCA scratch), `b68dea6` (hash storage), `4b9de7b` (CPA scratch), `cf2ec8a`
(polynomial scratch), `6b989c7` (NTT scratch), `0cf76f2` (encoding scratch),
`4a227f6` (caller storage), `dad378c` (shared implementation), `1129c2a`
(FIPS 203 notes) and `43d32a8` (optimized selection operations).

## Protocol and provider boundaries

The [hybrid protocol handler](../kex/hybrid-pq-kex.c) and
[ML-KEM handler](../kex/mlkem768x25519-sha256.c) bind the KEM outputs to the SSH
transcript and X25519 exchange. The registered modules retain independent key
and signature verification. [Hybrid storage tests](../test/test_hybrid_storage.c),
[transport tests](../test/test_transport.c) and the optional
[OpenSSH interoperability tests](../test/openssh_interop.py) exercise those
boundaries with the production libraries. Primitive vectors alone do not prove
the SSH integration.

The current native suites are defined in [CMake](../test/CMakeLists.txt) and
run on Linux with both providers, macOS with OpenSSL and Windows with OpenSSL
in [CI](../.github/workflows/ci.yml). Source-level width and byte-order review
is distinct from execution on those native targets. Arithmetic models do not
claim actual execution on every integer width or processor, and source or
selected assembly inspection does not establish constant-time behavior for
every compiler configuration. Native provider internals also retain their own
allocation, cleanup and compatibility contracts.

These are the scope limits of the evidence, rather than a requirement to prove
every compiler, dependency and operating system before release. New source,
provider or platform changes require validation relevant to those changes.
