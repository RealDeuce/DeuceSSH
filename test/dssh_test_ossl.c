/*
 * dssh_test_ossl.c -- OpenSSL + C11 threads failure injection.
 *
 * Countdown-based wrappers: each failable call decrements a shared
 * atomic counter.  When it reaches zero, the wrapper returns the
 * appropriate failure value without calling the real function.
 *
 * Under DSSH_TESTING, macros in ssh-internal.h redirect library
 * calls to these wrappers.  OpenSSL's own internal calls are
 * unaffected because OpenSSL doesn't include ssh-internal.h.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <threads.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef DSSH_CRYPTO_OPENSSL
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#endif

#include "dssh_test_ossl.h"

static _Thread_local int clock_fail_at = -1;
static _Thread_local int clock_call_num;
static _Thread_local bool clock_fixed;
static _Thread_local struct timespec clock_value;
static _Thread_local struct timespec clock_next;
static _Thread_local unsigned clock_remaining;
static _Thread_local bool clock_scheduled;
static _Atomic(cnd_t *) watched_condition;
static atomic_bool condition_wait_entered;
static _Atomic(mtx_t *) paused_mutex;
static _Thread_local mtx_t *delayed_mutex;
static _Thread_local unsigned delayed_mutex_skip;
static atomic_bool mutex_pause_entered;
static atomic_bool mutex_pause_released;
static _Thread_local struct dssh_test_wait_probe *wait_probe;
static _Thread_local mtx_t *ownership_mutex;
static _Thread_local bool ownership_held;

void
dssh_test_mtx_watch_ownership(mtx_t *mutex)
{
	ownership_mutex = mutex;
	ownership_held = false;
}

bool
dssh_test_mtx_ownership(void)
{
	return ownership_held;
}

void
dssh_test_wait_probe(struct dssh_test_wait_probe *probe)
{
	wait_probe = probe;
}

atomic_bool *
dssh_test_thrd_pause_mutex(mtx_t *mutex)
{
	atomic_store(&mutex_pause_entered, false);
	atomic_store(&mutex_pause_released, false);
	atomic_store(&paused_mutex, mutex);
	return &mutex_pause_entered;
}

atomic_bool *
dssh_test_thrd_pause_mutex_after(mtx_t *mutex, unsigned skip)
{
	delayed_mutex = mutex;
	delayed_mutex_skip = skip;
	atomic_store(&mutex_pause_entered, false);
	atomic_store(&mutex_pause_released, false);
	return &mutex_pause_entered;
}

void
dssh_test_thrd_resume_mutex(void)
{
	atomic_store(&mutex_pause_released, true);
}

atomic_bool *
dssh_test_thrd_watch_condition(cnd_t *condition)
{
	atomic_store(&condition_wait_entered, false);
	atomic_store(&watched_condition, condition);
	return &condition_wait_entered;
}

static void
observe_condition(cnd_t *condition)
{
	if (condition == atomic_load(&watched_condition))
		atomic_store(&condition_wait_entered, true);
}

void
dssh_test_clock_reset(void)
{
	clock_fail_at = -1;
	clock_call_num = 0;
	clock_fixed = false;
	clock_scheduled = false;
}

void
dssh_test_clock_fail_after(int n)
{
	clock_fail_at = n;
	clock_call_num = 0;
}

void
dssh_test_clock_set(struct timespec value)
{
	clock_value = value;
	clock_fixed = true;
	clock_scheduled = false;
}

void
dssh_test_clock_schedule(struct timespec first, unsigned count, struct timespec second)
{
	clock_value = first;
	clock_next = second;
	clock_remaining = count;
	clock_scheduled = true;
	clock_fixed = true;
}

int
dssh_test_clock_count(void)
{
	return clock_call_num;
}

static bool
clock_should_fail(void)
{
	/* Disarmed calls need not count; bounded armed tests count up to the
	 * requested failure, then disarm to avoid signed counter overflow. */
	if (clock_fail_at < 0)
		return false;
	int call = clock_call_num;
	if (clock_call_num < INT_MAX)
		clock_call_num++;
	if (call == clock_fail_at) {
		clock_fail_at = -1;
		return true;
	}
	return false;
}

int
dssh_test_timespec_get(struct timespec *ts, int base)
{
	if (clock_should_fail())
		return 0;
	if (clock_fixed && base == TIME_UTC) {
		if (clock_scheduled) {
			if (clock_remaining == 0)
				clock_value = clock_next;
			else
				clock_remaining--;
		}
		*ts = clock_value;
		return TIME_UTC;
	}
	return timespec_get(ts, base);
}

static atomic_int ossl_fail_at = -1;
static atomic_int ossl_call_num = 0;

/*
 * Thread-local participation flag.  Defaults to true so all threads
 * participate in the countdown (backward compatible).  A thread can
 * opt out by calling dssh_test_ossl_exclude_thread(), which sets its
 * local flag to false -- its ossl calls then pass straight through
 * without incrementing the counter.
 */
static _Thread_local bool ossl_this_thread = true;
#ifdef DSSH_CRYPTO_OPENSSL
static _Thread_local bool md_size_override;
static _Thread_local int md_size_value;
static _Thread_local bool digest_length_override;
static _Thread_local unsigned int digest_length_value;
static _Thread_local bool encoded_length_override;
static _Thread_local int encoded_length_value;

void
dssh_test_ossl_encoded_length(int value)
{
	encoded_length_override = true;
	encoded_length_value = value;
}

void
dssh_test_ossl_md_size(int value)
{
	md_size_override = true;
	md_size_value = value;
}

void
dssh_test_ossl_digest_length(unsigned int value)
{
	digest_length_override = true;
	digest_length_value = value;
}
#endif

/*
 * Separate countdown for recoverable lock/condvar wrappers (items 85-86).
 * Kept independent of the OpenSSL + init countdown so existing ossl
 * tests are not affected by the additional failable call sites.
 */
static atomic_int thrd_fail_at = -1;
static atomic_int thrd_call_num = 0;
static atomic_bool join_fail_next;
static atomic_int join_call_num;
static _Thread_local mtx_t *reject_mutex_once;
static _Thread_local mtx_t *rejected_mutex;
static _Thread_local unsigned rejected_unlocks;
static _Thread_local mtx_t *unlock_fail_mutex;
static _Thread_local unsigned unlock_fail_skip;
static _Thread_local bool unlock_fail_release_real;
static _Thread_local mtx_t *wake_fail_mutex;
static _Thread_local cnd_t *wake_fail_condition;
static _Thread_local unsigned wake_fail_remaining;
static _Thread_local unsigned wake_fail_hits;
static _Thread_local bool wake_fail_complete_real;
static _Thread_local bool wake_fail_report;

static void
wake_failure_record(void)
{
	wake_fail_remaining--;
	wake_fail_hits++;
	if (wake_fail_report && wake_fail_remaining == 0) {
		if (fputs("DSSH_TEST_WAKE_FAILURE\n", stderr) < 0 || fflush(stderr) != 0)
			_Exit(7);
	}
}

void
dssh_test_wake_lock(mtx_t *mutex, bool complete_real)
{
	wake_fail_mutex = mutex;
	wake_fail_condition = NULL;
	wake_fail_remaining = 1;
	wake_fail_hits = 0;
	wake_fail_complete_real = complete_real;
	wake_fail_report = true;
}

void
dssh_test_wake_condition(cnd_t *condition, unsigned failures,
    bool complete_real, bool report)
{
	wake_fail_mutex = NULL;
	wake_fail_condition = condition;
	wake_fail_remaining = failures;
	wake_fail_hits = 0;
	wake_fail_complete_real = complete_real;
	wake_fail_report = report;
}

unsigned
dssh_test_wake_hits(void)
{
	return wake_fail_hits;
}

void
dssh_test_ossl_reset(void)
{
	atomic_store(&ossl_fail_at, -1);
	atomic_store(&ossl_call_num, 0);
	atomic_store(&thrd_fail_at, -1);
	atomic_store(&thrd_call_num, 0);
	atomic_store(&join_fail_next, false);
	atomic_store(&join_call_num, 0);
	reject_mutex_once = NULL;
	rejected_mutex = NULL;
	rejected_unlocks = 0;
	unlock_fail_mutex = NULL;
	wait_probe = NULL;
	dssh_test_mtx_watch_ownership(NULL);
	wake_fail_mutex = NULL;
	wake_fail_condition = NULL;
	wake_fail_remaining = 0;
	wake_fail_hits = 0;
	ossl_this_thread = true;
#ifdef DSSH_CRYPTO_OPENSSL
	md_size_override = false;
	digest_length_override = false;
	encoded_length_override = false;
#endif
	dssh_test_clock_reset();
}

void
dssh_test_ossl_fail_after(int n)
{
	atomic_store(&ossl_call_num, 0);
	atomic_store(&ossl_fail_at, n);
}

void
dssh_test_ossl_exclude_thread(void)
{
	ossl_this_thread = false;
}

int
dssh_test_ossl_count(void)
{
	return atomic_load(&ossl_call_num);
}

void
dssh_test_thrd_fail_after(int n)
{
	atomic_store(&thrd_call_num, 0);
	atomic_store(&thrd_fail_at, n);
}

void
dssh_test_thrd_reset(void)
{
	atomic_store(&thrd_fail_at, -1);
	atomic_store(&thrd_call_num, 0);
	atomic_store(&join_fail_next, false);
	atomic_store(&join_call_num, 0);
	reject_mutex_once = NULL;
	rejected_mutex = NULL;
	rejected_unlocks = 0;
	unlock_fail_mutex = NULL;
	wait_probe = NULL;
	dssh_test_mtx_watch_ownership(NULL);
	wake_fail_mutex = NULL;
	wake_fail_condition = NULL;
	wake_fail_remaining = 0;
	wake_fail_hits = 0;
}

void
dssh_test_unlock_fail_after(mtx_t *mutex, unsigned skip, bool release_real)
{
	unlock_fail_mutex = mutex;
	unlock_fail_skip = skip;
	unlock_fail_release_real = release_real;
}

void
dssh_test_mtx_reject_once(mtx_t *mutex)
{
	reject_mutex_once = mutex;
	rejected_mutex = NULL;
	rejected_unlocks = 0;
}

unsigned
dssh_test_mtx_rejected_unlocks(void)
{
	return rejected_unlocks;
}

void
dssh_test_join_fail_next(void)
{
	atomic_store(&join_call_num, 0);
	atomic_store(&join_fail_next, true);
}

int
dssh_test_join_count(void)
{
	return atomic_load(&join_call_num);
}

int
dssh_test_thrd_count(void)
{
	return atomic_load(&thrd_call_num);
}

/*
 * Check if a lock/unlock/condvar/join call should fail.  Uses the
 * separate thrd_fail_at / thrd_call_num countdown.
 */
static bool
should_thrd_fail(void)
{
	if (!ossl_this_thread)
		return false;
	int fa = atomic_load(&thrd_fail_at);
	if (fa < 0)
		return false;
	int n = atomic_fetch_add(&thrd_call_num, 1);
	return (n == fa);
}

/* Simulated failure never consumes the real joinable worker. */
int
dssh_test_thrd_join(thrd_t thr, int *res)
{
	atomic_fetch_add(&join_call_num, 1);
	if (atomic_exchange(&join_fail_next, false))
		return thrd_error;
	if (should_thrd_fail())
		return thrd_error;
	return thrd_join(thr, res);
}

/*
 * Check if this call should fail.  Returns true if the countdown
 * has fired (call_num == fail_at).  Threads that called
 * dssh_test_ossl_exclude_thread() are ignored.
 */
static bool
should_fail(void)
{
	if (!ossl_this_thread)
		return false;
	int fa = atomic_load(&ossl_fail_at);
	if (fa < 0)
		return false;
	int n = atomic_fetch_add(&ossl_call_num, 1);
	return (n == fa);
}

#ifdef DSSH_CRYPTO_OPENSSL
int
dssh_test_EVP_MD_get_size(const EVP_MD *md)
{
	if (md_size_override)
		return md_size_value;
	return EVP_MD_get_size(md);
}

int
dssh_test_EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int length)
{
	int ret = EVP_EncodeBlock(out, in, length);
	return encoded_length_override ? encoded_length_value : ret;
}
/* ================================================================
 * OpenSSL creation wrappers (return NULL on failure)
 * ================================================================ */

EVP_MD_CTX *
dssh_test_EVP_MD_CTX_new(void)
{
	if (should_fail())
		return NULL;
	return EVP_MD_CTX_new();
}

EVP_CIPHER_CTX *
dssh_test_EVP_CIPHER_CTX_new(void)
{
	if (should_fail())
		return NULL;
	return EVP_CIPHER_CTX_new();
}

EVP_MAC_CTX *
dssh_test_EVP_MAC_CTX_new(EVP_MAC *mac)
{
	if (should_fail())
		return NULL;
	return EVP_MAC_CTX_new(mac);
}

EVP_MAC *
dssh_test_EVP_MAC_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties)
{
	if (should_fail())
		return NULL;
	return EVP_MAC_fetch(ctx, algorithm, properties);
}

EVP_MD *
dssh_test_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties)
{
	if (should_fail())
		return NULL;
	return EVP_MD_fetch(ctx, algorithm, properties);
}

EVP_PKEY_CTX *
dssh_test_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
{
	if (should_fail())
		return NULL;
	return EVP_PKEY_CTX_new(pkey, e);
}

EVP_PKEY_CTX *
dssh_test_EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
	if (should_fail())
		return NULL;
	return EVP_PKEY_CTX_new_id(id, e);
}

EVP_PKEY_CTX *
dssh_test_EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *ctx,
    const char *name, const char *propquery)
{
	if (should_fail())
		return NULL;
	return EVP_PKEY_CTX_new_from_name(ctx, name, propquery);
}

EVP_PKEY *
dssh_test_EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
    const unsigned char *pub, size_t len)
{
	if (should_fail())
		return NULL;
	return EVP_PKEY_new_raw_public_key(type, e, pub, len);
}

BN_CTX *
dssh_test_BN_CTX_new(void)
{
	if (should_fail())
		return NULL;
	return BN_CTX_new();
}

BIGNUM *
dssh_test_BN_new(void)
{
	if (should_fail())
		return NULL;
	return BN_new();
}

OSSL_PARAM_BLD *
dssh_test_OSSL_PARAM_BLD_new(void)
{
	if (should_fail())
		return NULL;
	return OSSL_PARAM_BLD_new();
}

OSSL_PARAM *
dssh_test_OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld)
{
	if (should_fail())
		return NULL;
	return OSSL_PARAM_BLD_to_param(bld);
}

/* ================================================================
 * OpenSSL operation wrappers (return 0 or <=0 on failure)
 * ================================================================ */

int
dssh_test_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
    ENGINE *impl)
{
	if (should_fail())
		return 0;
	return EVP_DigestInit_ex(ctx, type, impl);
}

int
dssh_test_EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
	if (should_fail())
		return 0;
	return EVP_MD_CTX_reset(ctx);
}

int
dssh_test_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
    size_t cnt)
{
	if (should_fail())
		return 0;
	return EVP_DigestUpdate(ctx, d, cnt);
}

int
dssh_test_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
    unsigned int *s)
{
	if (should_fail())
		return 0;
	int ret = EVP_DigestFinal_ex(ctx, md, s);
	if (ret == 1 && digest_length_override && s != NULL)
		*s = digest_length_value;
	return ret;
}

int
dssh_test_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
	if (should_fail())
		return 0;
	return EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

int
dssh_test_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
    size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
	if (should_fail())
		return 0;
	return EVP_DigestSign(ctx, sigret, siglen, tbs, tbslen);
}

int
dssh_test_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
	if (should_fail())
		return 0;
	return EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

int
dssh_test_EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
    size_t siglen, const unsigned char *tbs, size_t tbslen)
{
	if (should_fail())
		return 0;
	return EVP_DigestVerify(ctx, sigret, siglen, tbs, tbslen);
}

int
dssh_test_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    ENGINE *impl, const unsigned char *key, const unsigned char *iv)
{
	if (should_fail())
		return 0;
	return EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
}

int
dssh_test_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    int *outl, const unsigned char *in, int inl)
{
	if (should_fail())
		return 0;
	return EVP_EncryptUpdate(ctx, out, outl, in, inl);
}

int
dssh_test_EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key,
    size_t keylen, const OSSL_PARAM params[])
{
	if (should_fail())
		return 0;
	return EVP_MAC_init(ctx, key, keylen, params);
}

int
dssh_test_EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data,
    size_t datalen)
{
	if (should_fail())
		return 0;
	return EVP_MAC_update(ctx, data, datalen);
}

int
dssh_test_EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out,
    size_t *outl, size_t outsize)
{
	if (should_fail())
		return 0;
	return EVP_MAC_final(ctx, out, outl, outsize);
}

int
dssh_test_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_keygen_init(ctx);
}

int
dssh_test_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_keygen(ctx, ppkey);
}

int
dssh_test_EVP_PKEY_pairwise_check(EVP_PKEY_CTX *ctx)
{
	if (should_fail())
		return -1;
	return EVP_PKEY_pairwise_check(ctx);
}

int
dssh_test_EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_up_ref(pkey);
}

int
dssh_test_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_derive_init(ctx);
}

int
dssh_test_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_derive_set_peer(ctx, peer);
}

int
dssh_test_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
    size_t *keylen)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_derive(ctx, key, keylen);
}

int
dssh_test_EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_fromdata_init(ctx);
}

int
dssh_test_EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey,
    int selection, OSSL_PARAM params[])
{
	if (should_fail())
		return 0;
	return EVP_PKEY_fromdata(ctx, ppkey, selection, params);
}

int
dssh_test_EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey,
    unsigned char *pub, size_t *len)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_get_raw_public_key(pkey, pub, len);
}

int
dssh_test_EVP_PKEY_get_bn_param(const EVP_PKEY *pkey,
    const char *key_name, BIGNUM **bn)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_get_bn_param(pkey, key_name, bn);
}

int
dssh_test_EVP_Digest(const void *data, size_t count, unsigned char *md,
    unsigned int *size, const EVP_MD *type, ENGINE *impl)
{
	if (should_fail())
		return 0;
	int ret = EVP_Digest(data, count, md, size, type, impl);
	if (ret == 1 && digest_length_override && size != NULL)
		*size = digest_length_value;
	return ret;
}

int
dssh_test_RAND_bytes(unsigned char *buf, int num)
{
	if (should_fail())
		return 0;
	return RAND_bytes(buf, num);
}

int
dssh_test_BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx)
{
	if (should_fail())
		return 0;
	return BN_mod_exp(r, a, p, m, ctx);
}

int
dssh_test_BN_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
	if (should_fail())
		return 0;
	return BN_rand(rnd, bits, top, bottom);
}

int
dssh_test_BN_rand_range(BIGNUM *rnd, const BIGNUM *range)
{
	if (should_fail())
		return 0;
	return BN_rand_range(rnd, range);
}

BIGNUM *
dssh_test_BN_dup(const BIGNUM *a)
{
	if (should_fail())
		return NULL;
	return BN_dup(a);
}

int
dssh_test_BN_rshift1(BIGNUM *r, const BIGNUM *a)
{
	if (should_fail())
		return 0;
	return BN_rshift1(r, a);
}

int
dssh_test_BN_sub_word(BIGNUM *a, BN_ULONG word)
{
	if (should_fail())
		return 0;
	return BN_sub_word(a, word);
}

int
dssh_test_BN_add_word(BIGNUM *a, BN_ULONG word)
{
	if (should_fail())
		return 0;
	return BN_add_word(a, word);
}

int
dssh_test_BN_check_prime(const BIGNUM *p, BN_CTX *ctx, BN_GENCB *cb)
{
	if (should_fail())
		return 0;
	return BN_check_prime(p, ctx, cb);
}

BIGNUM *
dssh_test_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
	if (should_fail())
		return NULL;
	return BN_bin2bn(s, len, ret);
}

int
dssh_test_BN_bn2bin(const BIGNUM *value, unsigned char *out)
{
	if (should_fail())
		return -1;
	return BN_bn2bin(value, out);
}

int
dssh_test_OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld,
    const char *key, const BIGNUM *bn)
{
	if (should_fail())
		return 0;
	return OSSL_PARAM_BLD_push_BN(bld, key, bn);
}

int
dssh_test_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)
{
	if (should_fail())
		return 0;
	return EVP_CIPHER_CTX_set_padding(ctx, pad);
}

int
dssh_test_EVP_PKEY_CTX_set_params(EVP_PKEY_CTX *ctx,
    const OSSL_PARAM *params)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_CTX_set_params(ctx, params);
}

int
dssh_test_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode)
{
	if (should_fail())
		return 0;
	return EVP_PKEY_CTX_set_rsa_padding(ctx, pad_mode);
}

#endif /* DSSH_CRYPTO_OPENSSL */

/* ================================================================
 * C11 threads wrappers
 * ================================================================ */

int
dssh_test_mtx_init(mtx_t *mtx, int type)
{
	if (should_fail())
		return thrd_error;
	return mtx_init(mtx, type);
}

int
dssh_test_cnd_init(cnd_t *cond)
{
	if (should_fail())
		return thrd_error;
	return cnd_init(cond);
}

int
dssh_test_thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
{
	if (should_fail())
		return thrd_error;
	return thrd_create(thr, func, arg);
}

/*
 * Lock/unlock/condvar wrappers.
 *
 * mtx_lock: skip the real acquisition on injected failure.
 * cnd_wait/cnd_timedwait: skip waiting on injected failure, preserving
 * the caller's already-held associated mutex in this model.
 *
 * cnd_broadcast/cnd_signal call the real function, then report injected error.
 * Mutex release uses only the independent fresh-process fatal control: either
 * retain the real owned mutex, or really unlock before reporting failure.
 * The recoverable countdown does not count/inject mutex releases.
 */

int
dssh_test_mtx_lock(mtx_t *mtx)
{
	if (mtx == delayed_mutex) {
		if (delayed_mutex_skip > 0)
			delayed_mutex_skip--;
		else {
			delayed_mutex = NULL;
			atomic_store(&mutex_pause_entered, true);
			while (!atomic_load(&mutex_pause_released))
				thrd_yield();
		}
	}
	if (mtx == atomic_load(&paused_mutex)) {
		atomic_store(&mutex_pause_entered, true);
		while (!atomic_load(&mutex_pause_released))
			thrd_yield();
	}
	if (wake_fail_remaining != 0 && mtx == wake_fail_mutex) {
		if (wake_fail_complete_real && mtx_lock(mtx) != thrd_success)
			_Exit(7);
		wake_failure_record();
		return thrd_error;
	}
	if (reject_mutex_once != NULL && mtx == reject_mutex_once) {
		reject_mutex_once = NULL;
		rejected_mutex = mtx;
		return thrd_error;
	}
	if (should_thrd_fail())
		return thrd_error;
	int ret = mtx_lock(mtx);
	if (ret == thrd_success && mtx == ownership_mutex)
		ownership_held = true;
	if (ret == thrd_success && mtx == rejected_mutex)
		rejected_mutex = NULL;
	return ret;
}

int
dssh_test_mtx_unlock(mtx_t *mtx)
{
	if (rejected_mutex != NULL && mtx == rejected_mutex) {
		if (rejected_unlocks < UINT_MAX)
			rejected_unlocks++;
		return thrd_error;
	}
	if (unlock_fail_mutex != NULL && mtx == unlock_fail_mutex) {
		if (unlock_fail_skip > 0)
			unlock_fail_skip--;
		else {
			unlock_fail_mutex = NULL;
			if (unlock_fail_release_real && mtx_unlock(mtx) != thrd_success)
				_Exit(7);
			/* Test-driver provenance: emit only when the armed native
			 * boundary is reached, never from the production library. */
			if (fputs("DSSH_TEST_UNLOCK_FAILURE\n", stderr) < 0 || fflush(stderr) != 0)
				_Exit(7);
			return thrd_error;
		}
	}
	/* Release faults have their own process-isolated fatal checks. */
	int ret = mtx_unlock(mtx);
	if (ret == thrd_success && mtx == ownership_mutex)
		ownership_held = false;
	if (wait_probe != NULL && mtx == wait_probe->mutex
	    && atomic_load(&wait_probe->returning)) {
		if (wait_probe->releases == 0)
			wait_probe->unlock_result = ret;
		if (wait_probe->releases < UINT_MAX)
			wait_probe->releases++;
	}
	return ret;
}

static int
probe_wait_result(struct dssh_test_wait_probe *probe)
{
	atomic_store(&probe->returning, true);
	/* Test-only nonblocking atomic handoff: no callback, wait, yield or
	 * additional physical mutex while the associated mutex is owned. */
	while (!atomic_load(&probe->release)) {
	}
	return probe->result;
}

static int
condition_wait(cnd_t *cond, mtx_t *mtx, const struct timespec *ts)
{
	struct dssh_test_wait_probe *probe = wait_probe;
	if (probe != NULL && (probe->condition != cond || probe->mutex != mtx))
		probe = NULL;
	bool first = false;
	if (probe != NULL) {
		unsigned calls = atomic_load(&probe->calls);
		first = calls == 0;
		if (first)
			probe->timed = ts != NULL;
		if (calls < UINT_MAX)
			atomic_store(&probe->calls, calls + 1);
		if (first && !probe->complete_real)
			return probe_wait_result(probe);
	}
	if (should_thrd_fail())
		return thrd_error;
	int ret;
	do {
		observe_condition(cond);
		if (probe != NULL) {
			unsigned calls = atomic_load(&probe->native_calls);
			if (calls < UINT_MAX)
				atomic_store(&probe->native_calls, calls + 1);
		}
		ret = ts != NULL ? cnd_timedwait(cond, mtx, ts) : cnd_wait(cond, mtx);
	} while (first && probe->until_timeout && ts != NULL && ret == thrd_success);
	if (first) {
		atomic_store(&probe->native_result, ret);
		return probe_wait_result(probe);
	}
	return ret;
}

int
dssh_test_cnd_wait(cnd_t *cond, mtx_t *mtx)
{
	return condition_wait(cond, mtx, NULL);
}

int
dssh_test_cnd_timedwait(cnd_t *cond, mtx_t *mtx,
    const struct timespec *ts)
{
	return condition_wait(cond, mtx, ts);
}

int
dssh_test_cnd_broadcast(cnd_t *cond)
{
	if (wake_fail_remaining != 0 && cond == wake_fail_condition) {
		if (wake_fail_complete_real && cnd_broadcast(cond) != thrd_success)
			_Exit(7);
		wake_failure_record();
		return thrd_error;
	}
	int ret = cnd_broadcast(cond);
	if (should_thrd_fail())
		return thrd_error;
	return ret;
}

int
dssh_test_cnd_signal(cnd_t *cond)
{
	if (wake_fail_remaining != 0 && cond == wake_fail_condition) {
		if (wake_fail_complete_real && cnd_signal(cond) != thrd_success)
			_Exit(7);
		wake_failure_record();
		return thrd_error;
	}
	int ret = cnd_signal(cond);
	if (should_thrd_fail())
		return thrd_error;
	return ret;
}


/* Target library-owned key-file streams, without changing provider stdio. */
#include "dssh_test_alloc.h"

static _Thread_local dssh_test_key_clear_observer key_clear_observer;
static _Thread_local void *key_clear_data;
static _Thread_local bool key_close_error;
static _Thread_local bool key_write_armed;
static _Thread_local bool key_put_armed;
static _Thread_local unsigned int key_write_after;
static _Thread_local unsigned int key_put_after;
static _Thread_local unsigned int key_write_count;
static _Thread_local unsigned int key_write_short_count;
static _Thread_local unsigned int key_put_count;
static _Thread_local unsigned int key_put_injected;
static _Thread_local unsigned int key_native_write_errors;
static _Thread_local bool key_watch_read;
static _Thread_local bool key_read_short;
static _Thread_local unsigned int key_read_short_count;
static _Thread_local unsigned int key_close_count;
static _Thread_local unsigned int key_close_injected;
static _Thread_local unsigned int key_close_native_errors;
static _Thread_local unsigned int key_read_count;

static _Thread_local bool key_stream_watch, key_setvbuf_error, key_stream_closed;
static _Thread_local FILE *key_watched_stream;
static _Thread_local char *key_stream_buffer;
static _Thread_local size_t key_stream_capacity;
static _Thread_local struct dssh_test_key_stream_report key_stream_report;

void
dssh_test_key_watch_stream(void)
{
	key_stream_watch = true;
	key_stream_report.valid = true;
}

void
dssh_test_key_setvbuf_error_once(void)
{
	key_setvbuf_error = true;
}

struct dssh_test_key_stream_report
dssh_test_key_stream_report(void)
{
	return key_stream_report;
}

int
dssh_test_key_file_setvbuf(FILE *stream, char *buffer, int mode, size_t capacity)
{
	int ret = setvbuf(stream, buffer, mode, capacity);
	if (key_stream_watch) {
		if (key_stream_report.active || buffer == NULL || mode != _IOFBF || capacity != BUFSIZ
		    || key_stream_report.configurations == UINT_MAX)
			key_stream_report.valid = false;
		else {
			key_stream_report.configurations++;
			key_watched_stream = stream;
			key_stream_buffer = buffer;
			key_stream_capacity = capacity;
			key_stream_closed = false;
			key_stream_report.active = true;
		}
		if (ret != 0) {
			if (key_stream_report.native_errors == UINT_MAX)
				key_stream_report.valid = false;
			else
				key_stream_report.native_errors++;
		}
	}
	if (key_setvbuf_error) {
		key_setvbuf_error = false;
		if (key_stream_report.injected == UINT_MAX)
			key_stream_report.valid = false;
		else
			key_stream_report.injected++;
		return EOF;
	}
	return ret;
}

void
dssh_test_key_stdio_reset(void)
{
	key_stream_watch = false;
	key_setvbuf_error = false;
	key_stream_closed = false;
	key_watched_stream = NULL;
	key_stream_buffer = NULL;
	key_stream_capacity = 0;
	key_stream_report = (struct dssh_test_key_stream_report){0};
	key_clear_observer = NULL;
	key_clear_data = NULL;
	key_close_error = false;
	key_write_armed = false;
	key_put_armed = false;
	key_write_after = 0;
	key_put_after = 0;
	key_write_count = 0;
	key_write_short_count = 0;
	key_put_count = 0;
	key_put_injected = 0;
	key_native_write_errors = 0;
	key_watch_read = false;
	key_read_short = false;
	key_read_short_count = 0;
	key_close_count = 0;
	key_close_injected = 0;
	key_close_native_errors = 0;
	key_read_count = 0;
}

void
dssh_test_key_close_error_once(void)
{
	key_close_error = true;
}

void
dssh_test_key_watch_read_free(void)
{
	key_watch_read = true;
}

void
dssh_test_key_read_short_once(void)
{
	key_read_short = true;
}

unsigned int
dssh_test_key_short_read_calls(void)
{
	return key_read_short_count;
}

unsigned int
dssh_test_key_close_calls(void)
{
	return key_close_count;
}

unsigned int
dssh_test_key_close_errors(void)
{
	return key_close_injected;
}

unsigned int
dssh_test_key_native_close_errors(void)
{
	return key_close_native_errors;
}

unsigned int
dssh_test_key_read_calls(void)
{
	return key_read_count;
}

int
dssh_test_key_file_close(FILE *stream)
{
	if (key_stream_watch && key_stream_report.active && stream == key_watched_stream) {
		bool nonzero = false;
		for (size_t i = 0; i < key_stream_capacity; i++) {
			if (key_stream_buffer[i] != 0)
				nonzero = true;
		}
		if (key_stream_closed || key_stream_report.closes == UINT_MAX
		    || (nonzero && key_stream_report.nonzero == UINT_MAX))
			key_stream_report.valid = false;
		else {
			key_stream_report.closes++;
			if (nonzero)
				key_stream_report.nonzero++;
		}
		key_stream_closed = true;
		key_watched_stream = NULL;
	}
	int ret = fclose(stream);
	if (key_close_count < UINT_MAX)
		key_close_count++;
	if (ret != 0 && key_close_native_errors < UINT_MAX)
		key_close_native_errors++;
	if (key_close_error) {
		key_close_error = false;
		if (key_close_injected < UINT_MAX)
			key_close_injected++;
		return EOF;
	}
	return ret;
}

size_t
dssh_test_key_file_read(void *ptr, size_t size, size_t count, FILE *stream)
{
	size_t requested = count;
	if (key_read_short && count != 0) {
		key_read_short = false;
		requested--;
		if (key_read_short_count < UINT_MAX)
			key_read_short_count++;
	}
	size_t ret = fread(ptr, size, requested, stream);
	if (key_read_count < UINT_MAX)
		key_read_count++;
	if (key_watch_read && size != 0 && count <= SIZE_MAX / size) {
		key_watch_read = false;
		dssh_test_alloc_watch_free(ptr, size * count);
	}
	return ret;
}


void
dssh_test_key_observe_clear(dssh_test_key_clear_observer observer, void *data)
{
	key_clear_observer = observer;
	key_clear_data = data;
}

void
dssh_test_key_file_cleared(const void *ptr, size_t length)
{
	if (key_stream_watch && key_stream_report.active && ptr == key_stream_buffer) {
		bool zero = length == key_stream_capacity;
		const unsigned char *bytes = ptr;
		if (zero) {
			for (size_t i = 0; i < key_stream_capacity; i++) {
				if (bytes[i] != 0)
					zero = false;
			}
		}
		if (!key_stream_closed || length != key_stream_capacity || !zero
		    || key_stream_report.clears == UINT_MAX)
			key_stream_report.valid = false;
		else
			key_stream_report.clears++;
		key_stream_buffer = NULL;
		key_stream_capacity = 0;
		key_stream_report.active = false;
	}
	if (key_clear_observer != NULL)
		key_clear_observer(ptr, length, key_clear_data);
}


void
dssh_test_key_write_short_after(unsigned int calls)
{
	key_write_armed = true;
	key_write_after = calls;
}

void
dssh_test_key_put_error_after(unsigned int calls)
{
	key_put_armed = true;
	key_put_after = calls;
}

unsigned int
dssh_test_key_write_calls(void)
{
	return key_write_count;
}

unsigned int
dssh_test_key_short_write_calls(void)
{
	return key_write_short_count;
}

unsigned int
dssh_test_key_put_calls(void)
{
	return key_put_count;
}

unsigned int
dssh_test_key_put_errors(void)
{
	return key_put_injected;
}

unsigned int
dssh_test_key_native_write_errors(void)
{
	return key_native_write_errors;
}

size_t
dssh_test_key_file_write(const void *ptr, size_t size, size_t count, FILE *stream)
{
	size_t requested = count;
	if (key_write_armed && count != 0) {
		if (key_write_after == 0) {
			key_write_armed = false;
			requested--;
			if (key_write_short_count < UINT_MAX)
				key_write_short_count++;
		}
		else
			key_write_after--;
	}
	size_t ret = fwrite(ptr, size, requested, stream);
	if (ret != requested && key_native_write_errors < UINT_MAX)
		key_native_write_errors++;
	if (key_write_count < UINT_MAX)
		key_write_count++;
	return ret;
}

int
dssh_test_key_file_put(int byte, FILE *stream)
{
	int ret = fputc(byte, stream);
	if (ret == EOF && key_native_write_errors < UINT_MAX)
		key_native_write_errors++;
	if (key_put_count < UINT_MAX)
		key_put_count++;
	if (key_put_armed) {
		if (key_put_after == 0) {
			key_put_armed = false;
			if (key_put_injected < UINT_MAX)
				key_put_injected++;
			return EOF;
		}
		key_put_after--;
	}
	return ret;
}
