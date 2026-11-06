/*
 * key_algo/rsa-sha2-256-botan.cpp -- RSA-SHA2-256 host key algorithm via Botan3 native C++ API.
 *
 * The dssh_register_rsa_sha2_256() function lives in the companion .c file
 * to avoid C++ exposure to C flexible array member structs.
 */

#include <botan/bigint.h>
#include <botan/pem.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/system_rng.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "deucessh-algorithms.h"
#include "deucessh-crypto.h"
#include "deucessh.h"
#include "private-key-file.h"
#include "key-context-botan.h"
#include "key-wire.h"
#include "key-file-common.h"
#include "key-text.h"

struct dssh_key_algo_ctx;

#define RSA_SHA2_256_NAME     "rsa-sha2-256"
#define RSA_SHA2_256_NAME_LEN 12

/* The SSH wire format uses "ssh-rsa" as the key type name,
 * even for rsa-sha2-256 signatures (RFC 8332 s3). */
#define RSA_KEY_TYPE_NAME     "ssh-rsa"
#define RSA_KEY_TYPE_NAME_LEN 7

/* Botan renamed the PKCS#1 v1.5 padding from "EMSA_PKCS1(...)" to
   "PKCS1v15(...)" between Botan 3.6 and 3.9.  The old spelling became a
   lookup-miss that throws mid-construction of PK_Verifier, and at least
   in Botan 3.9 the throw cascades through a half-initialised object so
   the caller sees SIGSEGV/SIGBUS rather than a clean exception.  Use
   the modern spelling. */
#define RSA_SIGN_PADDING "PKCS1v15(SHA-256)"


static struct dssh_botan_key_context *rsa_ctx;

static int
sign_impl(struct dssh_bytes_result *out, const uint8_t *data, size_t data_len, struct dssh_botan_key_context *cbd)
{
	if (out == NULL || (data == NULL && data_len > 0)
	    || out->bytes.data != NULL || out->bytes.len != 0
	    || out->lease.release != NULL || out->lease.owner != NULL)
		return DSSH_ERROR_INVALID;
	if (cbd == NULL || cbd->privkey == NULL)
		return DSSH_ERROR_INIT;

	try {
		Botan::PK_Signer signer(*cbd->privkey, Botan::system_rng(), RSA_SIGN_PADDING);
		signer.update(data, data_len);
		auto raw_sig = signer.signature(Botan::system_rng());

		if (raw_sig.empty())
			return DSSH_ERROR_INIT;
		if (raw_sig.size() > UINT32_MAX)
			return DSSH_ERROR_INVALID;
		if (raw_sig.size() > SIZE_MAX - 20)
			return DSSH_ERROR_INVALID;
		size_t needed = 20 + raw_sig.size();

		uint8_t *buf = NULL;
		int acquired = dssh_signature_buffer_acquire(cbd->signatures, needed, out, &buf);
		if (acquired < 0)
			return acquired;

		size_t pos  = 0;
		int    sret = dssh_serialize_uint32(RSA_SHA2_256_NAME_LEN, buf, needed, &pos);
		if (sret < 0) {
			return sret;
		}
		memcpy(&buf[pos], RSA_SHA2_256_NAME, RSA_SHA2_256_NAME_LEN);
		pos += RSA_SHA2_256_NAME_LEN;
		uint32_t siglen_u32 = static_cast<uint32_t>(raw_sig.size());
		sret                = dssh_serialize_uint32(siglen_u32, buf, needed, &pos);
		if (sret < 0) {
			return sret;
		}
		memcpy(&buf[pos], raw_sig.data(), raw_sig.size());
		pos += raw_sig.size();

		out->bytes.len = pos;
		return 0;
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

/*
 * Write the SSH-format public key blob:
 *   string  "ssh-rsa"
 *   string  e (public exponent)
 *   string  n (modulus)
 */
static int
pubkey_impl(const uint8_t **out, size_t *outlen, struct dssh_botan_key_context *cbd)
{
	if (cbd == NULL || cbd->privkey == NULL)
		return DSSH_ERROR_INIT;

	/* Return cached blob if already computed */
	if (cbd->pub_blob != NULL) {
		*out    = cbd->pub_blob;
		*outlen = cbd->pub_blob_len;
		return 0;
	}

	try {
		auto *rsa_priv = dynamic_cast<Botan::RSA_PrivateKey *>(cbd->privkey.get());
		if (rsa_priv == NULL)
			return DSSH_ERROR_INIT;

		auto   e_raw = rsa_priv->get_e().serialize();
		auto   n_raw = rsa_priv->get_n().serialize();
		size_t e_sz  = e_raw.size();
		size_t n_sz  = n_raw.size();

		/* mpint encoding: add leading zero if MSB is set. */
		bool e_pad = (e_sz > 0 && (e_raw[0] & DSSH_MPINT_SIGN_BIT));
		bool n_pad = (n_sz > 0 && (n_raw[0] & DSSH_MPINT_SIGN_BIT));

		if (e_sz > UINT32_MAX - 1 || n_sz > UINT32_MAX - 1)
			return DSSH_ERROR_INVALID;
		uint32_t e_u32  = static_cast<uint32_t>(e_sz);
		uint32_t n_u32  = static_cast<uint32_t>(n_sz);
		uint32_t e_wire = e_u32 + (e_pad ? 1 : 0);
		uint32_t n_wire = n_u32 + (n_pad ? 1 : 0);

		if (!dssh_buffer_has(SIZE_MAX - 19, e_wire, n_wire))
			return DSSH_ERROR_INVALID;
		size_t needed = 19 + e_wire + n_wire;

		uint8_t *buf = static_cast<uint8_t *>(malloc(needed));

		if (buf == NULL)
			return DSSH_ERROR_ALLOC;

		size_t pos = 0;
		int    sret;

#define PK_SER(v)                                                     \
	do {                                                          \
		sret = dssh_serialize_uint32((v), buf, needed, &pos); \
		if (sret < 0) {                                       \
			free(buf);                                    \
			return sret;                                  \
		}                                                     \
	} while (0)

		PK_SER(RSA_KEY_TYPE_NAME_LEN);
		memcpy(&buf[pos], RSA_KEY_TYPE_NAME, RSA_KEY_TYPE_NAME_LEN);
		pos += RSA_KEY_TYPE_NAME_LEN;

		PK_SER(e_wire);
		if (e_pad)
			buf[pos++] = 0;
		memcpy(&buf[pos], e_raw.data(), e_sz);
		pos += e_sz;

		PK_SER(n_wire);
		if (n_pad)
			buf[pos++] = 0;
		memcpy(&buf[pos], n_raw.data(), n_sz);
		pos += n_sz;

#undef PK_SER

		cbd->pub_blob     = buf;
		cbd->pub_blob_len = pos;
		*out              = buf;
		*outlen           = pos;
		return 0;
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

/* --- extern "C" wrappers for function pointer vtable --- */

extern "C" int
dssh_botan_rsa256_sign(struct dssh_bytes_result *out, const uint8_t *data, size_t data_len,
    dssh_key_algo_ctx *ctx)
{
	try {
		return sign_impl(out, data, data_len, reinterpret_cast<struct dssh_botan_key_context *>(ctx));
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

extern "C" int
dssh_botan_rsa256_verify(const uint8_t *key_blob, size_t key_blob_len, const uint8_t *sig_blob,
    size_t sig_blob_len, const uint8_t *data, size_t data_len)
{
	struct dssh_rsa_wire_key key;
	struct dssh_bytes signature;
	int ret;
	if (data == NULL && data_len != 0)
		return DSSH_ERROR_INVALID;
	ret = dssh_key_wire_rsa(key_blob, key_blob_len, &key);
	if (ret < 0)
		return ret;
	ret = dssh_key_wire_blob(sig_blob, sig_blob_len, RSA_SHA2_256_NAME,
	    RSA_SHA2_256_NAME_LEN, &signature);
	if (ret < 0)
		return ret;
	if (signature.len == 0)
		return DSSH_ERROR_INVALID;
	const uint8_t *e_bytes = key.exponent.data;
	size_t e_len = key.exponent.len;
	const uint8_t *n_bytes = key.modulus.data;
	size_t n_len = key.modulus.len;
	const uint8_t *raw_sig = signature.data;
	size_t raw_sig_len = signature.len;

	try {
		Botan::BigInt        e_bn = Botan::BigInt::from_bytes(std::span<const uint8_t>(e_bytes, e_len));
		Botan::BigInt        n_bn = Botan::BigInt::from_bytes(std::span<const uint8_t>(n_bytes, n_len));
		Botan::RSA_PublicKey pubkey_h(n_bn, e_bn);

		Botan::PK_Verifier verifier(pubkey_h, RSA_SIGN_PADDING);
		verifier.update(data, data_len);
		if (verifier.check_signature(raw_sig, raw_sig_len))
			return 0;
		return DSSH_ERROR_INVALID;
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

extern "C" int
dssh_botan_rsa256_pubkey(const uint8_t **out, size_t *outlen, dssh_key_algo_ctx *ctx)
{
	try {
		return pubkey_impl(out, outlen, reinterpret_cast<struct dssh_botan_key_context *>(ctx));
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

extern "C" int
dssh_botan_rsa256_haskey(dssh_key_algo_ctx *ctx)
{
	struct dssh_botan_key_context *cbd = reinterpret_cast<struct dssh_botan_key_context *>(ctx);
	if (cbd == NULL || cbd->privkey == NULL)
		return 0;
	try {
		return (cbd->privkey->algo_name() == "RSA");
	}
	catch (...) {
		return 0;
	}
}

extern "C" void
dssh_botan_rsa256_cleanup(dssh_key_algo_ctx *ctx)
{
	struct dssh_botan_key_context *cbd = reinterpret_cast<struct dssh_botan_key_context *>(ctx);

	if (cbd == rsa_ctx)
		rsa_ctx = NULL;
	if (cbd != NULL) {
		free(cbd->pub_blob);
		dssh_signature_pool_destroy(cbd->signatures);
		try {
			delete cbd;
		}
		catch (...) {
		}
	}
}

/* Finish construction and caching before the registry can expose the key. */
static int
install_key(std::unique_ptr<Botan::Private_Key> privkey)
{
	try {
		std::unique_ptr<dssh_botan_key_context> replacement(new (std::nothrow) dssh_botan_key_context{});
		if (replacement == nullptr)
			return DSSH_ERROR_ALLOC;
		replacement->privkey = std::move(privkey);
		const uint8_t *blob;
		size_t blob_len;
		int ret = pubkey_impl(&blob, &blob_len, replacement.get());
		if (ret == 0)
			ret = dssh_signature_pool_create(&replacement->signatures);
		if (ret == 0)
			ret = dssh_key_algo_set_ctx(RSA_SHA2_256_NAME, replacement.get());
		if (ret < 0) {
			free(replacement->pub_blob);
			dssh_signature_pool_destroy(replacement->signatures);
			return ret;
		}
		struct dssh_botan_key_context *old = rsa_ctx;
		dssh_key_algo_ctx *old_opaque = reinterpret_cast<dssh_key_algo_ctx *>(old);
		rsa_ctx = replacement.release();
		dssh_botan_rsa256_cleanup(old_opaque);
		return 0;
	}
	catch (const std::bad_alloc &) {
		return DSSH_ERROR_ALLOC;
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}
}

/* --- Public API functions --- */

DSSH_PUBLIC int
dssh_rsa_sha2_256_load_key_file(const char *path, dssh_pem_password_cb pw_cb, void *pw_cbdata)
{
	if (path == NULL)
		return DSSH_ERROR_INIT;
	int config_ret = dssh_key_algo_set_ctx(RSA_SHA2_256_NAME, rsa_ctx);
	if (config_ret < 0)
		return config_ret;
	FILE *fp = fopen(path, "rb");
	if (fp == NULL)
		return DSSH_ERROR_INIT;
	if (fseek(fp, 0, SEEK_END) != 0)
		return dssh_key_file_close(fp, DSSH_ERROR_INIT);
	long fsize = ftell(fp);
	size_t file_sz;
	int ret = dssh_key_file_length(fsize, SIZE_MAX, &file_sz);
	if (ret < 0)
		return dssh_key_file_close(fp, ret);
	if (fseek(fp, 0, SEEK_SET) != 0)
		return dssh_key_file_close(fp, DSSH_ERROR_INIT);
	uint8_t *pem_data = static_cast<uint8_t *>(malloc(file_sz));
	if (pem_data == NULL)
		return dssh_key_file_close(fp, DSSH_ERROR_ALLOC);
	dssh_key_file_buffer input(pem_data, file_sz);
	ret = fread(pem_data, 1, file_sz, fp) == file_sz ? 0 : DSSH_ERROR_INIT;
	ret = dssh_key_file_close(fp, ret);
	if (ret < 0)
		return ret;
	char pw_buf[256];
	dssh_key_file_secret_region password_bytes(pw_buf, sizeof(pw_buf));
	struct dssh_key_file_password_state password = {pw_cb, pw_cbdata, 0};
	try {
		Botan::DataSource_Memory ds(pem_data, file_sz);
		auto get_password = [&]() -> std::string {
			int length = dssh_key_file_password(pw_buf, 256, 0, &password);
			if (length < 0)
				throw dssh_key_file_password_error{};
			size_t count = static_cast<size_t>(length);
			return std::string(pw_buf, count);
		};
		auto privkey = pw_cb == NULL ? Botan::PKCS8::load_key(ds)
		    : Botan::PKCS8::load_key(ds, get_password);
		if (privkey == nullptr || privkey->algo_name() != "RSA")
			return DSSH_ERROR_INVALID;
		return install_key(std::move(privkey));
	}
	catch (...) {
		return password.status < 0 ? password.status : DSSH_ERROR_INIT;
	}
}

static bool
write_pem_to_file(FILE *fp, const std::string& pem)
{
	return fwrite(pem.data(), 1, pem.size(), fp) == pem.size();
}

DSSH_PUBLIC int
dssh_rsa_sha2_256_save_key_file(const char *path, dssh_pem_password_cb pw_cb, void *pw_cbdata)
{
	if (path == NULL)
		return DSSH_ERROR_INIT;
	if (rsa_ctx == NULL || rsa_ctx->privkey == NULL)
		return DSSH_ERROR_INIT;
	std::shared_ptr<Botan::Private_Key> key = rsa_ctx->privkey;
	FILE *fp = dssh_private_key_open(path);
	if (fp == NULL)
		return DSSH_ERROR_INIT;
	char pw_buf[256];
	dssh_key_file_secret_region password_bytes(pw_buf, sizeof(pw_buf));
	struct dssh_key_file_password_state password = {pw_cb, pw_cbdata, 0};
	try {
		dssh_key_file_secret_string pem;
		if (pw_cb != NULL) {
			int length = dssh_key_file_password(pw_buf, 256, 1, &password);
			if (length < 0)
				return dssh_key_file_close(fp, password.status);
			size_t count = static_cast<size_t>(length);
			std::string_view phrase(pw_buf, count);
			pem.value = Botan::PKCS8::PEM_encode_encrypted_pbkdf_msec(*key,
			    Botan::system_rng(), phrase, std::chrono::milliseconds(300), nullptr, "AES-256/CBC");
		}
		else {
			pem.value = Botan::PKCS8::PEM_encode(*key);
		}
		bool written = write_pem_to_file(fp, pem.value);
		return dssh_key_file_close(fp, written ? 0 : DSSH_ERROR_INIT);
	}
	catch (...) {
		return dssh_key_file_close(fp, password.status < 0 ? password.status : DSSH_ERROR_INIT);
	}
}

DSSH_PUBLIC int64_t
dssh_rsa_sha2_256_get_pub_str(char *buf, size_t bufsz)
{
	const uint8_t *blob;
	size_t length;
	int ret = pubkey_impl(&blob, &length, rsa_ctx);
	if (ret < 0)
		return ret;
	return dssh_key_text_format(blob, length, RSA_KEY_TYPE_NAME, RSA_KEY_TYPE_NAME_LEN, buf, bufsz);
}

DSSH_PUBLIC int
dssh_rsa_sha2_256_save_pub_file(const char *path)
{
	if (path == NULL)
		return DSSH_ERROR_INIT;
	const uint8_t *blob;
	size_t length;
	int ret = pubkey_impl(&blob, &length, rsa_ctx);
	if (ret < 0)
		return ret;
	return dssh_key_text_write(path, blob, length, RSA_KEY_TYPE_NAME, RSA_KEY_TYPE_NAME_LEN);
}

DSSH_PUBLIC int
dssh_rsa_sha2_256_generate_key(unsigned int bits)
{
	int config_ret = dssh_key_algo_set_ctx(RSA_SHA2_256_NAME, rsa_ctx);
	if (config_ret < 0)
		return config_ret;
	char bits_str[16];
	int  sret = snprintf(bits_str, sizeof(bits_str), "%u", bits);
	if (sret < 0 || static_cast<size_t>(sret) >= sizeof(bits_str))
		return DSSH_ERROR_INVALID;

	std::unique_ptr<Botan::Private_Key> privkey;

	try {
		privkey = std::make_unique<Botan::RSA_PrivateKey>(Botan::system_rng(), bits);
	}
	catch (...) {
		return DSSH_ERROR_INIT;
	}

	return install_key(std::move(privkey));
}
