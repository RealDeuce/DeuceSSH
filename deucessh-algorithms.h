/*
 * deuce-ssh-algorithms.h -- Built-in algorithm registration and key management.
 *
 * Include this header to access register_*() functions for built-in
 * algorithms and key load/save/generate functions for key algorithms.
 */

#ifndef DSSH_ALGORITHMS_H
#define DSSH_ALGORITHMS_H

#include "deucessh.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Password callback for PEM key files.  Same signature as OpenSSL's
 * pem_password_cb -- buf receives the passphrase, size is the buffer
 * length, rwflag is 0 for reading / 1 for writing, userdata is the
 * opaque pointer passed alongside. Return a byte count in [0, size], including
 * zero for an empty password; a negative result reports failure. A full buffer
 * is valid and needs no NUL terminator. Passphrases may contain NUL bytes.
 * Do not throw C++ exceptions through this callback. NULL callback permits
 * unencrypted input/output only and never invokes a provider prompt; cbdata
 * is ignored in that case. File imports preserve the installed key on error.
 */
typedef int (*dssh_pem_password_cb)(char *buf, int size, int rwflag, void *userdata);

/* Global registration and key replacement use application-serialized setup;
 * complete them before any session-init attempt. Before freeze, serialize key
 * utilities with replacement, including work on other application threads.
 * Same-thread password-callback key replacement is allowed; key-file export
 * uses the native key selected on entry. After freeze, key reads/exports can
 * overlap with sessions and each other, with caller-coordinated destinations.
 * See the process-global setup contract at dssh_session_init(). */

/* Key exchange */
DSSH_PUBLIC int dssh_register_curve25519_sha256(void);
DSSH_PUBLIC int dssh_register_dh_gex_sha256(void);
DSSH_PUBLIC int dssh_register_sntrup761x25519_sha512(void);
DSSH_PUBLIC int dssh_register_mlkem768x25519_sha256(void);

/* Private-key save contract (all three builtin key families):
 * Save PEM by opening and overwriting the selected file itself. Validate a
 * regular, singly linked, effective-caller-owned target before changing it;
 * reject a final-component symbolic link/reparse point. New/final files are
 * private to the effective caller (POSIX mode 0600 or protected Windows
 * caller-SID ACL). An error may leave the destination empty or partial.
 * Existing file identity is retained; the caller coordinates the destination
 * directory/namespace throughout the operation and manages recovery copies. */

/* Host key algorithms */
/* Load or generate keys before the first dssh_session_init(). Subsequent
 * key replacement returns DSSH_ERROR_TOOLATE. Failed replacement preserves
 * the existing key. Public-key blobs are cached before key publication. */
DSSH_PUBLIC int     dssh_register_ssh_ed25519(void);
DSSH_PUBLIC int     dssh_ed25519_load_key_file(const char *path, dssh_pem_password_cb pw_cb, void *pw_cbdata);
DSSH_PUBLIC int     dssh_ed25519_save_key_file(const char *path, dssh_pem_password_cb pw_cb, void *pw_cbdata);
DSSH_PUBLIC int64_t dssh_ed25519_get_pub_str(char *buf, size_t bufsz);
DSSH_PUBLIC int     dssh_ed25519_save_pub_file(const char *path);
DSSH_PUBLIC int     dssh_ed25519_generate_key(void);
DSSH_PUBLIC int     dssh_register_rsa_sha2_256(void);
DSSH_PUBLIC int     dssh_rsa_sha2_256_load_key_file(const char *path, dssh_pem_password_cb pw_cb, void *pw_cbdata);
DSSH_PUBLIC int     dssh_rsa_sha2_256_save_key_file(const char *path, dssh_pem_password_cb pw_cb, void *pw_cbdata);
DSSH_PUBLIC int64_t dssh_rsa_sha2_256_get_pub_str(char *buf, size_t bufsz);
DSSH_PUBLIC int     dssh_rsa_sha2_256_save_pub_file(const char *path);
DSSH_PUBLIC int     dssh_rsa_sha2_256_generate_key(unsigned int bits);
DSSH_PUBLIC int     dssh_register_rsa_sha2_512(void);
DSSH_PUBLIC int     dssh_rsa_sha2_512_load_key_file(const char *path, dssh_pem_password_cb pw_cb, void *pw_cbdata);
DSSH_PUBLIC int     dssh_rsa_sha2_512_save_key_file(const char *path, dssh_pem_password_cb pw_cb, void *pw_cbdata);
DSSH_PUBLIC int64_t dssh_rsa_sha2_512_get_pub_str(char *buf, size_t bufsz);
DSSH_PUBLIC int     dssh_rsa_sha2_512_save_pub_file(const char *path);
DSSH_PUBLIC int     dssh_rsa_sha2_512_generate_key(unsigned int bits);

/* Encryption */
DSSH_PUBLIC int dssh_register_aes256_ctr(void);
DSSH_PUBLIC int dssh_register_aes128_cbc(void);
DSSH_PUBLIC int dssh_register_none_enc(void);

/* MAC */
DSSH_PUBLIC int dssh_register_hmac_sha2_256(void);
DSSH_PUBLIC int dssh_register_hmac_sha2_512(void);
DSSH_PUBLIC int dssh_register_none_mac(void);

/* Compression */
DSSH_PUBLIC int dssh_register_none_comp(void);

/*
 * Set the opaque context pointer for a registered key algorithm.
 * Called by key algorithm modules after generating or loading a key.
 * Must be called before dssh_session_init() -- returns DSSH_ERROR_TOOLATE
 * if any session has been created (the global registry is read
 * concurrently by active sessions during KEX).
 * Returns 0 on success, DSSH_ERROR_INIT if the algorithm is not registered.
 */
DSSH_PUBLIC int dssh_key_algo_set_ctx(const char *name, void *ctx);

/*
 * Set borrowed process-lifetime configuration for a registered KEX algorithm.
 * This becomes kctx->config and the initializer's config argument; per-session
 * state is created/reset by that module's init callback and cleaned by its
 * cleanup callback. Neither callback owns this global configuration.
 * Must be called before dssh_session_init() -- returns DSSH_ERROR_TOOLATE
 * if any session has been created (the global registry is read
 * concurrently by active sessions during KEX).
 * Returns 0 on success, DSSH_ERROR_INIT if the algorithm is not registered.
 */
DSSH_PUBLIC int dssh_kex_set_ctx(const char *name, void *ctx);

#ifdef __cplusplus
}
#endif

#endif   // ifndef DSSH_ALGORITHMS_H
