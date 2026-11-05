/*
 * kex/mlkem768x25519-sha256-botan.c -- Registration (Botan3).
 */

#include <stdlib.h>
#include <string.h>

#include "deucessh-kex.h"
#include "hybrid-pq-kex-ops.h"
#include "deucessh.h"

#define KEX_NAME     "mlkem768x25519-sha256"
#define KEX_NAME_LEN 21

extern int  dssh_botan_mlkem768x25519_handler(const struct dssh_kex_context *kctx, struct dssh_kex_result *out);

DSSH_PUBLIC int
dssh_register_mlkem768x25519_sha256(void)
{
	struct dssh_kex_s *kex = malloc(sizeof(*kex) + KEX_NAME_LEN + 1);

	if (kex == NULL)
		return DSSH_ERROR_ALLOC;
	kex->next      = NULL;
	kex->init      = mlkem768x25519_init;
	kex->handler   = dssh_botan_mlkem768x25519_handler;
	kex->cleanup   = hybrid_pq_cleanup;
	kex->flags     = DSSH_KEX_FLAG_NEEDS_SIGNATURE_CAPABLE | DSSH_KEX_FLAG_K_ENCODING_STRING;
	kex->hash_name = "SHA-256";
	kex->config       = NULL;
	memcpy(kex->name, KEX_NAME, KEX_NAME_LEN + 1);
	int ret = dssh_transport_register_kex(kex);
	if (ret < 0)
		free(kex);
	return ret;
}
