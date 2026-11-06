/* Private native C++ context; never included by installed module headers. */
#ifndef DSSH_KEY_CONTEXT_BOTAN_H
#define DSSH_KEY_CONTEXT_BOTAN_H

#include <memory>
#include <botan/pk_keys.h>
#include "signature-result.h"

struct dssh_botan_key_context {
	struct dssh_signature_pool *signatures = nullptr;
	/* A file operation retains its target across an application password callback. */
	std::shared_ptr<Botan::Private_Key> privkey;
	uint8_t *pub_blob = nullptr;
	size_t pub_blob_len = 0;
};

#endif
