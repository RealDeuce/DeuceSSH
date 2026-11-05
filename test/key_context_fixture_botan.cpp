#include <new>
#include "key_algo/key-context-botan.h"

struct dssh_key_algo_ctx;
extern "C" dssh_key_algo_ctx *
test_empty_key_context(void)
{
	auto *context = new (std::nothrow) dssh_botan_key_context{};
	auto *opaque = reinterpret_cast<dssh_key_algo_ctx *>(context);
	return opaque;
}
