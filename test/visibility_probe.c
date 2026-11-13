#include "visibility_probe.h"

DSSH_PRIVATE int
dssh_visibility_private(void)
{
	return 42;
}

DSSH_PUBLIC int
dssh_visibility_probe(void)
{
	return dssh_visibility_private();
}
