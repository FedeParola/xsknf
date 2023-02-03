#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xsknf.h>

static void __exit_with_error(int error, const char *file, const char *func,
		int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));

	xsknf_cleanup();

	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, \
		__LINE__)

void hex_dump(void *pkt, size_t length);