/*
 * ARM64 kexec gzip binary image support.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libfdt.h>
#include <stdlib.h>

#include "crashdump-arm64.h"
#include "dt-ops.h"
#include "image-header.h"
#include "kexec-arm64.h"
#include "fs2dt.h"
#include "kexec-syscall.h"
#include "arch/options.h"

int gzip_image_arm64_probe(const char *kernel_buf, off_t kernel_size)
{
	fprintf(stderr, "kexec: arm64 binary Image files are currently NOT SUPPORTED.\n");
	return -1;
}


int gzip_image_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, const char *kernel_compressed_buf,
	off_t kernel_compressed_size, struct kexec_info *info)
{
	return -ENOSYS;
}

void gzip_image_arm64_usage(void)
{
	printf(
"     A gzip compressed arm64 binary Image.gz file, big or little endian.\n"
"     This file type is currently NOT SUPPORTED.\n\n"
"     --page-offset         Kernel page-offset for binary image load.\n\n"
	);
}
