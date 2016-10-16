/*
 * ARM64 kexec binary image support.
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

int image_arm64_probe(const char *kernel_buf, off_t kernel_size)
{
	const struct arm64_image_header *h;

	if (kernel_size < sizeof(struct arm64_image_header))
		return -EINVAL;

	h = (const struct arm64_image_header *)(kernel_buf);

	if (!arm64_header_check_magic(h))
		return -1;

	dbgprintf("%s: PE format: %s\n", __func__,
		(arm64_header_check_pe_sig(h) ? "yes" : "no"));

	return 0;
}

static unsigned long long get_kernel_text_sym(void)
{
	const char *kallsyms = "/proc/kallsyms";
	const char *text = "_text";
	char sym[128];
	char line[128];
	FILE *fp;
	unsigned long long vaddr;
	char type;

	fp = fopen(kallsyms, "r");	if (!fp) {
		fprintf(stderr, "Cannot open %s\n", kallsyms);
		return 0;
	}

	while(fgets(line, sizeof(line), fp) != NULL) {
#if __ANDROID__
		if (sscanf(line, "%llx %c %s", &vaddr, &type, sym) != 3)
#else
		if (sscanf(line, "%Lx %c %s", &vaddr, &type, sym) != 3)
#endif
			continue;
		if (strcmp(sym, text) == 0) {
			dbgprintf("kernel symbol %s vaddr = %16llx\n", text, vaddr);
			return vaddr;
		}
	}

	fprintf(stderr, "Cannot get kernel %s symbol address\n", text);
	return 0;
}

static unsigned long long get_kernel_page_offset(void)
{
	unsigned long long text_sym_addr = get_kernel_text_sym();
	unsigned long long text_page_offset =
		text_sym_addr & 0xFFFFFFFFFFE00000;

	if(arm64_opts.page_offset) {
		if (text_page_offset != arm64_opts.page_offset)
			dbgprintf("User page offset %lx did not match with text page offset %llx\n",
					arm64_opts.page_offset, text_page_offset); 
		return arm64_opts.page_offset;
	} else if(text_page_offset) {
		dbgprintf("text page offset is %llx\n", text_page_offset);
		return text_page_offset;
	} else {
		return ARM64_DEFAULT_PAGE_OFFSET;
	}
}

int image_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, const char *kernel_compressed_buf,
	off_t kernel_compressed_size, struct kexec_info *info)
{
	int result;
	const struct arm64_image_header *h;
	char *header_option = NULL;

	h = (const struct arm64_image_header *)(kernel_buf);

	if (arm64_process_image_header(h))
		return -1;

	arm64_mem.page_offset = get_kernel_page_offset();

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		result = load_crashdump_segments(info, &header_option);

		if (result) {
			fprintf(stderr, "kexec: load crashdump segments failed.\n");
			return -1;
		}
		info->entry = get_crash_entry();
	} else if (!info->entry) {
		result = parse_iomem_single("Kernel code\n", &info->entry, NULL);

		if (result) {
			fprintf(stderr, "kexec: Could not get kernel code address.\n");
			return -1;
		}
	}

	/* Add kernel */
	add_segment_phys_virt(info, kernel_buf, kernel_size,
			info->entry, kernel_size, 0);

	result = arm64_load_other_segments(info, (unsigned long)info->entry,
		header_option, kernel_compressed_buf, kernel_compressed_size);

	if (header_option)
		free(header_option);

	return result;
}

void image_arm64_usage(void)
{
	printf(
"     An arm64 binary Image file, big or little endian.\n\n"
"     --page-offset         Kernel page-offset for binary image load.\n\n");
}
