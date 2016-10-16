/*
 * ARM64 kexec.
 */

#if !defined(KEXEC_ARM64_H)
#define KEXEC_ARM64_H

#include <stdbool.h>
#include <sys/types.h>

#include "image-header.h"
#include "kexec.h"

#define KEXEC_SEGMENT_MAX 16

#define BOOT_BLOCK_VERSION 17
#define BOOT_BLOCK_LAST_COMP_VERSION 16
#define COMMAND_LINE_SIZE 2048

#define ARM64_DEFAULT_PAGE_OFFSET 0xfffffe0000000000

int elf_arm64_probe(const char *kernel_buf, off_t kernel_size);
int elf_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, const char *kernel_compressed_buf,
	off_t kernel_compressed_size, struct kexec_info *info);
void elf_arm64_usage(void);

int image_arm64_probe(const char *kernel_buf, off_t kernel_size);
int image_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, const char *kernel_compressed_buf,
	off_t kernel_compressed_size, struct kexec_info *info);
void image_arm64_usage(void);

int gzip_image_arm64_probe(const char *kernel_buf, off_t kernel_size);
int gzip_image_arm64_load(int argc, char **argv, const char *kernel_buf,
	off_t kernel_size, const char *kernel_compressed_buf,
	off_t kernel_compressed_size, struct kexec_info *info);
void gzip_image_arm64_usage(void);

off_t initrd_base;
off_t initrd_size;

/**
 * struct arm64_mem - Memory layout info.
 */

struct arm64_mem {
	uint64_t text_offset;
	uint64_t image_size;
	uint64_t page_offset;
	uint64_t memstart;
};

extern struct arm64_mem arm64_mem;

int arm64_process_image_header(const struct arm64_image_header *h);
int arm64_load_other_segments(struct kexec_info *info,
	uint64_t kernel_entry, char *option, const char *kernel_buf,
	off_t kernel_size);

#endif
