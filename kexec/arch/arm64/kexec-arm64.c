/*
 * ARM64 kexec.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libfdt.h>
#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>

#include <linux/elf.h>

#include "dt-ops.h"
#include "kexec.h"
#include "crashdump.h"
#include "crashdump-arm64.h"
#include "kexec-arm64.h"
#include "fs2dt.h"
#include "kexec-syscall.h"
#include "arch/options.h"

/* Global varables the core kexec routines expect. */

unsigned char reuse_initrd;

off_t initrd_base;
off_t initrd_size;

const struct arch_map_entry arches[] = {
	{ "aarch64", KEXEC_ARCH_ARM64 },
	{ "aarch64_be", KEXEC_ARCH_ARM64 },
	{ NULL, 0 },
};

/* arm64 global varables. */

struct arm64_opts arm64_opts;
struct arm64_mem arm64_mem = {
	.memstart = UINT64_MAX,
};

static void set_memstart(uint64_t v)
{
	if (arm64_mem.memstart == UINT64_MAX || v < arm64_mem.memstart)
		arm64_mem.memstart = v;
}

static int check_memstart(void)
{
	return arm64_mem.memstart != UINT64_MAX;
}

void arch_usage(void)
{
	dbgprintf("Build time: %s : %s\n", __DATE__, __TIME__);
	printf(arm64_opts_usage);
}

int arch_process_options(int argc, char **argv)
{
	static const char short_options[] = KEXEC_OPT_STR "";
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0 }
	};
	int opt;
	const char *append = NULL;
	char *tmp_cmdline = NULL;

	for (opt = 0; opt != -1; ) {
		opt = getopt_long(argc, argv, short_options, options, 0);

		switch (opt) {
		case OPT_APPEND:
			append = optarg;
			break;
		case OPT_REUSE_CMDLINE:
			tmp_cmdline = get_command_line();
			break;
		case OPT_DTB:
			arm64_opts.dtb = optarg;
			break;
		case OPT_INITRD:
			arm64_opts.initrd = optarg;
			break;
		case OPT_PORT:
			arm64_opts.port = strtoull(optarg, NULL, 0);
			break;
		case OPT_PAGE_OFFSET:
			arm64_opts.page_offset = strtoull(optarg, NULL, 0);
			break;
		default:
			break; /* Ignore core and unknown options. */
		}
	}

	arm64_opts.command_line = concat_cmdline(tmp_cmdline, append);
	kexec_debug = 1; // FIXME: for debugging only.

	dbgprintf("%s:%d: command_line: %s\n", __func__, __LINE__,
		arm64_opts.command_line);
	dbgprintf("%s:%d: initrd: %s\n", __func__, __LINE__,
		arm64_opts.initrd);
	dbgprintf("%s:%d: dtb: %s\n", __func__, __LINE__, arm64_opts.dtb);
	dbgprintf("%s:%d: port: 0x%" PRIx64 "\n", __func__, __LINE__,
		arm64_opts.port);

	return 0;
}

struct dtb {
	char *buf;
	off_t size;
	const char *name;
	const char *path;
};

static void dump_reservemap(const struct dtb *dtb)
{
	int i;

	for (i = 0; ; i++) {
		uint64_t address;
		uint64_t size;

		fdt_get_mem_rsv(dtb->buf, i, &address, &size);

		if (!size)
			break;

		dbgprintf("%s: %s {%" PRIx64 ", %" PRIx64 "}\n", __func__,
			dtb->name, address, size);
	}
}

enum cpu_enable_method {
	cpu_enable_method_unknown,
	cpu_enable_method_psci,
	cpu_enable_method_spin_table,
};

/**
 * struct cpu_properties - Various properties from a device tree cpu node.
 *
 * These properties will be valid over a dtb re-size.
 */

struct cpu_properties {
	uint64_t hwid;
	uint64_t cpu_release_addr;
	char node_path[128];
	char enable_method[128];
	enum cpu_enable_method type;
};

/**
 * read_cpu_properties - Helper to read the device tree cpu properties.
 */

static int read_cpu_properties(struct cpu_properties *cp,
	const struct dtb *dtb, int node_offset, unsigned int address_cells)
{
	int result;
	const void *data;

	result = fdt_get_path(dtb->buf, node_offset, cp->node_path,
		sizeof(cp->node_path));

	if (result < 0) {
		fprintf(stderr, "kexec: %s:%d: %s: fdt_get_path failed: %s\n",
			__func__, __LINE__, dtb->name, fdt_strerror(result));
		return result;
	}

	data = fdt_getprop(dtb->buf, node_offset, "device_type", &result);

	if (!data) {
		dbgprintf("%s: %s (%s) read device_type failed: %s\n",
			__func__, dtb->name, cp->node_path,
			fdt_strerror(result));
		return result == -FDT_ERR_NOTFOUND ? 0 : result;
	}

	if (strcmp(data, "cpu")) {
		dbgprintf("%s: %s (%s): '%s'\n", __func__, dtb->name,
			cp->node_path, (const char *)data);
		return 0;
	}

	data = fdt_getprop(dtb->buf, node_offset, "reg", &result);

	if (!data) {
		fprintf(stderr, "kexec: %s:%d: read hwid failed: %s\n",
			__func__, __LINE__, fdt_strerror(result));
		return result;
	}

	cp->hwid = (address_cells == 1) ? fdt32_to_cpu(*(uint32_t *)data) :
		fdt64_to_cpu(*(uint64_t *)data);

	data = fdt_getprop(dtb->buf, node_offset, "enable-method", &result);

	if (!data) {
		fprintf(stderr,
			"kexec: %s:%d: read enable_method failed: %s\n",
			__func__, __LINE__, fdt_strerror(result));
		return result;
	}

	strncpy(cp->enable_method, data, sizeof(cp->enable_method));
	cp->enable_method[sizeof(cp->enable_method) - 1] = 0;

	if (!strcmp(cp->enable_method, "psci")) {
		cp->type = cpu_enable_method_psci;
		return 1;
	}

	if (strcmp(cp->enable_method, "spin-table")) {
		cp->type = cpu_enable_method_unknown;
		return -1;
	}

	cp->type = cpu_enable_method_spin_table;

	data = fdt_getprop(dtb->buf, node_offset, "cpu-release-addr", &result);

	if (!data) {
		fprintf(stderr, "kexec: %s:%d: "
			"read cpu-release-addr failed: %s\n",
			__func__, __LINE__, fdt_strerror(result));
		return result;
	}

	cp->cpu_release_addr = fdt64_to_cpu(*(uint64_t *)data);

	return 1;
}

static int check_cpu_properties(const struct cpu_properties *cp_1,
	const struct cpu_properties *cp_2)
{
	assert(cp_1->hwid == cp_2->hwid);

	if (cp_1->type != cp_2->type) {
		fprintf(stderr,
			"%s:%d: hwid-%" PRIx64 ": "
			"Error: Different enable methods: %s -> %s\n",
			__func__, __LINE__, cp_1->hwid, cp_1->enable_method,
			cp_2->enable_method);
		return -EINVAL;
	}

	if (cp_1->type != cpu_enable_method_psci
		&& cp_1->type != cpu_enable_method_spin_table) {
		fprintf(stderr,
			"%s:%d: hwid-%" PRIx64 ": "
			"Warning: Unknown enable method: %s.\n",
			__func__, __LINE__, cp_1->hwid,
			cp_1->enable_method);
	}

	if (cp_1->type == cpu_enable_method_spin_table) {
		if (cp_1->cpu_release_addr != cp_2->cpu_release_addr) {
			fprintf(stderr, "%s:%d: hwid-%" PRIx64 ": "
				"Error: Different cpu-release-addr: "
				"%" PRIx64 " -> %" PRIx64 ".\n",
				__func__, __LINE__,
				cp_1->hwid,
				cp_2->cpu_release_addr,
				cp_1->cpu_release_addr);
			return -EINVAL;
		}
	}

	dbgprintf("%s: hwid-%" PRIx64 ": OK\n", __func__, cp_1->hwid);

	return 0;
}

struct cpu_info {
	unsigned int cpu_count;
	struct cpu_properties *cp;
};

static int read_cpu_info(struct cpu_info *info, const struct dtb *dtb)
{
	int i;
	int offset;
	int result;
	int depth;
	const void *data;
	unsigned int address_cells;

	offset = fdt_subnode_offset(dtb->buf, 0, "cpus");

	if (offset < 0) {
		fprintf(stderr, "kexec: %s:%d: read cpus node failed: %s\n",
			__func__, __LINE__, fdt_strerror(offset));
		return offset;
	}

	data = fdt_getprop(dtb->buf, offset, "#address-cells", &result);

	if (!data) {
		fprintf(stderr,
			"kexec: %s:%d: read cpus address-cells failed: %s\n",
			__func__, __LINE__, fdt_strerror(result));
		return result;
	}

	address_cells = fdt32_to_cpu(*(uint32_t *)data);

	if (address_cells < 1 || address_cells > 2) {
		fprintf(stderr,
			"kexec: %s:%d: bad cpus address-cells value: %u\n",
			__func__, __LINE__, address_cells);
		return -EINVAL;
	}

	for (i = 0, depth = 0; ; i++) {
		info->cp = realloc(info->cp, (i + 1) * sizeof(*info->cp));

		if (!info->cp) {
			fprintf(stderr, "kexec: %s:%d: malloc failed: %s\n",
				__func__, __LINE__, fdt_strerror(offset));
			result = -ENOMEM;
			goto on_error;
		}

next_node:
		memset(&info->cp[i], 0, sizeof(*info->cp));

		offset = fdt_next_node(dtb->buf, offset, &depth);

		if (offset < 0) {
			fprintf(stderr, "kexec: %s:%d: "
				"read cpu node failed: %s\n", __func__,
				__LINE__, fdt_strerror(offset));
			result = offset;
			goto on_error;
		}

		if (depth != 1)
			break;

		result = read_cpu_properties(&info->cp[i], dtb, offset,
			address_cells);

		if (result == 0)
			goto next_node;

		if (result < 0)
			goto on_error;

		if (info->cp[i].type == cpu_enable_method_psci)
			dbgprintf("%s: %s cpu-%d (%s): hwid-%" PRIx64 ", '%s'\n",
				__func__, dtb->name, i, info->cp[i].node_path,
				info->cp[i].hwid,
				info->cp[i].enable_method);
		else
			dbgprintf("%s: %s cpu-%d (%s): hwid-%" PRIx64 ", '%s', "
				"cpu-release-addr %" PRIx64 "\n",
				__func__, dtb->name, i, info->cp[i].node_path,
				info->cp[i].hwid,
				info->cp[i].enable_method,
				info->cp[i].cpu_release_addr);
	}

	info->cpu_count = i;
	return 0;

on_error:
	free(info->cp);
	info->cp = NULL;
	return result;
}

static int check_cpu_nodes(const struct dtb *dtb_1, const struct dtb *dtb_2)
{
	int result;
	unsigned int cpu_1;
	struct cpu_info info_1;
	struct cpu_info info_2;
	unsigned int to_process;

	memset(&info_1, 0, sizeof(info_1));
	memset(&info_2, 0, sizeof(info_2));

	result = read_cpu_info(&info_1, dtb_1);

	if (result)
		goto on_exit;

	result = read_cpu_info(&info_2, dtb_2);

	if (result)
		goto on_exit;

	to_process = info_1.cpu_count < info_2.cpu_count
		? info_1.cpu_count : info_2.cpu_count;

	for (cpu_1 = 0; cpu_1 < info_1.cpu_count; cpu_1++) {
		struct cpu_properties *cp_1 = &info_1.cp[cpu_1];
		unsigned int cpu_2;

		for (cpu_2 = 0; cpu_2 < info_2.cpu_count; cpu_2++) {
			struct cpu_properties *cp_2 = &info_2.cp[cpu_2];

			if (cp_1->hwid != cp_2->hwid)
				continue;

			to_process--;

			result = check_cpu_properties(cp_1, cp_2);

			if (result)
				goto on_exit;
		}
	}

	if (to_process) {
		fprintf(stderr, "kexec: %s:%d: Warning: "
			"Failed to process %u CPUs.\n",
			__func__, __LINE__, to_process);
		result = -EINVAL;
		goto on_exit;
	}

on_exit:
	free(info_1.cp);
	free(info_2.cp);
	return result;
}

static int set_bootargs(struct dtb *dtb, const char *command_line)
{
	int result;

	if (!command_line || !command_line[0])
		return 0;

	result = dtb_set_bootargs(&dtb->buf, &dtb->size, command_line);

	if (result)
		fprintf(stderr,
			"kexec: Set device tree bootargs failed.\n");

	return result;
}

static int read_proc_dtb(struct dtb *dtb, const char *command_line)
{
	int result;
	struct stat s;
	static const char path[] = "/proc/device-tree";

	result = stat(path, &s);

	if (result) {
		dbgprintf("%s: %s\n", __func__, strerror(errno));
		return -1;
	}

	dtb->path = path;
	create_flatten_tree((char **)&dtb->buf, &dtb->size,
		(command_line && command_line[0]) ? command_line : NULL);

	return 0;
}

static int read_sys_dtb(struct dtb *dtb, const char *command_line)
{
	int result;
	struct stat s;
	static const char path[] = "/sys/firmware/fdt";

	result = stat(path, &s);

	if (result) {
		dbgprintf("%s: %s\n", __func__, strerror(errno));
		return -1;
	}

	dtb->path = path;
	dtb->buf = slurp_file("/sys/firmware/fdt", &dtb->size);

	return set_bootargs(dtb, command_line);
}

#define DTB_PAD_SIZE            1024
#define INVALID_SOC_REV_ID 0xFFFFFFFF

struct msm_id
{
	uint32_t platform_id;
	uint32_t hardware_id;
	uint32_t soc_rev;
};

static uint32_t dtb_compatible(void *dtb, struct msm_id *devid)
{
	int root_offset;
	const void *prop;
	struct msm_id msm_id;
	int len;

	root_offset = fdt_path_offset(dtb, "/");
	if (root_offset < 0)
		return 0;

	prop = fdt_getprop(dtb, root_offset, "qcom,msm-id", &len);
	if (!prop || len <= 0) {
		printf("DTB: qcom,msm-id entry not found\n");
		return 0;
	} else if (len < (int)sizeof(struct msm_id)) {
		printf("DTB: qcom,msm-id entry size mismatch (%d != %d)\n",
			len, sizeof(struct msm_id));
		return 0;
	}
	msm_id.platform_id = fdt32_to_cpu(((const struct msm_id *)prop)->platform_id);
	msm_id.hardware_id = fdt32_to_cpu(((const struct msm_id *)prop)->hardware_id);
	msm_id.soc_rev = fdt32_to_cpu(((const struct msm_id *)prop)->soc_rev);

	if (msm_id.platform_id != devid->platform_id ||
		msm_id.hardware_id != devid->hardware_id) {
		return INVALID_SOC_REV_ID;
	}

	return msm_id.soc_rev;
}

static int get_appended_dtb(const char *kernel, off_t kernel_len, struct dtb *dtb_struct)
{
	char *kernel_end = (char*)kernel + kernel_len;
	char *dtb;
	FILE *f;
	struct msm_id devid;
	char *bestmatch_tag = NULL;
	uint32_t bestmatch_tag_size;
	uint32_t bestmatch_soc_rev_id = INVALID_SOC_REV_ID;

	f = fopen("/proc/device-tree/qcom,msm-id", "r");
	if(!f)
	{
		fprintf(stderr, "DTB: Couldn't open /proc/device-tree/qcom,msm-id!\n");
		return 0;
	}

	fread(&devid, sizeof(struct msm_id), 1, f);
	fclose(f);

	devid.platform_id = fdt32_to_cpu(devid.platform_id);
	devid.hardware_id = fdt32_to_cpu(devid.hardware_id);
	devid.soc_rev = fdt32_to_cpu(devid.soc_rev);

	printf("DTB: platform %u hw %u soc 0x%x\n", devid.platform_id, devid.hardware_id, devid.soc_rev);

	// scan the compressed kernel buf for dtb
	dtb = kernel;
	while(dtb + sizeof(struct fdt_header) < kernel_end)
	{

		int ret = fdt_check_header(dtb);
		if (ret != 0) {
			dtb++;
			continue;
		} else {
			printf("DTB: found dtb header at %zu\n", dtb);
		}

		uint32_t dtb_soc_rev_id;
		uint32_t dtb_size;

		// stop if we go over kernel_end
		if (dtb + fdt_totalsize(dtb) > kernel_end) {
			printf("DTB: went over kernel_end, BREAK!\n");
			break;
		}
		dtb_size = fdt_totalsize(dtb);
		dtb_soc_rev_id = dtb_compatible(dtb, &devid);
		if (dtb_soc_rev_id == devid.soc_rev) {
			dtb_struct->buf = xmalloc(dtb_size);
			memcpy(dtb_struct->buf, dtb, dtb_size);
			dtb_struct->size = dtb_size;
			printf("DTB: match 0x%x, my id 0x%x, len %u\n", dtb_soc_rev_id, devid.soc_rev, dtb_size);
			return 1;
		} else if ((dtb_soc_rev_id != INVALID_SOC_REV_ID) &&
				   (dtb_soc_rev_id < devid.soc_rev)) {
			/* if current bestmatch is less than new dtb_soc_rev_id then update
			   bestmatch_tag */
			if((bestmatch_soc_rev_id == INVALID_SOC_REV_ID) ||
			   (bestmatch_soc_rev_id < dtb_soc_rev_id)) {
				bestmatch_tag = dtb;
				bestmatch_tag_size = dtb_size;
				bestmatch_soc_rev_id = dtb_soc_rev_id;
			}
		}

		/* goto the next device tree if any */
		dtb += dtb_size;
	}
	if(bestmatch_tag) {
		printf("DTB: bestmatch 0x%x, my id 0x%x\n", bestmatch_soc_rev_id, devid.soc_rev);
		dtb_struct->buf = xmalloc(bestmatch_tag_size);
		memcpy(dtb_struct->buf, bestmatch_tag, bestmatch_tag_size);
		dtb_struct->size = bestmatch_tag_size;
		return 1;
	}
	return 0;
}

int dtb_add_memory_reg(void *dtb_buf, int off)
{
	FILE *f;
	uint32_t reg;
	int res;

	f = fopen("/proc/device-tree/memory/reg", "r");
	if(!f)
	{
		fprintf(stderr, "DTB: Failed to open /proc/device-tree/memory/reg!\n");
		return 0;
	}

	fdt_delprop(dtb_buf, off, "reg");

	while(fread(&reg, sizeof(reg), 1, f) == 1)
		fdt_appendprop(dtb_buf, off, "reg", &reg, sizeof(reg));

	fclose(f);
	return 1;
}

int read_appended_dtb(const char *kernel_buf, off_t kernel_size, struct dtb *dtb, const char *command_line) {

	if(get_appended_dtb(kernel_buf, kernel_size, dtb))
	{
		int ret, off;

		printf("DTB: Using DTB appended to zImage\n");
		dtb->size = fdt_totalsize(dtb->buf) + DTB_PAD_SIZE;
		dtb->buf = xrealloc(dtb->buf, dtb->size);
		ret = fdt_open_into(dtb->buf, dtb->buf, dtb->size);
		if(ret)
			die("DTB: fdt_open_into failed");
			ret = fdt_path_offset(dtb->buf, "/memory");
		if (ret >= 0)
			dtb_add_memory_reg(dtb->buf, ret);
		else
			fprintf(stderr, "DTB: Could not find memory node.\n");
		// this shouldn't be used, but we set it for completeness
		dtb->path = "appended";
		ret = set_bootargs(dtb, command_line);
		return ret;
	} else {
		printf("DTB: appended DTB not detected\n");
	}

	return 1;
}

static int read_1st_dtb(struct dtb *dtb, const char *command_line, const char *kernel_buf, off_t kernel_size)
{
	int result;

	result = read_appended_dtb(kernel_buf, kernel_size, dtb, command_line);
	if (!result)
		goto on_success;

	result = read_sys_dtb(dtb, command_line);

	if (!result)
		goto on_success;

	result = read_proc_dtb(dtb, command_line);

	if (!result)
		goto on_success;

	dbgprintf("%s: not found\n", __func__);
	return -1;

on_success:
	dbgprintf("%s: found %s\n", __func__, dtb->path);
	return 0;
}

static int setup_2nd_dtb(char *command_line, struct dtb *dtb_2)
{
	int result;

	result = fdt_check_header(dtb_2->buf);

	if (result) {
		fprintf(stderr, "kexec: Invalid 2nd device tree.\n");
		return -EINVAL;
	}

	result = set_bootargs(dtb_2, command_line);

	dump_reservemap(dtb_2);

	return result;
}

static uint64_t read_sink(const char *command_line)
{
	uint64_t v;
	const char *p;

	if (arm64_opts.port)
		return arm64_opts.port;

#if defined(ARM64_DEBUG_PORT)
	return (uint64_t)(ARM64_DEBUG_PORT);
#endif
	if (!command_line)
		return 0;

	p = strstr(command_line, "earlyprintk=");

	if (!p)
		return 0;

	while (*p != ',')
		p++;

	p++;

	while (isspace(*p))
		p++;

	if (*p == 0)
		return 0;

	errno = 0;

	v = strtoull(p, NULL, 0);

	if (errno)
		return 0;

	return v;
}

/**
 * arm64_load_other_segments - Prepare the dtb, initrd and purgatory segments.
 */

int arm64_load_other_segments(struct kexec_info *info,
	uint64_t kernel_entry, char *option,const char *kernel_buf,
	off_t kernel_size)
{
	int result;
	uint64_t dtb_base;
	unsigned long hole_min, hole_max;
	uint64_t purgatory_sink;
	struct mem_ehdr ehdr;
	char *initrd_buf = NULL;
	struct dtb dtb_1 = {.name = "dtb_1"};
	struct dtb dtb_2 = {.name = "dtb_2"};

	char command_line[COMMAND_LINE_SIZE] = "";

	dbgprintf("%s:%d: add '%s' to command line\n", __func__, __LINE__,
		option);

	if (arm64_opts.command_line) {
		strncpy(command_line, arm64_opts.command_line,
			sizeof(command_line));
		command_line[sizeof(command_line) - 1] = 0;
	}

	if (option && option[0])
		strcat(command_line, option);

	purgatory_sink = read_sink(command_line);
	dbgprintf("%s:%d: purgatory sink: 0x%" PRIx64 "\n", __func__, __LINE__,
		purgatory_sink);

	if (arm64_opts.dtb) {
		dtb_2.buf = slurp_file(arm64_opts.dtb, &dtb_2.size);
		assert(dtb_2.buf);
	}

	result = read_1st_dtb(&dtb_1, command_line, kernel_buf, kernel_size);

	if (result && !arm64_opts.dtb) {
		fprintf(stderr, "kexec: Error: No device tree available.\n");
		return result;
	}

	if (result && arm64_opts.dtb) {
		// skip header if loading dtb.img
		dtb_2.buf = dtb_2.buf+2048;
		dtb_1 = dtb_2;
	}
	else if (!result && !arm64_opts.dtb)
		dtb_2 = dtb_1;

	result = setup_2nd_dtb(command_line, &dtb_2);

	if (result)
		return result;
	
	result =  check_cpu_nodes(&dtb_1, &dtb_2);

	if (result)
		return result;

	/*
	 * Put the DTB after the kernel with an alignment of 128 KiB, giving
	 * a max supported DTB size of 128 KiB (worst case).  Also add 2 KiB
	 * to the DTB size for any DTB growth.
	 */

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		hole_min = crash_reserved_mem.start + arm64_mem.text_offset
				+ arm64_mem.image_size;
		hole_max = crash_reserved_mem.end;
	} else {
		hole_min = arm64_mem.memstart + arm64_mem.text_offset
				+ arm64_mem.image_size;
		hole_max = ULONG_MAX;
	}

	if (arm64_opts.initrd) {
		initrd_buf = slurp_file(arm64_opts.initrd, &initrd_size);

		if (!initrd_buf)
			fprintf(stderr, "kexec: Empty ramdisk file.\n");
		else {
			/* Put the initrd after the DTB with an alignment of
			 * page size. */

#if 1
			initrd_base = 0x02700000; // from lk/project/msm8994.mk
			add_segment_phys_virt(info, initrd_buf,
				initrd_size, initrd_base, initrd_size, 0);
#else
			initrd_base = add_buffer_phys_virt(info, initrd_buf,
				initrd_size, initrd_size, 0,
				hole_min, hole_max, 1, 0);
#endif

			dbgprintf("initrd: base %lx, size %lxh (%ld)\n",
				initrd_base, initrd_size, initrd_size);

			if (initrd_base == ULONG_MAX)
				return -ENOMEM;

			result = dtb_set_initrd((char **)&dtb_2.buf,
				&dtb_2.size, initrd_base,
				initrd_base + initrd_size);

			if (result)
				return result;
		}
	}

#if 1
	dtb_base = 0x02500000; // from lk/project/msm8994.mk
	add_segment_phys_virt(info, dtb_2.buf, dtb_2.size,
		dtb_base, dtb_2.size, 0);
#else
	dtb_base = add_buffer_phys_virt(info, dtb_2.buf, dtb_2.size, dtb_2.size,
			128UL * 1024, hole_min, hole_max, 1, 0);
#endif

	dbgprintf("dtb:    base %lx, size %lxh (%ld)\n", dtb_base, dtb_2.size,
		dtb_2.size);

	if (dtb_base == ULONG_MAX)
		return -ENOMEM;

#if 0

	result = build_elf_rel_info(purgatory, purgatory_size, &ehdr, 0);

	if (result < 0) {
		fprintf(stderr, "%s: Error: "
			"build_elf_rel_info failed.\n", __func__);
		return -EBADF;
	}

	elf_rel_build_load(info, &info->rhdr, purgatory, purgatory_size,
		hole_min, hole_max, 1, 0);

	info->entry = (void *)elf_rel_get_addr(&info->rhdr, "purgatory_start");

	elf_rel_set_symbol(&info->rhdr, "arm64_sink", &purgatory_sink,
		sizeof(purgatory_sink));

	elf_rel_set_symbol(&info->rhdr, "arm64_kernel_entry", &kernel_entry,
		sizeof(kernel_entry));

	elf_rel_set_symbol(&info->rhdr, "arm64_dtb_addr", &dtb_base,
		sizeof(dtb_base));

#endif

	return 0;
}

unsigned long virt_to_phys(unsigned long v)
{
	unsigned long p;

	assert(arm64_mem.page_offset);
	assert(check_memstart());

	p = v - arm64_mem.page_offset + arm64_mem.memstart;

	dbgprintf("%s: %016lx -> %016lx\n", __func__, v, p);
	return p;
}

unsigned long phys_to_virt(struct crash_elf_info *UNUSED(elf_info),
	unsigned long p)
{
	unsigned long v;

	assert(arm64_mem.page_offset);
	assert(check_memstart());

	v = p - arm64_mem.memstart + arm64_mem.page_offset;

	dbgprintf("%s: %016lx -> %016lx\n", __func__, p, v);
	return v;
}

void add_segment(struct kexec_info *info, const void *buf, size_t bufsz,
	unsigned long base, size_t memsz)
{
	add_segment_phys_virt(info, buf, bufsz, base, memsz, 1);
}

int arm64_process_image_header(const struct arm64_image_header *h)
{
#if !defined(KERNEL_IMAGE_SIZE)
# define KERNEL_IMAGE_SIZE (768 * 1024)
#endif

	if (!arm64_header_check_magic(h))
		return -EINVAL;

	if (h->image_size) {
		arm64_mem.text_offset = le64_to_cpu(h->text_offset);
		arm64_mem.image_size = le64_to_cpu(h->image_size);
	} else {
		/* For 3.16 and older kernels. */
		arm64_mem.text_offset = 0x80000;
		arm64_mem.image_size = KERNEL_IMAGE_SIZE;
	}

	return 0;
}

static int get_memory_ranges_dt(struct memory_range *array, unsigned int *count, char *kernel_buf, off_t kernel_size)
{
	struct region {uint64_t base; uint64_t size;};
	struct dtb dtb = {.name = "range_dtb"};
	int offset;
	int result;

	*count = 0;

	result = read_1st_dtb(&dtb, NULL, kernel_buf, kernel_size);

	if (result) {
		goto on_error;
	}

	result = fdt_check_header(dtb.buf);

	if (result) {
		dbgprintf("%s:%d: %s: fdt_check_header failed:%s\n", __func__,
			__LINE__, dtb.path, fdt_strerror(result));
		goto on_error;
	}

	for (offset = 0; ; ) {
		const struct region *region;
		const struct region *end;
		int len;

		offset = fdt_subnode_offset(dtb.buf, offset, "memory");

		if (offset == -FDT_ERR_NOTFOUND)
			break;

		if (offset <= 0) {
			dbgprintf("%s:%d: fdt_subnode_offset failed: %d %s\n",
				__func__, __LINE__, offset,
				fdt_strerror(offset));
			goto on_error;
		}

		dbgprintf("%s:%d: node_%d %s\n", __func__, __LINE__, offset,
			fdt_get_name(dtb.buf, offset, NULL));

		region = fdt_getprop(dtb.buf, offset, "reg", &len);

		if (region <= 0) {
			dbgprintf("%s:%d: fdt_getprop failed: %d %s\n",
				__func__, __LINE__, offset,
				fdt_strerror(offset));
			goto on_error;
		}

		for (end = region + len / sizeof(*region);
			region < end && *count < KEXEC_SEGMENT_MAX;
			region++) {
			struct memory_range r;

			r.type = RANGE_RAM;
			r.start = fdt64_to_cpu(region->base);
			r.end = r.start + fdt64_to_cpu(region->size);

			if (!region->size) {
				dbgprintf("%s:%d: SKIP: %016llx - %016llx\n",
					__func__, __LINE__, r.start, r.end);
				continue;
			}

			dbgprintf("%s:%d:  RAM: %016llx - %016llx\n", __func__,
				__LINE__, r.start, r.end);

			array[(*count)++] = r;

			set_memstart(r.start);
		}
	}

	if (!*count) {
		dbgprintf("%s:%d: %s: No RAM found.\n", __func__, __LINE__,
			dtb.path);
		goto on_error;
	}

	dbgprintf("%s:%d: %s: Success\n", __func__, __LINE__, dtb.path);
	result = 0;
	goto on_exit;

on_error:
	fprintf(stderr, "%s:%d: %s: Unusable device-tree file\n", __func__,
		__LINE__, dtb.path);
	result = -1;

on_exit:
	free(dtb.buf);
	return result;
}

static int get_memory_ranges_iomem(struct memory_range *array,
	unsigned int *count)
{
	const char *iomem;
	char line[MAX_LINE];
	FILE *fp;

	*count = 0;

	iomem = proc_iomem();
	fp = fopen(iomem, "r");

	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s\n", iomem, strerror(errno));
		return -1;
	}

	while(fgets(line, sizeof(line), fp) != 0) {
		struct memory_range r;
		char *str;
		int consumed;

		if (*count >= KEXEC_SEGMENT_MAX)
			break;

		if (sscanf(line, "%Lx-%Lx : %n", &r.start, &r.end, &consumed)
			!= 2)
			continue;

		str = line + consumed;
		r.end++;

		if (memcmp(str, "System RAM\n", 11)) {
			dbgprintf("%s:%d: SKIP: %016Lx - %016Lx : %s", __func__,
				__LINE__, r.start, r.end, str);
			continue;
		}

		r.type = RANGE_RAM;

		dbgprintf("%s:%d: RAM: %016llx - %016llx : %s", __func__,
			__LINE__, r.start, r.end, str);

		array[(*count)++] = r;

		set_memstart(r.start);
	}

	fclose(fp);

	if (!*count) {
		dbgprintf("%s:%d: failed: No RAM found.\n", __func__, __LINE__);
		return -1;
	}

	dbgprintf("%s:%d: Success\n", __func__, __LINE__);
	return 0;
}

int get_memory_ranges(struct memory_range **range, int *ranges,
	unsigned long kexec_flags, char *kernel_buf, off_t kernel_size)
{
	static struct memory_range array[KEXEC_SEGMENT_MAX];
	unsigned int count;
	int result;

	result = get_memory_ranges_dt(array, &count, kernel_buf, kernel_size);

	if (result)
		result = get_memory_ranges_iomem(array, &count);

	*range = result ? NULL : array;
	*ranges = result ? 0 : count;

	return result;
}

struct file_type file_type[] = {
	{"elf-arm64", elf_arm64_probe, elf_arm64_load, elf_arm64_usage},
	{"image-arm64", image_arm64_probe, image_arm64_load, image_arm64_usage},
	{"gzip-image-arm64", gzip_image_arm64_probe, gzip_image_arm64_load, gzip_image_arm64_usage},
};

int file_types = sizeof(file_type) / sizeof(file_type[0]);

int arch_compat_trampoline(struct kexec_info *info)
{
	return 0;
}

int machine_verify_elf_rel(struct mem_ehdr *ehdr)
{
	return (ehdr->e_machine == EM_AARCH64);
}

void machine_apply_elf_rel(struct mem_ehdr *ehdr, unsigned long r_type,
	void *ptr, unsigned long address, unsigned long value)
{
#if !defined(R_AARCH64_ABS64)
# define R_AARCH64_ABS64 257
#endif

#if !defined(R_AARCH64_LD_PREL_LO19)
# define R_AARCH64_LD_PREL_LO19 273
#endif

#if !defined(R_AARCH64_ADR_PREL_LO21)
# define R_AARCH64_ADR_PREL_LO21 274
#endif

#if !defined(R_AARCH64_JUMP26)
# define R_AARCH64_JUMP26 282
#endif

#if !defined(R_AARCH64_CALL26)
# define R_AARCH64_CALL26 283
#endif

	uint64_t *loc64;
	uint32_t *loc32;
	uint64_t *location = (uint64_t *)ptr;
	uint64_t data = *location;
	const char *type = NULL;

	switch(r_type) {
	case R_AARCH64_ABS64:
		type = "ABS64";
		loc64 = ptr;
		*loc64 = cpu_to_elf64(ehdr, elf64_to_cpu(ehdr, *loc64) + value);
		break;
	case R_AARCH64_LD_PREL_LO19:
		type = "LD_PREL_LO19";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ (((value - address) << 3) & 0xffffe0));
		break;
	case R_AARCH64_ADR_PREL_LO21:
		if (value & 3)
			die("%s: ERROR Unaligned value: %lx\n", __func__,
				value);
		type = "ADR_PREL_LO21";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ (((value - address) << 3) & 0xffffe0));
		break;
	case R_AARCH64_JUMP26:
		type = "JUMP26";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ (((value - address) >> 2) & 0x3ffffff));
		break;
	case R_AARCH64_CALL26:
		type = "CALL26";
		loc32 = ptr;
		*loc32 = cpu_to_le32(le32_to_cpu(*loc32)
			+ (((value - address) >> 2) & 0x3ffffff));
		break;
	default:
		die("%s: ERROR Unknown type: %lu\n", __func__, r_type);
		break;
	}

	dbgprintf("%s: %s %016lx->%016lx\n", __func__, type, data, *location);
}

void arch_reuse_initrd(void)
{
	reuse_initrd = 1;
}

void arch_update_purgatory(struct kexec_info *UNUSED(info))
{
}
