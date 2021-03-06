#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <libfdt.h>
#include <stdio.h>
#include <stdlib.h>

#include "kexec.h"
#include "dt-ops.h"

static const char n_chosen[] = "/chosen";

static const char p_bootargs[] = "bootargs";
static const char p_initrd_start[] = "linux,initrd-start";
static const char p_initrd_end[] = "linux,initrd-end";

int dtb_set_initrd(char **dtb, off_t *dtb_size, off_t start, off_t end)
{
	int result;
	uint64_t value;

	dbgprintf("%s: start %jd, end %jd, size %jd (%jd KiB)\n",
		__func__, (intmax_t)start, (intmax_t)end,
		(intmax_t)(end - start),
		(intmax_t)(end - start) / 1024);

	value = cpu_to_fdt64(start);

	result = dtb_set_property(dtb, dtb_size, n_chosen, p_initrd_start,
		&value, sizeof(value));

	if (result)
		return result;

	value = cpu_to_fdt64(end);

	result = dtb_set_property(dtb, dtb_size, n_chosen, p_initrd_end,
		&value, sizeof(value));

	if (result) {
		dtb_delete_property(*dtb, n_chosen, p_initrd_start);
		return result;
	}

	return 0;
}

int dtb_set_bootargs(char **dtb, off_t *dtb_size, const char *command_line)
{
	return dtb_set_property(dtb, dtb_size, n_chosen, p_bootargs,
		command_line, strlen(command_line) + 1);
}

int dtb_set_property(char **dtb, off_t *dtb_size, const char *node,
	const char *prop, const void *value, int value_len)
{
	int result;
	int nodeoffset;
	void *new_dtb;
	int new_size;

	value_len = FDT_TAGALIGN(value_len);

	new_size = FDT_TAGALIGN(*dtb_size + fdt_node_len(node)
		+ fdt_prop_len(prop, value_len));

	new_dtb = malloc(new_size);

	if (!new_dtb) {
		dbgprintf("%s: malloc failed\n", __func__);
		return -ENOMEM;
	}

	result = fdt_open_into(*dtb, new_dtb, new_size);

	if (result) {
		dbgprintf("%s: fdt_open_into failed: %s\n", __func__,
			fdt_strerror(result));
		goto on_error;
	}

	nodeoffset = fdt_path_offset(new_dtb, node);
	
	if (nodeoffset == -FDT_ERR_NOTFOUND) {
		result = fdt_add_subnode(new_dtb, nodeoffset, node);

		if (result) {
			dbgprintf("%s: fdt_add_subnode failed: %s\n", __func__,
				fdt_strerror(result));
			goto on_error;
		}
	} else if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset failed: %s\n", __func__,
			fdt_strerror(nodeoffset));
		goto on_error;
	}

	result = fdt_setprop(new_dtb, nodeoffset, prop, value, value_len);

	if (result) {
		dbgprintf("%s: fdt_setprop failed: %s\n", __func__,
			fdt_strerror(result));
		goto on_error;
	}

	/*
	 * Can't call free on dtb since dtb may have been mmaped by
	 * slurp_file().
	 */

	*dtb = new_dtb;
	*dtb_size = new_size;

	return 0;

on_error:
	free(new_dtb);
	return result;
}

int dtb_delete_property(char *dtb, const char *node, const char *prop)
{
	int result;
	int nodeoffset = fdt_path_offset(dtb, node);

	if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset failed: %s\n", __func__,
			fdt_strerror(nodeoffset));
		return nodeoffset;
	}

	result = fdt_delprop(dtb, nodeoffset, prop);

	if (result)
		dbgprintf("%s: fdt_delprop failed: %s\n", __func__,
			fdt_strerror(nodeoffset));

	return result;
}
