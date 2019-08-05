#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

#include <libguile.h>
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#define CODE_BASE  0x8f000000
#define INITIAL_SP 0x8f100000
#define DEVICE_NAME_LEN 256

struct device {
	uint64_t base;
	uint64_t size;
	uc_cb_hookmem_t callback;
	uc_hook hook;
	void *state;
	char name[DEVICE_NAME_LEN];
};

struct uart_state {
	uint64_t cache[100];
};

struct mct_state {
	uint64_t timer;
	uint64_t timer_obs;
};

struct memory_mapping {
	uint64_t base;
	size_t size;
	uint32_t perms;
};

struct patch {
	uint64_t address;
	int64_t retval;
	uc_hook hook;
	void *fn;
};

struct max77705_state {
	uint8_t regs[256];
	uint8_t fuelgauge_regs[256];
	uint8_t usbc_regs[256];
	uint8_t led_regs[256];
};

static void uart_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void system_controller_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void chipid_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void mct_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void i2c_bulk_read(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

static int reg_ids[] = {
	UC_ARM64_REG_PC,  UC_ARM64_REG_LR,  UC_ARM64_REG_SP,  UC_ARM64_REG_X0,
	UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,  UC_ARM64_REG_X4,
	UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7,  UC_ARM64_REG_X8,
	UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11, UC_ARM64_REG_X12,
	UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15, UC_ARM64_REG_X16,
	UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X20,
	UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
	UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28,
};

static char *reg_names[] = {
	" pc", " lr", " sp", " x0",
	" x1", " x2", " x3", " x4",
	" x5", " x6", " x7", " x8",
	" x9", "x10", "x11", "x12",
	"x13", "x14", "x15", "x16",
	"x17", "x18", "x19", "x20",
	"x21", "x22", "x23", "x24",
	"x25", "x26", "x27", "x28",
};

struct device pinctrl0 = {
	.name = "pinctrl0",
	.base = 0x14050000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device pinctrl1 = {
	.name = "pinctrl1",
	.base = 0x17c60000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device pinctrl2 = {
	.name = "pinctrl2",
	.base = 0x13a80000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device pinctrl3 = {
	.base = 0x14220000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device pinctrl4 = {
	.base = 0x11050000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device pinctrl5 = {
	.base = 0x11430000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device pinctrl6 = {
	.base = 0x10430000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device pinctrl7 = {
	.base = 0x10830000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device pinctrl8 = {
	.base = 0x13880000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device watchdog_cl0 = {
	.base = 0x10050000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device watchdog_cl1 = {
	.base = 0x10060000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device chipid = {
	.base = 0x10000000,
	.size = 0x1000,
	.callback = chipid_callback,
	.state = NULL
};

struct device cmu_ewf = {
	.base = 0x1a240000,
	.size = 0x2000,
	.callback = NULL,
	.state = NULL
};

struct uart_state uart0_state;

struct device uart0 = {
	.base = 0x10440000,
	.size = 0x1000,
	.callback = uart_callback,
	.state = &uart0_state
};

struct device pwm = {
	.base = 0x10510000,
	.size = 0x1000,
	.callback = NULL,
	.state = NULL
};

struct device shmem = {
	.base = 0xf6e0000,
	.size = 0x7900000,
	.callback = NULL,
	.state = NULL
};

static struct mct_state mct_state = {
	.timer = 0,
	.timer_obs = 0
};

struct device mct = {
	.base = 0x10040000,
	.size = 0x1000,
	.callback = mct_callback,
	.state = &mct_state
};

struct device system_controller = {
	.base = 0x14060000,
	.size = 0x10000,
	.callback = system_controller_callback,
	.state = NULL
};

struct device speedy = {
	.base = 0x141c0000,
	.size = 0x2000,
	.callback = NULL,
	.state = NULL
};

struct device ufs = {
	.base = 0x11110000,
	.size = 0x21000,
	.callback = NULL,
	.state = NULL
};

struct device *devices[] = {
	&pinctrl0,
	&pinctrl1,
	&pinctrl2,
	&pinctrl3,
	&pinctrl4,
	&pinctrl5,
	&pinctrl6,
	&pinctrl7,
	&pinctrl8,
	&watchdog_cl0,
	&watchdog_cl1,
	&chipid,
	&cmu_ewf,
	&uart0,
	&pwm,
	&mct,
	&system_controller,
	&speedy,
	&ufs,
	NULL
};

struct memory_mapping memory_map[] = {
	{ 0x80000000, 0x00001000, UC_PROT_ALL }, // sec_debug_magic
	{ 0x8e000000, 0x03000000, UC_PROT_ALL },
	{ 0x95000000, 0x10000000, UC_PROT_ALL },
	{ 0x100000000,0x00001000, UC_PROT_ALL },
	{ 0xfd900000, 0x00100000, UC_PROT_ALL },
	{ 0x02030000, 0x00010000, UC_PROT_ALL },
	{ 0x15c30000, 0x00001000, UC_PROT_ALL },
	{ 0x15850000, 0x00020000, UC_PROT_ALL },
	{ 0x15970000, 0x00020000, UC_PROT_ALL },
	{ 0x10400000, 0x00002000, UC_PROT_ALL },
	{ 0xef000000, 0x00100000, UC_PROT_ALL },
	{ 0xfda00000, 0x01e00000, UC_PROT_ALL }, // exynos_ss
	{ 0x00000000, 0x00000000, UC_PROT_NONE },
};

struct patch patches[] = {
	{ 0x8f073654, 0x07, 0, 0 },
	{ 0x8f07269c, 0x00, 0, 0 },
	{ 0x8f073bbc, 0x01, 0, 0 }, // ccic_is_max77705
	{ 0x8f052c10, 0x00, 0, i2c_bulk_read },
	{ 0x8f04fdcc, 0x00, 0, 0 },
	{ 0x8f002324, 0x01, 0, 0 },
	{ 0, 0, 0, 0}
};

struct max77705_state max77705_state = {
	.regs      = { 0x05, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.usbc_regs = { 0x13, 0x27, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x05,
		       0x81, 0x00, 0x91, 0x08, 0x03, 0x07, 0x00, 0x00 }
};
struct max77705_state *max77705 = &max77705_state;

static void
uart_callback(uc_engine *uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void *user_data)
{
	struct device *uart = (struct device *) user_data;
	struct uart_state *state = (struct uart_state *) uart->state;
	uint64_t offset = address - uart->base;
	uint64_t *cache = &state->cache[offset];
	uint64_t ret;

	if (type == UC_MEM_READ)
		goto read;

	if (type == UC_MEM_WRITE)
		goto write;

	return;

read:
	switch (offset) {
	case 0x10:
		*cache = ~*cache;
		ret = *cache;
		break;
	default:
		*cache = 0;
		ret = *cache;
	};
	uc_mem_write(uc, address, &ret, sizeof(uint64_t));
	return;

write:
	switch (offset) {
	case 0x20:
		printf("%c", (char) value);
		break;
	};
	return;
}

static void
system_controller_callback(uc_engine *uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void *user_data)
{
	uint32_t val;
	if (type != UC_MEM_READ)
		return;

	switch (address) {
	case 0x14060404:
		val = 0x01 << 0x1d;
		break;
	case 0x1406080c:
		val = 0x00;
		break;
	case 0x14060880:
		val = 0xbadabcd;
		break;
	case 0x14060f08:
		val = 0x10000;
		break;
	case 0x14060f0c:
		val = 0x10000;
		break;
	case 0x14060f10:
		val = 0x10000;
		break;
	case 0x14060f14:
		val = 0x10000;
		break;
	case 0x14060f20:
		val = 0x10000;
		break;
	case 0x14060f24:
		val = 0x10000;
		break;
	case 0x14060f28:
		val = 0x10000;
		break;
	case 0x14060f2c:
		val = 0x10000;
		break;
	case 0x14060f30:
		val = 0x10000;
		break;
	case 0x14060f34:
		val = 0x10000;
		break;
	case 0x14060f38:
		val = 0x10000;
		break;
	case 0x14060f3c:
		val = 0x10000;
		break;
	};

	uc_mem_write(uc, address, &val, sizeof(uint32_t));
}

static void
chipid_callback(uc_engine *uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void *user_data)
{
	uint32_t val;
	if (type != UC_MEM_READ)
		return;

	switch (address) {
	case 0x10000004:
		val = 0xfde14d2;
		break;
	};

	uc_mem_write(uc, address, &val, sizeof(uint32_t));
}

static void
mct_callback(uc_engine *uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void *user_data)
{
	uint64_t val;
	uint64_t obs;
	struct mct_state *state = (struct mct_state *) user_data;

	if (type != UC_MEM_READ)
		return;

	switch (address) {
	case 0x10040100:
		state->timer += 0x1000;
		val = state->timer;
		break;
	case 0x10040104:
		state->timer += 0x1000;
		val = state->timer;
		address = 0x10040100;
		return;
	}

	uc_mem_write(uc, address, &val, sizeof(uint64_t));
}

static uc_err
register_device(uc_engine *uc, struct device *dev)
{
	uc_err err;

	err = uc_mem_map(uc, dev->base, dev->size, UC_PROT_READ | UC_PROT_WRITE);
	if (err != UC_ERR_OK)
		return err;

	if (dev->callback) {
		err = uc_hook_add(uc, &dev->hook,
		    UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
		    dev->callback, dev,
		    dev->base,
		    dev->base + dev->size - 1);
		if (err != UC_ERR_OK)
			return err;
	}

	return err;
}

static uc_err
load_image(uc_engine *uc, const char *file, uint64_t base, uint64_t *last)
{
	char buf[1024];
	FILE *f;
	long sz;
	uc_err err;
	uint64_t addr = base;

	if (!(f = fopen(file, "r")))
		return UC_ERR_HANDLE;

	fseek(f, 0L, SEEK_END);
	sz = ftell(f);
	fseek(f, 0L, SEEK_SET);

	while (ftell(f) != sz) {
		size_t n = fread(buf, 1, 1024, f);
		*last = addr;
		if ((err = uc_mem_write(uc, addr, buf, n)) != UC_ERR_OK)
			return err;
		addr += n;
	}

	return err;
}

static uc_err
init_mem(uc_engine *uc)
{
	uc_err err;
	struct memory_mapping map;
	int i;

	for (i = 0; memory_map[i].perms != UC_PROT_NONE; i++) {
		map = memory_map[i];
		if ((err = uc_mem_map(uc, map.base, map.size, map.perms)))
			return err;
	}

	for (i = 0; devices[i] != NULL; i++)
		if ((err = register_device(uc, devices[i])) != UC_ERR_OK)
			return err;

	return err;
}


static void
dump_regs(uc_engine *uc)
{

	uint8_t code[4*32];
	void *ptrs[32];
	uint64_t regs[32];
	int i;

	for (i = 0; i < 32; i++)
		ptrs[i] = &regs[i];

	uc_reg_read_batch(uc, reg_ids, ptrs, 32);

	printf("======================================================================\n");
	printf("PSTATE:\n");
	printf(" pc : 0x%016llx\t lr : 0x%016llx\t sp : 0x%016llx", regs[0], regs[1], regs[2]);

	for (i = 3; i < 32; i++) {
		if (i != 0 && (i - 3) % 3 == 0) printf("\n");
		printf("%s : 0x%016llx\t", reg_names[i], regs[i]);
	}

	if (uc_mem_read(uc, regs[0], code, sizeof(code)) != UC_ERR_OK)
		return;

	{
		csh handle;
		cs_insn *insn;
		size_t j, n;

		if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
			return;

		printf("\nDisassembly:\n");
		n = cs_disasm(handle, code, sizeof(code), regs[0], 0, &insn);
		if (n > 0) {
			for (j = 0; j < n; j++)
				printf("\t0x%llx: %s %s\n",
				    insn[j].address, insn[j].mnemonic, insn[j].op_str);
			cs_free(insn, n);
		}

		cs_close(&handle);
	}

	return;
}

static void
max77705_bulk_read(uc_engine *uc, uint64_t reg, uint8_t offset, uint64_t dest)
{
	uint8_t res;
	uc_err err;

	switch (reg) {
	case 0xcc:
		res = max77705->regs[offset];
		break;
	case 0x6c:
		res = max77705->fuelgauge_regs[offset];
		break;
	case 0x4a:
		res = max77705->usbc_regs[offset];
		break;
	case 0x94:
		res = max77705->led_regs[offset];
		break;
	};

	uc_mem_write(uc, dest, &res, 1);
}

static void
i2c_bulk_read(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	int64_t lr, x0, x1, x2, x3;;
	int64_t res;

	uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
	uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
	uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
	uc_reg_read(uc, UC_ARM64_REG_X3, &x3);

	switch (x0) {
	case 0:
		max77705_bulk_read(uc, x1, x2, x3);
		uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
		break;
	case 12:
		res = 0x80;
		uc_mem_write(uc, x3, &res, 1);
		uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
		break;
	default:
		printf("i2c_bulk_read: device=0x%llx reg=0x%llx count=%llx dest=0x%llx\n",
		    x0, x1, x2, x3);
		break;
	}
}

static void
patch_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	int64_t lr;
	uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
	uc_reg_write(uc, UC_ARM64_REG_X0, user_data);
	uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

static void
init_patches(uc_engine *uc)
{
	int i;
	struct patch *patch;
	for (i = 0; patches[i].address != 0; i++) {
		patch = patches + i;
		if (patch->fn)
			uc_hook_add(uc, &patch->hook,
			    UC_HOOK_CODE, patch->fn,
			    &patch->retval, patch->address, patch->address);
		else
			uc_hook_add(uc, &patch->hook,
			    UC_HOOK_CODE, patch_hook,
			    &patch->retval, patch->address, patch->address);
	}
}

static void
pmic_chipid_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
    int64_t value, void *user_data)
{
	uint32_t val = 0x01;
	uc_mem_write(uc, 0x8f418430, &val, sizeof(uint32_t));
}

static void
trace_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	csh handle;
	cs_insn *insn;
	uint8_t code[4];
	size_t count;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != UC_ERR_OK)
		return;

	if (uc_mem_read(uc, address, code, sizeof(code)) != UC_ERR_OK)
		goto end;

	count = cs_disasm(handle, code, sizeof(code), address, 0, &insn);
	if (count > 0) {
		printf(">>> 0x%llx: %s %s\n",
		    insn->address, insn->mnemonic, insn->op_str);
		cs_free(insn, count);
	}

end:
	cs_close(&handle);
	return;
}

int
main(int argc, char **argv)
{
	uc_engine *uc;
	uc_err err;
	int64_t sp = INITIAL_SP;
	int64_t reg;
	uint64_t end;
	uc_hook trace, chipid;

	if (argc < 2) {
		printf("usage: %s <bl2>\n", argv[0]);
		return -1;
	}

	if ((err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc)) != UC_ERR_OK) {
		printf("uc_open: %s\n", uc_strerror(err));
		goto fail;
	}

	if ((err = init_mem(uc)) != UC_ERR_OK) {
		printf("init_mem: %s\n", uc_strerror(err));
		goto cleanup;
	}

	if ((err = load_image(uc, argv[1], CODE_BASE, &end)) != UC_ERR_OK) {
		printf("load_image: %s\n", uc_strerror(err));
		goto cleanup;
	}

	uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
	uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &reg);
	reg |= 0x300000;
	uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &reg);

	uc_hook_add(uc, &trace, UC_HOOK_CODE, trace_hook, NULL, 1, 0);
	uc_hook_add(uc, &chipid, UC_HOOK_MEM_READ, pmic_chipid_callback, NULL,
	    0x8f418430, 0x8f418430);

	init_patches(uc);

	if ((err = uc_emu_start(uc, CODE_BASE, end, 0, 0)) != UC_ERR_OK) {
		printf("uc_emu_start: %s\n", uc_strerror(err));
		dump_regs(uc);
		goto cleanup;
	}

	uc_close(uc);
	return 0;

cleanup:
	uc_close(uc);

fail:
	return -1;

}
