#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include "ufs.h"
#include "usb.h"

#define CODE_BASE  0x8f000000
#define INITIAL_SP 0x8f600000
#define DEVICE_NAME_LEN 256
#define USB_EVENT_LOOP 0x8f04ff5c
#define USB_EVENT_LOOP_TOP 0x8f050010
#define EXYNOS_USB_HANDLE_EVENT 0x8f066914
#define MALLOC 0x8f00f2dc
#define FREE 0x8f00f30c
#define USBD3_RDX_PROCESS 0x8f064f20


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

struct usb_state {
	uint32_t event_addr_lo0;
	uint32_t event_addr_hi0;
	uint32_t event_size;
	uint32_t event_count;
	uint32_t dcfg;
	uint32_t dctl;
	uint32_t depcmd;
	uint32_t depcmdpar0;
	uint32_t depcmdpar1;
	uint32_t depcmdpar2;
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

struct ufs_state {
	uint32_t reg_sys[256];
	uint32_t reg_hci[256];
	uint32_t reg_unipro[256];
	uint32_t reg_ufsp[256];
};

static void dump_regs(uc_engine *uc);

static void uart_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void system_controller_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void chipid_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void pwm_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void mct_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void ufs_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void adc_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void usb_callback(uc_engine *uc,
    uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

static void i2c_bulk_read(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

static void i2c_bulk_write(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

static void find_param_file(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

static void get_partition(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

static void ufs_scsi(uc_engine *uc, uint64_t address, uint64_t len, void *user_data);

static void ufs_infer_stat(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

static char pit_file[128];
static char param_file[128];
static char up_param_file[128];

static int reg_ids[] = {
	UC_ARM64_REG_PC,  UC_ARM64_REG_LR,  UC_ARM64_REG_SP,  UC_ARM64_REG_X0,
	UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,  UC_ARM64_REG_X4,
	UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7,  UC_ARM64_REG_X8,
	UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11, UC_ARM64_REG_X12,
	UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15, UC_ARM64_REG_X16,
	UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X20,
	UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
	UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28,
	UC_ARM64_REG_X29,
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
	"x29",
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
	.callback = NULL, // pwm_callback,
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

struct ufs_state ufs_state;
struct device ufs = {
	.base = 0x11110000,
	.size = 0x21000,
	.callback = ufs_callback,
	.state = &ufs_state,
};

struct device adc = {
	.base = 0x14230000,
	.size = 0x1000,
	.callback = adc_callback,
	.state = NULL,
};

struct device disp_ss = {
	.base = 0x16010000,
	.size = 0x2000,
};

struct device dsim = {
	.base = 0x16080000,
	.size = 0x1000,
};

static struct usb_state usb_state = {
	.event_addr_hi0 = 0x00,
	.event_addr_lo0 = 0x00,
	.event_size = 0x00,
};

struct device usb = {
	.base = 0x10c00000,
	.size = 0x10000,
	.callback = usb_callback,
	.state = &usb_state,
};

struct device phy = {
	.base = 0x11100000,
	.size = 0x1000,
};

struct device phy0 = {
	.base = 0x110a0000,
	.size = 0x1000,
};

struct device phy1 = {
	.base = 0x110b0000,
	.size = 0x1000,
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
	&adc,
	&disp_ss,
	&dsim,
	&usb,
	&phy,
	&phy0,
	&phy1,
	NULL
};

struct memory_mapping memory_map[] = {
	{ 0x80000000, 0x00001000, UC_PROT_ALL }, // sec_debug_magic
	{ 0x8e000000, 0x03000000, UC_PROT_ALL },
	{ 0x95000000, 0x10000000, UC_PROT_ALL },
	{ 0x100000000,0x00001000, UC_PROT_ALL },
	{ 0x02030000, 0x00010000, UC_PROT_ALL },
	{ 0x02050000, 0x00010000, UC_PROT_ALL },
	{ 0x15c30000, 0x00001000, UC_PROT_ALL },
	{ 0x15850000, 0x00020000, UC_PROT_ALL },
	{ 0x15970000, 0x00020000, UC_PROT_ALL },
	{ 0x10400000, 0x00002000, UC_PROT_ALL },
	{ 0xef000000, 0x00100000, UC_PROT_ALL },
	{ 0xcc000000, 0x10000000, UC_PROT_ALL },
	{ 0xfda00000, 0x02000000, UC_PROT_ALL }, // exynos_ss
	{ 0xfd900000, 0x00100000, UC_PROT_ALL },
	{ 0x10070000, 0x00010000, UC_PROT_ALL }, // BIG
	{ 0x00000000, 0x00000000, UC_PROT_NONE },
};

struct patch patches[] = {
	{ 0x8f073654, 0x07, 0, NULL }, // max77705_read_adc
	{ 0x8f07269c, 0x00, 0, NULL }, // ccic_wait_auth
	{ 0x8f073bbc, 0x01, 0, NULL }, // ccic_is_max77705
	{ 0x8f052c10, 0x00, 0, i2c_bulk_read },
	{ 0x8f052f9c, 0x00, 0, i2c_bulk_write },
	// { 0x8f05e78c, 0x00, 0, ufs_scsi }, // sub_8f05e78c
	// { 0x8f010dc4, 0x00, 0, get_partition },
	// { 0x8f0142c4, 0x00, 0, find_param_file },
	{ 0x8f078040, 0x01, 0, NULL }, // init_dsim
	{ 0x8f075220, 0x00, 0, NULL }, // exynos_display_set_brightness
	{ 0x8f04fdcc, 0x00, 0, NULL },
	{ 0x8f05c194, 0x00, 0, NULL }, //ufs_infer_stat
	{ 0x8f002324, 0x01, 0, NULL }, // supervisor call
	// { 0x8f01a084, 0x00, 0, NULL }, // mmc_init
	// { 0x8f05600c, 0x00, 0, NULL }, // mmu_enable
	{ 0x8f006470, 0x00, 0, NULL }, // dram training data
	{ 0x8f05dfc0, 0x00, 0, NULL }, // ufs_send_cmd_uipu
	{ 0x8f02c4f4, 0x00, 0, NULL }, // mobiload_cmd
	{ 0x8f050268, 0x00, 0, NULL }, // s5p_check_download
	{ 0x8f014c90, 0x01, 0, NULL }, // sub_8f014c90
	{ 0x8f05f450, 0x00, 0, NULL }, // sub_8f05f450
	// { 0x8f05c7c8, }, // sub_8f05c7c8
	{ 0, 0, 0, 0}
};

struct max77705_state max77705_state = {
	.regs      = { 0x05, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00 },
	.usbc_regs = { 0x13, 0x27, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x05,
		       0x81, 0x00, 0x91, 0x08, 0x03, 0x07, 0x00, 0x00 }
};

struct max77705_state *max77705 = &max77705_state;


static void
disassemble_memory(uc_engine *uc, uint64_t from, uint32_t count)
{
	uint8_t *buf;
	uc_err err;
	csh handle;
	cs_insn *insn;
	int i;

	buf = malloc(4*count);
	if (!buf)
		return;

	if ((err = uc_mem_read(uc, from, buf, 4*count)) != UC_ERR_OK)
		return;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
		return;

	count = cs_disasm(handle, buf, 4*count, from, count, &insn);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			printf(">>> 0x%llx: %s %s\n",
			    insn[i].address,
			    insn[i].mnemonic,
			    insn[i].op_str);
		}
		cs_free(insn, count);
	}

	cs_close(&handle);
	free(buf);
}

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

static void pwm_callback(uc_engine *uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void *user_data)
{
	uint32_t val;
	if (type != UC_MEM_READ)
		return;
	switch (address) {
	case 0x1051003c:
		val = 0x00000000;
		uc_mem_write(uc, address, &val, sizeof(uint32_t));
		break;
	case 0x10510040:
		val = 0x00000000;
		uc_mem_write(uc, address, &val, sizeof(uint32_t));
		break;
	}
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

static void
ufs_infer_stat(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{

}

static void
ufs_read(uc_engine *uc, uint64_t address, int size, int64_t value, void *user_data)
{
	uint32_t val;
	uint8_t reg;
	struct ufs_state *state = (struct ufs_state *) user_data;
	if (address >= 0x11120000 && address < 0x11120200) {
		// sys registers
		reg = address - 0x11120000;
		return;
	} else if (address >= 0x11121100 && address < 0x11121300) {
		// hci registers
		reg = address - 0x11121100;
		val = state->reg_hci[reg];
		uc_mem_write(uc, address, &val, sizeof(uint32_t));
		return;
	} else if (address >= 0x11110000 && address < 0x11118000) {
		// unipro registers
		// offset = address - 0x11110000;
		return;
	} else if (address >= 0x11130000 && address < 0x11130300) {
		// ufs_protector registers
		reg = address - 0x11130000;
		return;
	}

	fail:
	printf("ufs_read: unknown address: %llx\n", address);
	dump_regs(uc);
	uc_emu_stop(uc);
}

static void
ufs_update(uc_engine *uc, struct ufs_state *state)
{
	if (state->reg_hci[HCI_SW_RST] != 0)
		state->reg_hci[HCI_SW_RST] = 0;
	state->reg_hci[HCI_VENDOR_SPECIFIC_IS] = 1 << 14;
	return;
}

static void
ufs_write(uc_engine *uc, uint64_t address, int size, int64_t value, void *user_data)
{
	uint32_t reg, val;
	struct ufs_state *state = (struct ufs_state *) user_data;
	if (address >= 0x11120000 && address < 0x11120200) {
		// registers
		ufs_update(uc, state);
	} else if (address >= 0x11121100 && address < 0x11121300) {
		// hci registers
		reg = address - 0x11121100;
		val = value;
		state->reg_hci[reg] = val;
		ufs_update(uc, state);
	} else if (address >= 0x11110000 && address < 0x11118000) {
		// unipro registers
		ufs_update(uc, state);
	} else if (address >= 0x11130000 && address < 0x11130300) {
		// ufs_protector registers
		ufs_update(uc, state);
	} else {
		goto fail;
	}

	return;

fail:
	printf("ufs_read: unknown address: %llx\n", address);
	dump_regs(uc);
	uc_emu_stop(uc);

}

static void
adc_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
    int64_t value, void *user_data)
{
	uint32_t val;
	if (type != UC_MEM_READ)
		return;

	if (address == 0x14230008) {
		val = 1 << 0x1f;
		uc_mem_write(uc, address, &val, sizeof(uint32_t));
	}
}

static void
print_usb_state(uc_engine *uc)
{
	uint32_t evntsiz;
	uint64_t evntaddr;
	uc_mem_read(uc, 0x10c0c400, &evntaddr, sizeof(uint64_t));
	uc_mem_read(uc, 0x10c0c40c, &evntsiz, sizeof(uint32_t));
	printf("Event buf addr: %llx\n", evntaddr);
	printf("Event size: %x\n", evntsiz);
}

static uint64_t
call_malloc(uc_engine *uc, uint64_t size)
{
	uint64_t ret;
	if (uc_reg_write(uc, UC_ARM64_REG_X0, &size) != UC_ERR_OK)
		return 0;
	if (uc_emu_start(uc, MALLOC, 0x8f00f308, 0, 0) != UC_ERR_OK)
		return 0;
	uc_reg_read(uc, UC_ARM64_REG_X0, &ret);
	return ret;
}

static uc_err
call_usbd3_rdx_process(uc_engine *uc, uint64_t buf, uint32_t size)
{
	uc_err err;
	if ((err = uc_reg_write(uc, UC_ARM64_REG_X0, &buf)) != UC_ERR_OK)
		return err;
	if ((err = uc_reg_write(uc, UC_ARM64_REG_X1, &size)) != UC_ERR_OK)
		return err;
	if ((err = uc_emu_start(uc, USBD3_RDX_PROCESS, 0x8f06509c, 0, 0)) != UC_ERR_OK)
		return err;
}

static void
usb_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
    int64_t value, void *user_data)
{
	struct usb_state *state = (struct usb_state *) user_data;
	uint32_t reg = address & 0x0000ffff;

	switch (type) {
	case UC_MEM_READ:
		if (reg == DWC3_DCTL) {
			uint32_t val = 0x00;
			uc_mem_write(uc, address, &val, sizeof(uint32_t));
			return;
		}

		if (reg == DWC3_GEVNTCOUNT(0)) {
			uint32_t val = state->event_count;
			// val = 0b00000000000000000100000000000000;
			uc_mem_write(uc, address, &val, sizeof(uint32_t));
			return;
		}

		if (reg == DWC3_GEVNTADRLO(0)) {
			uint32_t val;
			val = state->event_addr_lo0;
			uc_mem_write(uc, address, &val, sizeof(uint32_t));
			return;
		}

		if (reg == DWC3_GEVNTADRHI(0)) {
			uint32_t val;
			val = state->event_addr_hi0;
			uc_mem_write(uc, address, &val, sizeof(uint32_t));
			return;
		}

		if (reg == DWC3_GEVNTSIZ(0)) {
			uint32_t val;
			val = state->event_size;
			uc_mem_write(uc, address, &val, sizeof(uint32_t));
			return;
		}

		if (reg == DWC3_GFLADJ) {
			uint32_t val = 0x00;
			uc_mem_write(uc, address, &val, sizeof(uint32_t));
			return;
		}

		if (reg - DWC3_DEP_BASE(0) == DWC3_DEPCMD) {
			uint32_t val = 0x00;
			uc_mem_write(uc, address, &val, sizeof(uint32_t));
			return;
		}

		if (reg - DWC3_DEP_BASE(1) == DWC3_DEPCMD) {
			uint32_t val = 0x00;
			uc_mem_write(uc, address, &val, sizeof(uint32_t));
			return;
		}

		// printf("Read on USB register: %llx\n", address);
		break;

	case UC_MEM_WRITE:
		if (reg == DWC3_GEVNTADRLO(0)) {
			state->event_addr_lo0 = value;
			return;
		}

		if (reg == DWC3_GEVNTADRHI(0)) {
			state->event_addr_hi0 = value;
			return;
		}

		if (reg == DWC3_DCTL) {
			state->dctl = value;
			return;
		}

		if (reg == DWC3_DCFG) {
			state->dcfg = value;
			return;
		}

		if (reg == DWC3_GEVNTCOUNT(0)) {
			state->event_count = value;
			return;
		}

		if (reg == DWC3_GEVNTSIZ(0)) {
			state->event_size = value;
			return;
		}

		if (reg - DWC3_DEP_BASE(0) == DWC3_DEPCMD) {
			uint64_t pc;
			state->depcmd = value;
			// uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
			// disassemble_memory(uc, pc - 20, 20);
			return;
		}

		// printf("Write on USB register: %llx (%llx)\n", address, value);
		break;
	default:
		return;
	}
}

static void
ufs_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
    int64_t value, void *user_data)
{
	switch (type) {
	case UC_MEM_READ:
		ufs_read(uc, address, size, value, user_data);
		break;
	case UC_MEM_WRITE:
		ufs_write(uc, address, size, value, user_data);
		break;
	default:
		return;
	}
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
	void *ptrs[33];
	uint64_t regs[33];
	int i;

	for (i = 0; i < 33; i++)
		ptrs[i] = &regs[i];

	uc_reg_read_batch(uc, reg_ids, ptrs, 33);

	printf("======================================================================\n");
	printf("PSTATE:\n");
	printf(" pc : 0x%016llx\t lr : 0x%016llx\t sp : 0x%016llx", regs[0], regs[1], regs[2]);

	for (i = 3; i < 33; i++) {
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
	case 0xd2:
		res = 0;
		break;
	case 0xd3:
		res = 0xb8;
		break;
	};

	uc_mem_write(uc, dest, &res, 1);
}

static void
max77705_write(uc_engine *uc, uint64_t reg, uint8_t offset, uint64_t dest)
{
	uint8_t res;
	switch (reg) {
	case 0xd2: // charger
		// ?
		break;
	}
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
i2c_bulk_write(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	int64_t lr, x0, x1, x2, x3;;

	uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
	uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
	uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
	uc_reg_read(uc, UC_ARM64_REG_X3, &x3);

	switch (x0) {
	case 0:
		max77705_write(uc, x1, x2, x3);
		uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
		break;
	default:
		printf("i2c_bulk_write: device=0x%llx reg=0x%llx count=%llx dest=0x%llx\n",
		    x0, x1, x2, x3);
		break;
	}
}


static void
find_param_file(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	int64_t ptr, end;
	uc_mem_read(uc, 0x8f389598, &ptr, sizeof(uint64_t));
	load_image(uc, param_file, ptr, &end);
}

static void
get_partition(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	int64_t lr, x0, x1, x2, x3;
	char name[1024];
	char *file = NULL;
	int64_t ret = 0;
	uint64_t end;

	uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
	uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
	uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
	uc_reg_read(uc, UC_ARM64_REG_X3, &x3);

	uc_mem_read(uc, x0, &name, sizeof(name));

	printf("%s\n", name);

	if (!strcmp(name, "PARAM")) {

	}

	if (!strcmp(name, "UP_PARAM")) {
	}

	if (!strcmp(name, "PERSISTENT")) {
	}

	    // uc_reg_write(uc, UC_ARM64_REG_X0, &ret);
	    // uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

static void
ufs_scsi(uc_engine *uc, uint64_t address, uint64_t len, void *user_data)
{
	uint64_t lr, x0, x1, x2, x3, x4;
	uint64_t read, lun, from, size, buffer;
	uint64_t sz;

	uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
	uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
	uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
	uc_reg_read(uc, UC_ARM64_REG_X3, &x3);
	uc_reg_read(uc, UC_ARM64_REG_X4, &x4);

	read = x0;
	lun = x1;
	from = x2;
	size = x3;
	buffer = x4;

	printf("LUN=%d read=%d from=%x size=%x buffer=%llx\n",
	    lun, read, from, size, buffer);

	if (lun == 0x00 && read == 1)
		load_image(uc, pit_file, buffer, &sz);
	else
		goto fail;

	x0 = 0x00;
	uc_reg_write(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
	return ;

fail:
	dump_regs(uc);
	uc_emu_stop(uc);

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

static void
hook_quit(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uc_emu_stop(uc);
	dump_regs(uc);
}

static void
show_heap(uc_engine *uc)
{
	uint64_t first_chunk = 0x90500000;
	uint64_t chunk_addr;
	uint64_t next, prev;
	uint32_t size;
	uint32_t is_free;
	uc_mem_read(uc, first_chunk, &size, sizeof(uint32_t));
	uc_mem_read(uc, first_chunk+0x4, &is_free, sizeof(uint32_t));
	uc_mem_read(uc, first_chunk+0x8, &prev, sizeof(uint64_t));
	uc_mem_read(uc, first_chunk+0x10, &next, sizeof(uint64_t));
	if (is_free == 0)
		printf("%llx <- %llx size:%lx [IN_USE] -> %llx\n",
		    prev, first_chunk, size, next);
	else
		printf("%llx <- %llx size:%lx -> %llx\n",
		    prev, first_chunk, size, next);
	chunk_addr = next;
	while (chunk_addr != first_chunk) {
		uc_mem_read(uc, chunk_addr, &size, sizeof(uint32_t));
		uc_mem_read(uc, chunk_addr+0x4, &is_free, sizeof(uint32_t));
		uc_mem_read(uc, chunk_addr+0x8, &prev, sizeof(uint64_t));
		uc_mem_read(uc, chunk_addr+0x10, &next, sizeof(uint64_t));
		if (is_free == 0)
			printf("%llx <- %llx size:%lx [IN_USE] -> %llx\n",
			    prev, chunk_addr, size, next);
		else
			printf("%llx <- %llx size:%lx -> %llx\n",
			    prev, chunk_addr, size, next);
		chunk_addr = next;
	}
}

static void
hook_free(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t chunk_size;
	uint64_t next, prev;
	uint64_t addr, lr;
	uc_reg_read(uc, UC_ARM64_REG_X0, &addr);
	uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
	uc_mem_read(uc, addr-0x18, &chunk_size, sizeof(uint32_t));
	uc_mem_read(uc, addr-0x10, &prev, sizeof(uint64_t));
	uc_mem_read(uc, addr-0x8, &next, sizeof(uint64_t));
	printf(">>> %llx\n", lr);
	printf("\tFreeing: %llx\n", addr);
	printf("\tsize: %llx\n", chunk_size);
	printf("\tnext: %llx\n", next);
	printf("\tprev: %llx\n", prev);
}

static void
hook_malloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{

}

static void
read_usbtx_buf(uc_engine *uc, uint8_t *buf, uint32_t size)
{
	uint64_t addr0, addr1;
	uc_mem_read(uc, 0x8f0ffab0, &addr0, sizeof(uint64_t));
	uc_mem_read(uc, addr0, &addr1, sizeof(uint64_t));
	uc_mem_read(uc, addr1, buf, size);
}

static void
hook_usb_packet(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint8_t buf[1000];
	uint64_t addr;
	uc_emu_stop(uc);
	addr = call_malloc(uc, 1000);
	while (1) {
		show_heap(uc);
		memset(buf, 0, 1000);
		read(0, buf, 1000);
		uc_mem_write(uc, addr, buf, 1000);
		call_usbd3_rdx_process(uc, addr, 1000);
		read_usbtx_buf(uc, buf, 1000);
		printf("%s\n", buf);
	}
}

static void
interrupt_handler(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	int64_t x0, x1, x2, pc, next_pc;
	int64_t x21, val;
	int64_t ret = 0xffffffff;
	uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
	uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
	uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
	next_pc = pc + 4;

	switch (x0) {
	case 0xc2001014: // read_otp
		switch (x1) {
		case 0x10c:
			ret = 0;
			val = 0x01;
			break;
		case 0x10d: // MODEL_ID
			ret = 0;
			val = 0x2c;
			break;
		case 0x109:
			ret = 0;
			val = 0x02;
			break;
		case 0x102: // BAN_ROM_SEC_BOOT_KEY
			ret = 0;
			val = 0x00;
			break;
		case 0x101: // USE_ROM_SEC_BOOT_KEY
			ret = 0;
			val = 0x00;
			break;
		case 0x103:
			ret = 0;
			val = 0x00;
			break;
		case 0x106: // ANTIBRK_NS_AP0
			ret = 0;
			val = 0x02;
			break;
		case 0x107: // ANTIBRK_NS_AP1
			ret = 0;
			val = 0x02;
			break;
		case 0x10e: // COMMERCIAL
			ret = 0;
			val = 0x01;
			break;
		case 0x10f: // TEST
			ret = 0;
			val = 0x00;
			break;
		case 0x110: // WARRANTY
			ret = 0;
			val = 0x00;
			break;
		case 0x104:
			ret = 0;
			val = 0;
			break;
		case 0x105: // JTAG_SW_LOCK
			ret = 0;
			val = 0x01;
			break;
		case 0x112: // ENABLE_ANTIBRK
			ret = 0;
			val = 0x01;
			break;
		case 0x111: // USE_PREORDER_KEY
			ret = 0;
			val = 0x01;
			break;
		case 0x113: // ENABLE_MODEL_ID
			ret = 0;
			val = 0x01;
			break;
		case 0x10b: // CUSTOM_FLAG
			ret = 0;
			switch (x2) {
			case 0x06:
				val = 0x0;
				break;
			case 0x07:
				val = 0x1;
				break;
			case 0x08:
				val = 0x1;
				break;
			case 0x09:
				val = 0x0;
				break;
			default:
				val = 0x0;
				break;
			}
			break;
		default:
			goto fail;
		}
		uc_reg_write(uc, UC_ARM64_REG_X2, &val);
		break;

	case 0xffffff0d: // SMC Read
		switch (x2) {
		case 0x0:
			ret = 2;
			break;
		case 0x1:
			ret = 1;
			break;
		default:
			ret = 0;
			break;
		}
		break;

	case 0xc2001018:
		ret = 0;
		break;

	default:
		goto fail;
		break;
	}

	uc_reg_write(uc, UC_ARM64_REG_X0, &ret);
	uc_reg_write(uc, UC_ARM64_REG_PC, &next_pc);

	return;

fail:
	dump_regs(uc);
	uc_emu_stop(uc);
}

static void
force_debug_hook(uc_engine *uc, uc_mem_type type, uint64_t address,
    int size, int64_t value, void *user_data)
{
	uint64_t val = 0x00;
	uc_mem_write(uc, 0x8f1041c0, &val, sizeof(uint64_t));
	return;
}

static int
init_filesystem(char *dir)
{
	struct dirent *de;
	DIR *dr = opendir(dir);
	if (!dr)
		return 0;

	while ((de = readdir(dr))) {
		if (!strcmp(de->d_name, "pit"))
			sprintf(pit_file, "%s/%s", dir, de->d_name);
		if (!strcmp(de->d_name, "param.bin"))
			sprintf(param_file, "%s/%s", dir, de->d_name);
		if (!strcmp(de->d_name, "up_param.bin"))
			sprintf(up_param_file, "%s/%s", dir, de->d_name);
	}

	printf("%s\n", param_file);

	closedir(dr);
	return 0;
}

static void
usb_event_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	/* struct input_state *state = (struct input_state *) user_data; */
	/* uc_emu_stop(uc); */
	/* state->usb->event_count = 1; */
	/* n = recv(sock, buf, n); */

	/* uc_mem_write(uc, state->usb->event_addr_lo0, buf, n); */
	/* uc_emu_start(uc); */
}

int
main(int argc, char **argv)
{
	uc_engine *uc;
	uc_err err;
	int64_t sp = INITIAL_SP;
	int64_t reg;
	uint64_t end;
	uc_hook trace, chipid, allocation, stop, interrupt, force_debug, free;

	if (argc < 3) {
		printf("usage: %s <bl2> <files>\n", argv[0]);
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

	init_filesystem(argv[2]);

	if ((err = load_image(uc, argv[1], CODE_BASE, &end)) != UC_ERR_OK) {
		printf("load_image: %s\n", uc_strerror(err));
		goto cleanup;
	}

	uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
	uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &reg);
	reg |= 0x300000;
	uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &reg);

	uc_hook_add(uc, &interrupt, UC_HOOK_INTR, interrupt_handler, NULL, 1, 0);
	uc_hook_add(uc, &chipid, UC_HOOK_MEM_READ, pmic_chipid_callback, NULL,
	    0x8f4184c0, 0x8f4184c0);
	uc_hook_add(uc, &force_debug, UC_HOOK_MEM_READ, force_debug_hook, NULL, 1, 0);
	uc_hook_add(uc, &free, UC_HOOK_CODE, hook_free, NULL, FREE, FREE);
	uc_hook_add(uc, &stop, UC_HOOK_CODE, hook_usb_packet, NULL,
	    USB_EVENT_LOOP_TOP, USB_EVENT_LOOP_TOP);

	// uc_hook_add(uc, &stop, UC_HOOK_CODE, hook_quit, NULL,
	//  EXYNOS_USB_HANDLE_EVENT, EXYNOS_USB_HANDLE_EVENT + 0x200);

	// uc_hook_add(uc, &trace, UC_HOOK_CODE, trace_hook, NULL, 1, 0);
	// uc_hook_add(uc, &trace, UC_HOOK_CODE, trace_hook, NULL, 0x8f050010, 0x8f050200);
	// uc_hook_add(uc, &trace, UC_HOOK_CODE, trace_hook, NULL,
	// uc_hook_add(uc, &trace, UC_HOOK_CODE, trace_hook, NULL, USB_EVENT_LOOP,
	// USB_EVENT_LOOP+0x13c);

	// EXYNOS_USB_HANDLE_EVENT, EXYNOS_USB_HANDLE_EVENT + 0x200);
	// uc_hook_add(uc, &stop, UC_HOOK_CODE, hook_quit, NULL, 0x8f05da58, 0x8f05da58);
	// uc_hook_add(uc, &stop, UC_HOOK_CODE, hook_quit, NULL, 0x8f05d9f0, 0x8f05d9f0);
	// uc_hook_add(uc, &stop, UC_HOOK_CODE, hook_quit, NULL, 0x8f05c194, 0x8f05c194);
	// uc_hook_add(uc, &stop, UC_HOOK_CODE, hook_quit, NULL, 0x8f05da04, 0x8f05da04);
	// uc_hook_add(uc, &stop, UC_HOOK_CODE, hook_quit, NULL, 0x8f05e78c, 0x8f05e78c);
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
