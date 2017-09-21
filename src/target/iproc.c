/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright (C) 2015  Black Sphere Technologies Ltd.
 * Written by Gareth McMullin <gareth@blacksphere.co.nz>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* This file implements iproc target specific functions providing
 * the XML memory map and Flash memory programming.
 */

#include "general.h"
#include "target.h"
#include "target_internal.h"

#define IPROC_CCA_CHIPID 0x18000000
#define IPROC_CCA_NAND 0x18026000 // base of NAND controller
#define IPROC_CCA_IDM 0x18100000 // base of IDM registers
#define IPROC_CCB_WATCHDOG 0x18039000 // base of watchdog

// watchdog
#define IPROC_CCB_WDT_WDOGCONTROL (IPROC_CCB_WATCHDOG+0x8)
#define IPROC_CCB_WDT_WDOGLOCK (IPROC_CCB_WATCHDOG+0xc00)
#define IPROC_CCB_WDT_UNLOCK_CODE 0x1ACCE551
#define IPROC_CCB_WDT_WDOGPERIPHID(n) (IPROC_CCB_WATCHDOG+0xfe0+4*(n))
#define IPROC_CCB_WDT_WDOGPCELLID(n)  (IPROC_CCB_WATCHDOG+0xff0+4*(n))

// NAND controller
#define IPROC_NAND_REVISION (IPROC_CCA_NAND+0x0)
#define IPROC_NAND_CMD_START (IPROC_CCA_NAND+0x4)
#define IPROC_NAND_EXT_ADDRESS (IPROC_CCA_NAND+0x8)
#define IPROC_NAND_ADDRESS (IPROC_CCA_NAND+0xc)
#define IPROC_NAND_END_ADDRESS (IPROC_CCA_NAND+0x10)
#define IPROC_NAND_INTFC_STATUS (IPROC_CCA_NAND+0x14)
#define IPROC_NAND_CS_NAND_SELECT (IPROC_CCA_NAND+0x18)
#define IPROC_NAND_ACC_CONTROL_CS(cs) (IPROC_CCA_NAND+0x50+0x10*(cs))
#define IPROC_NAND_CONFIG_CS(cs) (IPROC_CCA_NAND+0x54+0x10*(cs))
#define IPROC_NAND_TIMING_1_CS(cs) (IPROC_CCA_NAND+0x58+0x10*(cs))
#define IPROC_NAND_TIMING_2_CS(cs) (IPROC_CCA_NAND+0x5c+0x10*(cs))
#define IPROC_NAND_BLK_WR_PROTECT (IPROC_CCA_NAND+0xc8)
#define IPROC_NAND_UNCORR_ERROR_COUNT (IPROC_CCA_NAND+0xfc)
#define IPROC_NAND_CORR_ERROR_COUNT (IPROC_CCA_NAND+0x100) // zeroes before every read operation
#define IPROC_NAND_READ_ERROR_COUNT (IPROC_CCA_NAND+0x104) // zeroes only when written
#define IPROC_NAND_BLOCK_LOCK_STATUS (IPROC_CCA_NAND+0x108)
#define IPROC_NAND_INIT_STATUS (IPROC_CCA_NAND+0x144)
#define IPROC_NAND_ONFI_STATUS (IPROC_CCA_NAND+0x148)
#define IPROC_NAND_ONFI_DATA (IPROC_CCA_NAND+0x14c)
#define IPROC_NAND_FLASH_DEVICE_ID (IPROC_CCA_NAND+0x194)
#define IPROC_NAND_FLASH_DEVICE_ID_EXT (IPROC_CCA_NAND+0x198)
#define IPROC_NAND_FLASH_CACHE(n) (IPROC_CCA_NAND+0x400+4*(n)) // 0 <= n <= 127, for a 512 byte sub-page (but complete ECC block) cache
#define IPROC_NAND_block_erase_complete (IPROC_CCA_NAND+0xf04)
#define IPROC_NAND_program_page_complete (IPROC_CCA_NAND+0xf0c)
#define IPROC_NAND_ro_ctlr_ready (IPROC_CCA_NAND+0xf10)
#define IPROC_NAND_nand_rb_b (IPROC_CCA_NAND+0xf14)
#define IPROC_NAND_ecc_uncorr (IPROC_CCA_NAND+0xf18)
#define IPROC_NAND_ecc_corr (IPROC_CCA_NAND+0xf1c)

#define IPROC_IDM_NAND_IO_CONTROL_DIRECT (IPROC_CCA_IDM+0x1b408)
#define IPROC_IDM_NAND_RESET_CONTROL (IPROC_CCA_IDM+0x1b800)

// values for IPROC_NAND_CMD_START[28:24]
#define IPROC_NAND_OPCODE_PAGE_READ 1
#define IPROC_NAND_OPCODE_SPARE_AREA_READ 2
#define IPROC_NAND_OPCODE_STATUS_READ 3
#define IPROC_NAND_OPCODE_PROGRAM_PAGE 4
#define IPROC_NAND_OPCODE_PROGRAM_SPARE_AREA 5
#define IPROC_NAND_OPCODE_DEVICE_ID_READ 7
#define IPROC_NAND_OPCODE_BLOCK_ERASE 8
#define IPROC_NAND_OPCODE_FLASH_RESET 9
#define IPROC_NAND_OPCODE_BLOCKS_LOCK 10
#define IPROC_NAND_OPCODE_BLOCKS_LOCK_DOWN 11
#define IPROC_NAND_OPCODE_BLOCKS_UNLOCK 12
#define IPROC_NAND_OPCODE_READ_BLOCK_LOCK_STATUS 13

static int iproc_flash_erase(struct target_flash *f, target_addr addr, size_t len)
{
	//target *t = f->t;
	addr -= f->start;
	while (len) {
		// erase the block at offset 'addr'
		DEBUG("pretend iproc erase at %"PRIx32"\n", addr);
		addr += f->blocksize;
		len -= f->blocksize;
	}

	return 0;
}

static int iproc_flash_write(struct target_flash *f, target_addr dest,
                             const void *src, size_t len)
{
	target *t = f->t;
	int rc = target_mem_write(t, IPROC_NAND_FLASH_CACHE(0), src, len);
	if (rc)
		return rc;

	dest -= f->start;

	DEBUG("pretend iproc write %zu at %"PRIx32"\n", len, dest);

	return 0;
}

static int iproc_flash_read(struct target_flash *f, void *dst,
                             target_addr src, size_t len)
{
	target *t = f->t;
	src += f->start;

	// zero the uncorrectable ECC error counter
	target_mem_write32(t, IPROC_NAND_UNCORR_ERROR_COUNT, 0);

	// disable cache hits when reading the first subpage. we don't need them
	uint32_t acc_ctrl = target_mem_read32(t, IPROC_NAND_ACC_CONTROL_CS(0));
	DEBUG("acc_ctrl %"PRIx32"\n", acc_ctrl);
	acc_ctrl &= ~(/*PAGE_HIT_EN*/1<<24);
	target_mem_write32(t, IPROC_NAND_ACC_CONTROL_CS(0), acc_ctrl);

	while (len) {
		target_mem_write32(t, IPROC_NAND_EXT_ADDRESS, 0); // assume CS 0, and under 4 GB
		target_mem_write32(t, IPROC_NAND_ADDRESS, src);
		target_mem_write32(t, IPROC_NAND_CMD_START, IPROC_NAND_OPCODE_PAGE_READ<<24);
		uint32_t st;
		while (true) {
			st = target_mem_read32(t, IPROC_NAND_INTFC_STATUS);
			if (st & (/*CTRL_READY*/1<<31))
				break;
		}

		// copy out the data even if ECC failed
		size_t n = len;
		if (n > 512)
			n = 512;
		int rc = target_mem_read(t, dst, IPROC_NAND_FLASH_CACHE(0), len);
		if (rc)
			return rc;

		// check for uncorrectable errors?
		// these most often happen in erased pages with bit flips, since iproc nand controller doesn't correct these
		// (the designers failed to make the ECC value of an erased page be 0xfff)
		uint32_t uncorr = target_mem_read32(t, IPROC_NAND_UNCORR_ERROR_COUNT);
		DEBUG("uncorr %"PRIu32"\n", uncorr);
		if (uncorr != 0) {
			//return -2;
		}

		if (!(st & (/*CACHE_VALID*/1<<29))) {
			//return -1;
		}

		dst = (char*)dst + n;
		len -= n;
	}

	return 0;
}

static bool iproc_cmd_id_hw(target *t)
{
	uint32_t x = target_mem_read32(t, IPROC_CCA_CHIPID);
	tc_printf(t, "CCA_CHIPID 0x%"PRIx32"\n", x);

	x = target_mem_read32(t, IPROC_NAND_REVISION);
	tc_printf(t, "NAND_REVISION 0x%"PRIx32"\n", x);

	x = target_mem_read32(t, IPROC_NAND_FLASH_DEVICE_ID);
	tc_printf(t, "NAND_FLASH_DEVICE_ID 0x%"PRIx32"\n", x);

	return true;
}

static bool iproc_cmd_nand_read(target *t, int argc, const char *argv[])
{
	if (argc != 2) {
		tc_printf(t, "usage: nand-read <pagenum>\n");
		return false;
	}

	// arg is the NAND page number
	unsigned long pagenum = strtoul(argv[1], NULL, 0);

	struct target_flash* f = t->flash;
	if (!f) {
		// no flash was found
		return false;
	}

	const int page_size = 2048;
	uint8_t buf[page_size];
	memset(buf, 0xff, page_size);
	int rc = iproc_flash_read(f, buf, (target_addr)pagenum * page_size, page_size);
	if (rc) {
		tc_printf(t, "read failed: %d\n", rc);
		return false;
	}

	tc_printf(t, "NAND page %lu\n", pagenum);
	for (int i=0; i<page_size; i+=16) {
		tc_printf(t, "%03x: ", i);
		for (int j=0; j<16; j++) {
			uint8_t x = buf[i+j];
			tc_printf(t, "%02x ", x);
		}
		tc_printf(t, "\n");
	}

	return true;
}

const struct command_s iproc_cmd_list[] = {
	{"id-hw", (cmd_handler)iproc_cmd_id_hw, "Show iproc id registers"},
	{"nand-read", iproc_cmd_nand_read, "Show NAND page"},
	{NULL, NULL, NULL}
};

bool iproc_watchdog_disable(target *t)
{
	// make sure it looks like a watchdog we understand
	static const uint8_t expected_cellid[4] = { 0x0d, 0xf0, 0x05, 0xb1 };
	static const uint8_t expected_periphid[4] = { 0x05, 0x18, 0x14, 0x00 };
	uint32_t x;
	for (int i=0; i<4; i++) {
		x = target_mem_read32(t, IPROC_CCB_WDT_WDOGPCELLID(i));
		if ((x & 0xff) != expected_cellid[i])
			return false;
		x = target_mem_read32(t, IPROC_CCB_WDT_WDOGPERIPHID(i));
		if ((x & 0xff) != expected_periphid[i])
			return false;
	}

	// unlock the watchdog registers (if needed)
	target_mem_write32(t, IPROC_CCB_WDT_WDOGLOCK, IPROC_CCB_WDT_UNLOCK_CODE);
	// disable both the iterrupt and the reset
	target_mem_write32(t, IPROC_CCB_WDT_WDOGCONTROL, 0);

	// and see how we did
	x = target_mem_read32(t, IPROC_CCB_WDT_WDOGCONTROL);
	DEBUG("wdogcontrol %"PRIx32"\n", x);
	return (x&3) == 0;
}

bool iproc_probe(target *t)
{
	DEBUG("iproc_probe\n");

	// TODO what happens on other CPUs when we read this address?
	// I'd really like a better way to ID an iproc, but there isn't anything non-generic
	// in the AP registers that I can find.

	// is it an iproc? check the chipid register's lower 16 bits
	uint32_t chipid = target_mem_read32(t, IPROC_CCA_CHIPID);
	DEBUG("iproc chipid=%"PRIx32"\n", chipid);
	if ((chipid & 0xffff) != 0xcf1e) {
		return false;
	}

	// do we need to reset the NAND controller and force it to reconfigure itself via ONFI?
	// it might be a good idea if firmware left the NAND in a strange state.

	// reset the NAND controller
	target_mem_write32(t, IPROC_IDM_NAND_RESET_CONTROL, 1);
	platform_delay(1);
	target_mem_write32(t, IPROC_IDM_NAND_RESET_CONTROL, 0);
	platform_delay(1);
	uint32_t reset_ctrl = target_mem_read32(t, IPROC_IDM_NAND_RESET_CONTROL);
	DEBUG("iproc reset_ctrl=%"PRIx32"\n", reset_ctrl);
	if (reset_ctrl != 0) {
		DEBUG("iproc nand stuck in reset\n");
		return false;
	}

	// configure the NAND controller's APB and AXI interfaces
	// we run them in their default endiannesses and fix it up in software here
	target_mem_write32(t, IPROC_IDM_NAND_IO_CONTROL_DIRECT, (/*clk_enable*/1<<0));

	// does it have a NAND controller we support? Earlier than rev 6 is untested
	uint32_t nand_rev = target_mem_read32(t, IPROC_NAND_REVISION);
	DEBUG("iproc nand_rev=%"PRIx32"\n", nand_rev);
	if ((/*major rev*/(nand_rev>>8)&0xff) < 6) {
		DEBUG("iproc nand_rev %"PRIx32" too old\n", nand_rev);
		return false;
	}

	// and re-init the NAND controller
	uint32_t cs_nand_sel = target_mem_read32(t, IPROC_NAND_CS_NAND_SELECT);
	DEBUG("iproc cs_nand_sel=%"PRIx32"\n", cs_nand_sel);
	cs_nand_sel &= ~(/*DIRECT_ACCESS*/0xff<<0); // disable memory mapped NAND, so we can use the NAND controller
	cs_nand_sel &= ~((/*AUTO_DEVICE_ID_CONFIG*/1<<30)+(/*NAND_WP*/1<<29)+(/*WR_PROTECT_BLK0*/1<<28));
	target_mem_write32(t, IPROC_NAND_CS_NAND_SELECT, cs_nand_sel);
	cs_nand_sel |= (/*AUTO_DEVICE_ID_CONFIG*/1<<30);
	target_mem_write32(t, IPROC_NAND_CS_NAND_SELECT, cs_nand_sel);

	// give the NAND 1 second to initialize itself
	uint32_t init_status = target_mem_read32(t, IPROC_NAND_INIT_STATUS);
	while (!(init_status & (/*INIT_SUCCESS,FAIL,BLANK,TIMEOUT,UNC_ERROR,CORR_ERROR,PARAMETER_READY,AUTHENTICATION_FAIL*/0xff<<22))) {
		init_status = target_mem_read32(t, IPROC_NAND_INIT_STATUS);
	}
	DEBUG("iproc nand init_status=%"PRIx32"\n", init_status);

	if (!(init_status & (/*INIT_SUCCESS*/1<<29))) {
		DEBUG("iproc NAND init failure, %"PRIx32"\n", init_status);
		return false;
	}

	// does the NAND device support ONFI? non-ONFI is not supported, though it could be if someone wanted it
	// ONFI is just a convenient way to get hold of the NAND device's page/oob/block sizes. Otherwise they'd
	// have to look at IPROC_NAND_FLASH_DEVICE_ID and have a table of known NAND devices.
	uint32_t onfi_status = target_mem_read32(t, IPROC_NAND_ONFI_STATUS);
	DEBUG("iproc nand onfi_status=%"PRIx32"\n", onfi_status);
	if (!(init_status & (1<</*ONFI_INIT_DONE*/31)) || !(onfi_status & (1<</*ONFI_detected*/27))) {
		DEBUG("iproc no ONFI\n");
		// NOTE: should someone someday need to support NANDs which don't implement ONFI they'll have to set up the timing
		// and parameter registers themselves, using what they know about the NAND given its' device ID.
		return false;
	}

	// configure for ONFI timing mode 0 (the slowest)
	target_mem_write32(t, IPROC_NAND_TIMING_1_CS(0), 0xd8d8558d);
	target_mem_write32(t, IPROC_NAND_TIMING_2_CS(0), 0x00000c83);

	if (!iproc_watchdog_disable(t)) {
		DEBUG("Unable to disable iproc watchdog\n");
		// and continue anyway
	}

	// read NAND sizes from ONFI-derived data
	onfi_status &= ~(0xf<<28);

#ifdef ENABLE_DEBUG
	// dump the ONFI-derived data registers
	for (uint32_t i=0;i<8;i++) {
		target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (i<<28));
		uint32_t x = target_mem_read32(t, IPROC_NAND_ONFI_DATA);
		DEBUG("ONFI[%"PRIu32"] %"PRIx32"\n", i, x);
	}
#endif

	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (2<<28));
	uint32_t bytes_per_page = target_mem_read32(t, IPROC_NAND_ONFI_DATA); // for example: 2048
	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (4<<28));
	uint32_t blocks_per_lun = target_mem_read32(t, IPROC_NAND_ONFI_DATA); // for example: 2048 again
	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (5<<28));
	uint32_t pages_per_block = target_mem_read32(t, IPROC_NAND_ONFI_DATA); // for example: 64

	uint32_t blocksize = bytes_per_page * pages_per_block;
	uint64_t totalsize = (uint64_t)blocksize * (uint64_t)blocks_per_lun; // NOTE: iproc seems to assume one LUN. should someone need to support more they'll have to read the onfi parameters directly from the NAND, rather than relying on the iproc nand controller's interpretation of the ONFI parameters
	DEBUG("%"PRIu64"MB NAND with %"PRIu32" blocks of %"PRIu32"kB, each containing %"PRIu32" pages of %"PRIu32" bytes\n", totalsize>>20, blocks_per_lun, blocksize>>10, pages_per_block, bytes_per_page);

	// clamp totalsize at whatever size_t can hold
	if (totalsize != (uint64_t)(size_t)totalsize) {
		totalsize = (size_t)~(uint64_t)0;
		DEBUG("totalsize clamped to %"PRIu64"MB\n", totalsize>>20);
	}

	struct target_flash* f = calloc(1, sizeof(*f));
	f->start = 0; // TODO figure out where we should pretend the NAND lives
	f->length = (size_t)totalsize;
	f->blocksize = blocksize;
	f->erase = iproc_flash_erase;
	f->write = target_flash_write_buffered;
	f->done = target_flash_done_buffered;
	f->erased = 0xff;
	f->buf_size = 512; // AFAICT the iproc nand controller assumes a 512 byte sub-page write
	f->write_buf = iproc_flash_write;

	t->driver = "iproc";
	target_add_commands(t, iproc_cmd_list, "iproc");
	target_add_ram(t, 0x0, 256<<20);
	target_add_flash(t, f);

	return true;
}
