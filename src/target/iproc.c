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
#define IPROC_CCB_WATCHDOG 0x18039000 // base of watchdog

#define IPROC_CCB_WDT_WDOGCONTROL (IPROC_CCB_WATCHDOG+0x8)
#define IPROC_CCB_WDT_WDOGLOCK (IPROC_CCB_WATCHDOG+0xc00)
#define IPROC_CCB_WDT_UNLOCK_CODE 0x1ACCE551
#define IPROC_CCB_WDT_WDOGPERIPHID(n) (IPROC_CCB_WATCHDOG+0xfe0+4*(n))
#define IPROC_CCB_WDT_WDOGPCELLID(n)  (IPROC_CCB_WATCHDOG+0xff0+4*(n))

#define IPROC_NAND_REVISION (IPROC_CCA_NAND+0x0)
#define IPROC_NAND_CMD_START (IPROC_CCA_NAND+0x4)
#define IPROC_NAND_EXT_ADDRESS (IPROC_CCA_NAND+0x8)
#define IPROC_NAND_ADDRESS (IPROC_CCA_NAND+0xc)
#define IPROC_NAND_END_ADDRESS (IPROC_CCA_NAND+0x10)
#define IPROC_NAND_END_ADDRESS (IPROC_CCA_NAND+0x10)
#define IPROC_NAND_INTFC_STATUS (IPROC_CCA_NAND+0x14)
#define IPROC_NAND_SELECT (IPROC_CCA_NAND+0x18)
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

bool iproc_cmd_id(target *t)
{
	uint32_t x = target_mem_read32(t, IPROC_CCA_CHIPID);
	tc_printf(t, "CCA_CHIPID 0x%"PRIx32"\n", x);

	x = target_mem_read32(t, IPROC_NAND_REVISION);
	tc_printf(t, "NAND_REVISION 0x%"PRIx32"\n", x);

	x = target_mem_read32(t, IPROC_NAND_FLASH_DEVICE_ID);
	tc_printf(t, "NAND_FLASH_DEVICE_ID 0x%"PRIx32"\n", x);

	return true;
}

const struct command_s iproc_cmd_list[] = {
	{"id", (cmd_handler)iproc_cmd_id, "Show device id registers"},
	{NULL, NULL, NULL}
};

static int iproc_flash_erase(struct target_flash *f, target_addr addr, size_t len)
{
	//target *t = f->t;
	addr -= f->start;
	while (len) {
		// erase the block at offset 'addr'
		DEBUG("iproc erase at %"PRIx32"\n", addr);
		addr += f->blocksize;
		len -= f->blocksize;
	}

	return 0;
}

static int iproc_flash_write(struct target_flash *f, target_addr dest,
                             const void *src, size_t len)
{
	target *t = f->t;
	target_mem_write(t, IPROC_NAND_FLASH_CACHE(0), src, len);

	dest -= f->start;

	DEBUG("iproc write %zu at %"PRIx32"\n", len, dest);

	return 0;
}

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
	// TODO what happens on other CPUs when we read this strange address?
	// I'd really like a better way to ID an iproc, but there isn't anything non-generic
	// in the AP registers that I can find.

	// is it an iproc? check the chipid register's lower 16 bits
	uint32_t chipid = target_mem_read32(t, IPROC_CCA_CHIPID);
	DEBUG("iproc chipid=%"PRIx32"\n", chipid);
	if ((chipid & 0xffff) != 0xcf1e) {
		return false;
	}

	// does it have a NAND controller we support? Earlier than rev 6 is untested
	uint32_t nand_rev = target_mem_read32(t, IPROC_NAND_REVISION);
	if ((/*major rev*/(nand_rev>>8)&0xff) < 6) {
		DEBUG("iproc nand_rev %"PRIx32" too old\n", nand_rev);
		return false;
	}

	uint32_t init_status = target_mem_read32(t, IPROC_NAND_INIT_STATUS);
	if (!(init_status & (1<</*DEVICE_ID_INIT_DONE*/30))) {
		DEBUG("iproc no DEV ID\n");
		return false;
	}

	//uint32_t nand_dev_id = target_mem_read32(t, IPROC_NAND_FLASH_DEVICE_ID);
	//DEBUG("iproc_probe nand_dev_id=%"PRIx32"\n", nand_dev_id);

	// does the NAND device support ONFI? non-ONFI is not supported, though it could be if someone wanted it
	// ONFI is just a convenient way to get hold of the NAND device's page/oob/block sizes
	uint32_t onfi_status = target_mem_read32(t, IPROC_NAND_ONFI_STATUS);
	DEBUG("iproc_probe init_status=%"PRIx32", onfi_status=%"PRIx32"\n", init_status, onfi_status);
	if (!(init_status & (1<</*ONFI_INIT_DONE*/31)) || !(onfi_status & (1<</*ONFI_detected*/27))) {
		DEBUG("iproc no ONFI\n");
		return false;
	}

	// target seems usable

	/*
	if (!iproc_watchdog_disable(t)) {
		DEBUG("Unable to disable iproc watchdog\n");
		// and continue anyway
	}
	*/

	t->driver = "iproc";
	//target_add_commands(t, iproc_cmd_list, "iproc");
	//target_add_ram(t, 0x0, 256<<20);

	// read NAND sizes from ONFI data
	onfi_status &= ~(0xf<<28);
	for (uint32_t i=0;i<8;i++) {
		target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (i<<28));
		uint32_t x = target_mem_read32(t, IPROC_NAND_ONFI_DATA);
		DEBUG("ONFI[%"PRIu32"] %"PRIx32"\n", i, x);
	}

	// TODO remove HACK
	return true;

	/*
	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (2<<28));
	uint32_t bytes_per_page = target_mem_read32(t, IPROC_NAND_ONFI_DATA);
	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (3<<28));
	uint32_t row_col_size = target_mem_read32(t, IPROC_NAND_ONFI_DATA);
	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (4<<28));
	uint32_t blocks_per_lun = target_mem_read32(t, IPROC_NAND_ONFI_DATA);
	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (5<<28));
	uint32_t pages_per_blocks = target_mem_read32(t, IPROC_NAND_ONFI_DATA);
	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (6<<28));
	uint32_t page_and_block_size = target_mem_read32(t, IPROC_NAND_ONFI_DATA);
	target_mem_write32(t, IPROC_NAND_ONFI_STATUS, onfi_status | (7<<28));
	uint32_t device_size = target_mem_read32(t, IPROC_NAND_ONFI_DATA);
	*/
	
	uint32_t pagesize = 2048;
	uint32_t blocksize = pagesize *64;
	uint32_t totalsize = blocksize * 2048;

	struct target_flash* f = calloc(1, sizeof(*f));
	f->start = 0; // TODO figure out where we should pretend the NAND lives
	f->length = totalsize;
	f->blocksize = blocksize;
	f->erase = iproc_flash_erase;
	f->write = target_flash_write_buffered;
	f->done = target_flash_done_buffered;
	f->erased = 0xff;
	f->buf_size = 512;
	f->write_buf = iproc_flash_write;
	target_add_flash(t, f);

	return true;
}
