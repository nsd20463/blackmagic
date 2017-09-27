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

// hardcoded things which might need to change for new iproc hardware
#define IPROC_SUBPAGE_SIZE 512 // nand page are broken into 512 byte subpages, each with its own ECC
#define IPROC_SUBPAGE_SPARE_SIZE 64 // max size of spare bytes for each subpage
#define IPROC_NAND_WINDOW 0x1c000000 // physical address where an image of NAND appears when in boot mode and CPU is strapped to boot from NAND

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
#define IPROC_NAND_SPARE_AREA_READ(n) (IPROC_CCA_NAND+0x200+4*(n)) // 0 <= n <= 15, for a max of 64 bytes spare area per subpage
#define IPROC_NAND_SPARE_AREA_WRITE(n) (IPROC_CCA_NAND+0x280+4*(n)) // <same>
#define IPROC_NAND_FLASH_CACHE(n) (IPROC_CCA_NAND+0x400+4*(n)) // 0 <= n <= 127, for a 512 byte sub-page (ECC block) cache
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

// additional data added to our target_flash structures
struct iproc_flash {
	struct target_flash f;
	size_t pagesize; // learned from ONFI; typically 2048
	target_addr badblock_offset; // byte offset due to bad blocks found during this write (typically each file written starts at a known page, and skips any bad blocks)
};

// convert to/from big-endian uint32
static inline uint32_t htofrombe_uint32(uint32_t x) {
	// BMP is little-endian, so swap x's bytes around
	return (x>>24) + + ((x >> 8) & 0xff00) + ((x & 0xff00) << 8) + (x<<24);
}

// inplace endianess swap of each uint32_t in a potentially misaligned buffer
static void uint32_endianess_swap(uint8_t *buf, size_t len)
{
	for (size_t i=0; i+3<len; i+=4, buf+=4) {
		uint32_t x;
		memcpy(&x, buf, 4);
		x = htofrombe_uint32(x);
		memcpy(buf, &x, 4);
	}
}

// read from the flash. src ought to be nand-page aligned
// if spare is non-NULL then the spare area is also read. there needs to be 64*num-subpages-per-page
// NOTE the source argument is the byte offset from the base of flash, NOT a memory address
static int iproc_flash_read(struct target_flash *f, uint32_t errors[2], uint8_t *dst, uint32_t offset, size_t len, uint8_t *spare)
{
	target *t = f->t;

	if (errors) {
		errors[0] = 0;

		// zero the uncorrectable ECC error counter. unlike the correctable error counter this one doesn't zero itself before every read operation
		target_mem_write32(t, IPROC_NAND_UNCORR_ERROR_COUNT, 0);
	}

	// disable cache hits when reading the first subpage. we don't need (or want) them
	// note if we wanted more speed in the future we could re-enable the page cache after the first subpage
	uint32_t acc_ctrl = target_mem_read32(t, IPROC_NAND_ACC_CONTROL_CS(0));
	acc_ctrl &= ~(/*PAGE_HIT_EN*/1<<24);
	target_mem_write32(t, IPROC_NAND_ACC_CONTROL_CS(0), acc_ctrl);

	while ((ssize_t)len > 0) {
		target_mem_write32(t, IPROC_NAND_EXT_ADDRESS, 0); // assume CS 0, and under 4 GB
		target_mem_write32(t, IPROC_NAND_ADDRESS, offset);
		target_mem_write32(t, IPROC_NAND_CMD_START, (dst ? IPROC_NAND_OPCODE_PAGE_READ : IPROC_NAND_OPCODE_SPARE_AREA_READ)<<24);

		// wait for controller to be done
		uint32_t st;
		while (true) {
			st = target_mem_read32(t, IPROC_NAND_INTFC_STATUS);
			if (st & (/*CTRL_READY*/1<<31))
				break;
		}

		size_t n = len;
		if (n > IPROC_SUBPAGE_SIZE)
			n = IPROC_SUBPAGE_SIZE;

		if (dst) {
			// copy out the data even if ECC failed
			int rc = target_mem_read(t, dst, IPROC_NAND_FLASH_CACHE(0), n);
			if (rc)
				return rc;

			// fix endianess of data we just read. it arrives as big-endian uint32_t
			uint32_endianess_swap(dst, n);
		}

		if (spare) {
			int rc = target_mem_read(t, spare, IPROC_NAND_SPARE_AREA_READ(0), IPROC_SUBPAGE_SPARE_SIZE);
			if (rc)
				return rc;
			uint32_endianess_swap(spare, IPROC_SUBPAGE_SPARE_SIZE);
		}

		if (errors)
			errors[0] += target_mem_read32(t, IPROC_NAND_CORR_ERROR_COUNT);

		offset += n;
		if (dst)
			dst += n;
		if (spare)
			spare += IPROC_SUBPAGE_SPARE_SIZE;
		len -= n;
	}

	if (errors)
		errors[1] = target_mem_read32(t, IPROC_NAND_UNCORR_ERROR_COUNT);

	return 0;
}

// return true if the block at offset is marked as bad
// NOTE the source argument is the byte offset from the base of flash, NOT a memory address
static bool iproc_is_bad_block(struct target_flash *f, target_addr offset)
{
	const int page_size = ((struct iproc_flash*)f)->pagesize;
	const int spare_size = page_size / IPROC_SUBPAGE_SIZE * IPROC_SUBPAGE_SPARE_SIZE;
	uint8_t buf[spare_size];

	// ONFI spec says the block is bad if any of the spare area bytes of the first or
	// last page are 0x00. However ECC uses some of those bytes, and might have written
	// 0x00 legitimately. (ONFI's idea is that you're going to read the ONFI bad block
	// markers only once, and store them elsewhere in a data structure you persist
	// redudantly, so the trouble doesn't occur, but we wouldn't know where that
	// data structure was and how to interpret it)
	// Linux works around this by checking only the first byte of the spare areas,
	// rather than the entire area (NAND_LARGE_BADBLOCK_POS). (Linux also considers
	// the block bad if any bit is 0). That avoids the ECC bytes since ECC starts
	// at the 3rd byte.
	for (int j=0; j < 2; j++) {
		memset(buf, 0xff, sizeof(buf));
		int rc = iproc_flash_read(f, NULL, NULL, offset + (j==0 ? 0 : f->blocksize - page_size), page_size, buf);
		if (rc)
			return true; // better to be safe

		if (buf[0] != 0xff) // same check as linux
			return true;
	}

	return false;
}

static int iproc_flash_erase(struct target_flash *f, target_addr addr, size_t len)
{
	target *t = f->t;
	addr -= f->start;

	DEBUG("iproc erase %u at %"PRIx32"\n", (unsigned int)len, addr);

	// if addr or len are not block aligned then consider the caller to be confused
	if (addr & (f->blocksize-1) || len & (f->blocksize-1)) {
		tc_printf(t, "flash erase offset/len %u/%u is not block aligned\n", (unsigned int)addr, (unsigned int)len);
		return -1;
	}

	// adjust for any bad blocks we've skipped (needed since gdb incrementally erases the flash as it writes)
	addr += ((struct iproc_flash*)f)->badblock_offset;

	while ((ssize_t)len > 0) {
		// erase the block at offset 'addr'
		DEBUG("iproc erase block at %"PRIx32"\n", addr);

		if (iproc_is_bad_block(f, addr)) {
			DEBUG("skipping bad block %u\n", (unsigned int)addr);
			addr += f->blocksize;
			continue;
		}

		target_mem_write32(t, IPROC_NAND_EXT_ADDRESS, 0); // assume CS 0, and under 4 GB
		target_mem_write32(t, IPROC_NAND_ADDRESS, addr);
		target_mem_write32(t, IPROC_NAND_CMD_START, IPROC_NAND_OPCODE_BLOCK_ERASE<<24);

		// wait for controller to be done
		uint32_t st = 0;
		while (!(st & (/*CTRL_READY*/1<<31))) {
			st = target_mem_read32(t, IPROC_NAND_INTFC_STATUS);
		}

		if (st & (!(/*WP#*/1<<7))) {
			// write-protect is enabled. possible if there is an external circuit
			tc_printf(t, "NAND is write-protected\n");
			return -1;
		}

		if (st & (/*FAIL*/1<<0)) {
			tc_printf(t, "NAND erase block at %u failed\n", (unsigned int)addr);
			return -1;
		}

		addr += f->blocksize;
		len -= f->blocksize;
	}

	return 0;
}

static int iproc_flash_write_subpage(struct target_flash *f, target_addr dest, const void *src, size_t len)
{
	target *t = f->t;
	dest -= f->start;

	DEBUG("iproc write %u at %"PRIx32"\n", (unsigned int)len, dest);

	// if dest is not sub-page aligned or len is not a single subpage then consider the caller to be confused
	if (dest & (IPROC_SUBPAGE_SIZE-1) || len != IPROC_SUBPAGE_SIZE) {
		tc_printf(t, "flash erase offset/len %u/%u is not a %d-byte sub-page\n", (unsigned int)dest, (unsigned int)len, IPROC_SUBPAGE_SIZE);
		return -1;
	}

	// NOTE WELL: most of BMP is oriented towards Cortex-M[34] chips, which usually contain reliable (NOR?) flash. iproc can boot from not-quite-
	// so-reliable NAND as long as the first block of NAND is valid and iproc NAND controller can perform ECC on it. Both conditions are usually true.
	// However further blocks are sometimes marked as bad, either by the NAND manufacturer or later by software (when, for example, linux's MTD code
	// determines the block cannot be successfully erased or written). We must refuse to write to a bad block, because doing so might erase the bad
	// block marker.
	//
	// Secondly, although gdb does erase flash before writing to it, modern NANDs are picky about writes. They typically specify that writes
	// within a page and writes within a block *must* be in address order. That is, subpage 0 of page 0 must be the first data written in a block,
	// followed by subpage 1 of page 0, etc... . And data must only be written one time between block erasures. In my experience nothing dramatically
	// goes wrong if you don't follow these rules, just the reliability is reduced. Remember that modern NANDs are so close to the reliability limit
	// that they suffer from read-disturbances (where reading byte X occasionally disturbs a bit in byte Y, where Y can be in a different page than X)
	//
	// Bad block handling in typical u-boot and filesystem (UBI) images is done by writing the image starting at a block address, and into successive pages
	// skipping over any bad blocks that are encountered. This means that we have to adjust the 'dest' gdb supplies by the number of bad block bytes we've
	// skipped so far during this write, and that also means we have to make sure the erase erases the adjusted block.
	//
	// The one thing we don't handle yet (and might not ever) is a block going bad during this write operation. If we wanted to we'd have to check that
	// the erase and the write succeeded, and write bad block markers if they didn't, as well as rewrite the block's data in the next block. That, in
	// turn, means erroring and restarting the whole operation, since we've lost the block's data by the time we realize the block is bad.
	// (the BMP probably doesn't have the RAM to hold a whole NAND block's worth of data (128kB in a typical case))

	dest += ((struct iproc_flash*)f)->badblock_offset;

	DEBUG("iproc write sub-page at %"PRIx32"\n", dest);

	if ((dest & (f->blocksize-1)) == 0) {
		// we're starting a new block; check that the block isn't marked bad before writing to it
		while (iproc_is_bad_block(f, dest)) {
			((struct iproc_flash*)f)->badblock_offset += f->blocksize;
			DEBUG("skipping bad block %u; bad block offset 0x%x\n", (unsigned int)dest, (unsigned int)(((struct iproc_flash*)f)->badblock_offset));
			dest += f->blocksize;
			if (dest >= f->length)
				break;
		}
	}

	if (dest >= f->length) {
		tc_printf(t, "NAND is full\n");
		return -1;
	}

	// the address needs to be set up before copying into the flash cache
	target_mem_write32(t, IPROC_NAND_EXT_ADDRESS, 0); // assume CS 0, and under 4 GB
	target_mem_write32(t, IPROC_NAND_ADDRESS, dest);

	// byte-swap each uint32_t as we load it into the controller
	for (size_t i=0; i<IPROC_SUBPAGE_SIZE/4; i++) {
		uint32_t x;
		memcpy(&x, src, 4);
		src += 4;
		x = htofrombe_uint32(x);
		target_mem_write32(t, IPROC_NAND_FLASH_CACHE(i), x);
	}
	// the spare bytes are set to 1. the NAND controller will merge in the ECC bits it computes
	for (size_t i=0; i<16; i++) {
		target_mem_write32(t, IPROC_NAND_SPARE_AREA_WRITE(i), 0xffffffff);
	}

	// start the controller's operation
	target_mem_write32(t, IPROC_NAND_CMD_START, IPROC_NAND_OPCODE_PROGRAM_PAGE<<24);

	// wait for controller to be done
	uint32_t st = 0;
	while (!(st & (/*CTRL_READY*/1<<31))) {
		st = target_mem_read32(t, IPROC_NAND_INTFC_STATUS);
	}

	if (st & (!(/*WP#*/1<<7))) {
		// write-protect is enabled. possible if there is an external circuit
		tc_printf(t, "NAND is write-protected\n");
		return -1;
	}

	if (st & (/*FAIL*/1<<0)) {
		tc_printf(t, "NAND write at %u failed\n", (unsigned int)dest);
		return -1;
	}

	return 0;
}

int iproc_flash_done_buffered(struct target_flash *f)
{
	DEBUG("iproc_flash_done_buffered; badblock_offset %u\n", (unsigned int)(((struct iproc_flash*)f)->badblock_offset));
	// reset the badblock offset before the next write operation
	((struct iproc_flash*)f)->badblock_offset = 0;
	return target_flash_done_buffered(f);
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

	const int page_size = ((struct iproc_flash*)f)->pagesize;
	const int spare_size = page_size / IPROC_SUBPAGE_SIZE * IPROC_SUBPAGE_SPARE_SIZE;
	uint8_t buf[page_size+spare_size];
	memset(buf, 0xff, sizeof(buf));
	uint32_t errors[2];
	int rc = iproc_flash_read(f, errors, buf, (target_addr)pagenum * page_size, page_size, buf+page_size);
	if (rc) {
		tc_printf(t, "read failed: %d\n", rc);
		return false;
	}

	tc_printf(t, "NAND page %lu:\n", pagenum);
	for (int i=0; i<page_size; i+=16) {
		tc_printf(t, "%03x: ", i);
		for (int j=0; j<16; j++) {
			uint8_t x = buf[i+j];
			tc_printf(t, "%02x ", x);
			if (j == 7)
				tc_printf(t, " ");
		}
		tc_printf(t, "\n");
	}
	tc_printf(t, "spare/ECC bytes:\n");
	for (int i=0; i<spare_size; i+=16) {
		tc_printf(t, "%02x: ", i);
		for (int j=0; j<16; j++) {
			uint8_t x = buf[page_size+i+j];
			tc_printf(t, "%02x ", x);
			if (j == 7)
				tc_printf(t, " ");
		}
		tc_printf(t, "\n");
	}
	if (errors[0])
		tc_printf(t, "%"PRIu32" ECC-corrected bit errors\n", errors[0]);
	if (errors[1])
		tc_printf(t, "***** ECC REPORTS UNCORRECTABLE BIT ERRORS *****\n"); // note the exact number is not known. the hardware counter just counts subpages with uncorrectable errors

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

	// TODO what happens on other CPUs when we read the iproc chip-id address?
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
	// configure for the controller to generate and check ECC and to use sub-page reads and writes
	uint32_t acc_ctrl = target_mem_read32(t, IPROC_NAND_ACC_CONTROL_CS(0));
	DEBUG("acc_ctrl %"PRIx32"\n", acc_ctrl);
	acc_ctrl |= (/*RD_ECC_EN*/1<<31) + (/*WR_ECC_EN*/1<<30) + (/*FLAST_PGM_RDIN*/1<<28) +
		(/*RD_ERASED_ECC_EN*/1<<27) + (/*PARTIAL_PAGE_EN*/1<<26) + (/*PAGE_HIT_EN*/1<<24);
	target_mem_write32(t, IPROC_NAND_ACC_CONTROL_CS(0), acc_ctrl);

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

	struct iproc_flash* ff = calloc(1, sizeof(*ff));
	ff->pagesize = bytes_per_page;
	struct target_flash* f = (struct target_flash*)ff;
	f->start = IPROC_NAND_WINDOW;
	f->length = (size_t)totalsize; // this isn't the window size, but the full NAND size. It's unclear to me which would be correct. Probably the window is enough, since it's unlikely we'd program more than that over jtag
	f->blocksize = blocksize;
	f->erase = iproc_flash_erase;
	f->write = target_flash_write_buffered;
	f->done = iproc_flash_done_buffered;
	f->erased = 0xff;
	f->buf_size = IPROC_SUBPAGE_SIZE;
	f->write_buf = iproc_flash_write_subpage;

	t->driver = "iproc";
	target_add_commands(t, iproc_cmd_list, "iproc");
	target_add_ram(t, 0x0, 256<<20);
	target_add_flash(t, f);

	return true;
}
