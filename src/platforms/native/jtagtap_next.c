
#include "general.h"

// custom jtagtap_next specifically for BMP 2.1
// hand written to be faster than the generic code

#ifdef PLATFIRM_HAS_JTAGTAP_NEXT
// NOTE: return type is unsigned int rather than uint8_t to keep gcc from needing to truncate to 8 bits. the return value is always 0 or 1, but gcc doesn't know that.
unsigned int jtagtap_next(uint8_t dTMS, uint8_t dTDI) {
	uint32_t regs = 0x40010800; // base of GPIO register block on STM32
	unsigned int tms = dTMS;

	asm (
		// setup TDI and TMS
		" lsls %0, #4\n"
		" lsls %1, #3\n"
		" orrs %0, %1\n"
		" strh %0, [%2, #0x10]\n"
		" eor %0, #(1<<4)|(1<<3)\n"
		" strh %0, [%2, #0x14]\n"
		// TCK goes high
		" movs %1, #1<<5\n"
		" strh %1, [%2, #0x10]\n"
		// sample TDO
		" ldrh %0, [%2, #0x08]\n"
		// TCK goes low
		" strh %1, [%2, #0x14]\n"
		// return bit 6 (TDO) of gpio inputs
		" ubfx %0, %0, #6, #1\n"
		: "+l" (tms) : "l" (dTDI), "l" (regs));

	return tms;
}
#endif

/*
08006600 <jtagtap_next>:
 8006600:       b178            cbz     r0, 8006622 <jtagtap_next+0x22>
 // dTMS==1
 8006602:       4b0c            ldr     r3, [pc, #48]   ; (8006634 <jtagtap_next+0x34>)
 8006604:       2210            movs    r2, #16
 8006606:       601a            str     r2, [r3, #0]
 8006608:       b981            cbnz    r1, 800662c <jtagtap_next+0x2c>
 // dTDI==0
 800660a:       4b0b            ldr     r3, [pc, #44]   ; (8006638 <jtagtap_next+0x38>)
 800660c:       2208            movs    r2, #8
 800660e:       801a            strh    r2, [r3, #0]
 // pulse clock
 8006610:       4908            ldr     r1, [pc, #32]   ; (8006634 <jtagtap_next+0x34>)
 8006612:       2320            movs    r3, #32
 8006614:       4a09            ldr     r2, [pc, #36]   ; (800663c <jtagtap_next+0x3c>)
 8006616:       600b            str     r3, [r1, #0]
 8006618:       6810            ldr     r0, [r2, #0]
 800661a:       8193            strh    r3, [r2, #12]
 800661c:       f3c0 1080       ubfx    r0, r0, #6, #1
 8006620:       4770            bx      lr
 // dTMS==0
 8006622:       4b05            ldr     r3, [pc, #20]   ; (8006638 <jtagtap_next+0x38>)
 8006624:       2210            movs    r2, #16
 8006626:       801a            strh    r2, [r3, #0]
 8006628:       2900            cmp     r1, #0
 800662a:       d0ee            beq.n   800660a <jtagtap_next+0xa>
 // dTDI==1
 800662c:       4b01            ldr     r3, [pc, #4]    ; (8006634 <jtagtap_next+0x34>)
 800662e:       2208            movs    r2, #8
 8006630:       601a            str     r2, [r3, #0]
 8006632:       e7ed            b.n     8006610 <jtagtap_next+0x10>
 8006634:       40010810        .word   0x40010810
 8006638:       40010814        .word   0x40010814
 800663c:       40010808        .word   0x40010808

inline uint8_t jtagtap_next(uint8_t dTMS, uint8_t dTDI)
{
    uint16_t ret;

    gpio_set_val(TMS_PORT, TMS_PIN, dTMS);
    gpio_set_val(TDI_PORT, TDI_PIN, dTDI);
    gpio_set(TCK_PORT, TCK_PIN);
    ret = gpio_get(TDO_PORT, TDO_PIN);
    gpio_clear(TCK_PORT, TCK_PIN);

    //DEBUG("jtagtap_next(TMS = %d, TDI = %d) = %d\n", dTMS, dTDI, ret);

    return ret != 0;
}
*/
