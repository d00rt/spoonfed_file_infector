/* tinygccpe.scr: GNU ld linker script for smaller PE .exe output
 * by pts@fazekas.hu at Fri Feb  3 15:41:13 CET 2017
 *
 * It's different from the default by:
 *
 * * It drops initializers (e.g. .init, .ctors), and fails if the code tries
 *   to use them.
 * * It drops exceptions (e.g. .pdata), and fails if the code tries
 *   to use them.
 * * It merges .data and .rdata. 
 *
 * Other recommended gcc flags for small .exe file: -fno-ident -fno-stack-protector -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables -falign-functions=1 -mpreferred-stack-boundary=2 -falign-jumps=1 -falign-loops=1
 *
 * Use with: i686-w64-mingw32-gcc -Wl,--section-alignment,16,--file-alignment,16,-T,tinygccpe.scr -nostdlib -nodefaultlibs -nostartfiles ... -lkernel32
 * Also works with: i586-mingw32msvc-gcc -Wl,...
 *
 * Define `void __cdecl mainCRTStartup()' instead of `main'.
 *
 * Define `void __stdcall WinMainCRTStartup()' instead of `WinMain'.
 * 
 */

ENTRY(_start)
OUTPUT_FORMAT(pei-i386)



SECTIONS {
  /* Make the virtual address and file offset synced if the alignment is
   * lower than the target page size.
   */
  . = SIZEOF_HEADERS;
  . = ALIGN(__section_alignment__);
  .test __image_base__ + (__section_alignment__ < 0x1000 ?
      . : __section_alignment__) : {
    *(.test) *(SORT(.test$*)) *(.test.*) *(.gnu.linkonce.t.*) *(.glue_7t)
    *(.glue_7)
    PROVIDE (etext = .);
    PROVIDE (_etext = .);
  }

}
