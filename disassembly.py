"""
# disassembly.py
Disassemble a PE file and dump the code

Usage:
Change the "your_file.exe" to specific file
$ python disassembly.py

"""

#!/usr/bin/python

import pefile
from capstone import *

pe = pefile.PE("your_file.exe")

entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
entry_addr = entry+pe.OPTIONAL_HEADER.ImageBase
binary = pe.get_memory_mapped_image()[entry:entry+100]
disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

# loop and disassemble the code
for instr in disassembler.disasm(binary, entry_addr):
    print "%s\t%s" %(instr.mnemonic, instr.op_str)
