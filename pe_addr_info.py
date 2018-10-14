"""

Iterating through PE file's sections and print out base virtual memory addr, virtual size, and raw data size

Usage:
Change "file.exe" to desired file
$ python pe_addr_info.py


"""

#!/usr/bin/python

import pefile
pe = pefile.PE("file.exe")

for section in pe.sections:
  print(section.Name, hex(section.VirtualAddress), hex(section.Misc.VirtualSize), section.SizeOfRawData)
