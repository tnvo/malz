"""
Dump out the PE header info for a file

Usage:
Change the "file.exe"
$ python dump_pe_info.py

"""

#!/usr/bin/python

pe = pefile.PE("file.exe")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
  print entry.dll
  for function in entry.imports:
    print '\t', function.name
