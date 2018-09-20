#!/usr/bin/python

pe = pefile.PE("file.exe")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
  print entry.dll
  for function in entry.imports:
    print '\t', function.name
