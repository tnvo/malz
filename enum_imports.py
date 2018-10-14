"""
 # enum_imports.py
 Enumerates through and get all imports (DLL) and API
 
 Usage:
 python enum_imports.py [file.exe]
 
 Results:
 DLL
  API
  
 """
 
 #!/usr/bin/python
 
 import pefile
 import sys
 
 mal_file = sys.argv[1]
 pe = pefile.PE(mal_file)
 
 if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
   print "%s" % entry.dll
   for import in entry.imports:
    if import.name != None:
     print "\t%s" % (import.name)
    else:
     print "\tord(%s)" % (str(import.ordinal))
   print "\n"
 
