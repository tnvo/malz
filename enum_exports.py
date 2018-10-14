"""
# enum_exports.py
 
 Usage:
 $ python enum_exports.py [file.exe]
 
 Results:
 AddDriverPath
 AddRegistryforME
 ...etc

"""
#!/usr/bin/python
import pefile
 
 mal_file = sys.argv[1]
 pe = pefile.PE(mal_file)
 
 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORTS'):
  for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
   print "%s" % export.name
