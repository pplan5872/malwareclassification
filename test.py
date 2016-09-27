#!/usr/bin/python
# This file only is used to test code


from capstone import *

# using pefile module to handle PE file and dlls
import pefile

# For handling arguments
import argparse

# A structure for kernel32.dll
# we need information about imageBase, size of image
# and the entry point where the dll is loaded 
'''
kernel32_struct = {
	'imageBase': 0x0,
	'sizeOfImage': 0x0,
	'entryPoint': 0x0,
}
'''

class Dll:

	# constructor
	def __init__(self):

		# The imageBase field
		self.imageBase = 0x0

		# Size of the image
		self.sizeOfImage = 0x0

		# The entry point where the dll is loaded
		self.entryPoint = 0x0

	# set imageBase
	def setImageBase(self, imageBase):
		self.imageBase = imageBase

	# set sizeOfImage
	def setSizeOfImage(self, sizeOfImage):
		self.sizeOfImage = sizeOfImage

	# get entrypoint
	def setEntryPoint(self):
		return self.entryPoint

	# get imageBase
	def getImageBase(self):
		return self.imageBase

	# get sizeOfImage
	def getSizeOfImage(self):
		return self.sizeOfImage

	# get entrypoint
	def getEntryPoint(self):
		return self.entryPoint

# Sometimes we need information about exports 
class Exports:

	# Constructor
	def __init__(self):
		self.items = {}

	# get export's address
	def getAddress(self, name):
		return self.items[name]

	# set export's name
	def setAddress(self, name, address):
		self.items[name] = address

	# displays exports
	def displayExports(self):
		for i in self.items:
			print(i, self.items[i])


# Now we can handle a dll. What we want to do here is to get dll's content
# and also the dll's metadata
def dll_loader(dllPath, DllExports, Dll ):

	# Specify dll path
	dllName = dllPath.split('/')[1]

	print(dllName)
	# parse dll
	dll = pefile.PE(dllPath)

	# parse data directories
	dll.parse_data_directories()

	# get dll's contents
	data = bytearray(dll.get_memory_mapped_image())

	# Populate Dll instance with metadata
	
	Dll.setSizeOfImage =  dll.OPTIONAL_HEADER.SizeOfImage
	Dll.setEntryPoint = dll.OPTIONAL_HEADER.AddressOfEntryPoint
	Dll.setImageBase = dll.OPTIONAL_HEADER.ImageBase


	# Iterate export table
	for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:
		
		# Populate export table
		DllExports.setAddress(exp.name, dll.OPTIONAL_HEADER.ImageBase + exp.address)


def main():
	# parse arguments
	# Create an ArgumentParser object
	parser = argparse.ArgumentParser(prog = "Export search", description = 'Searching an export in a DLL')

	# Add the first argument: a path to the dll
	parser.add_argument('-d', dest='dll_path', help='Specify a dll path')

	# Add the second argument: an disired export
	parser.add_argument('-e', dest='export', help='Specify a disired export')

	# Let's parse arguments, the arguments are accessed through args variable
	args = parser.parse_args()

	print(args.dll_path)
	# Create an instance of exports for Kernel32.dll
	exports = Exports()

	# Create an instance of DLL
	dll = Dll()

	# Loading dll
	dll_loader(args.dll_path, exports, dll)

	# For displaying DLL's information

	# DLL's Entrypoint
	print(dll.getEntryPoint()) 

	# get the export address
	exportAddr = exports.getAddress(args.export)

	# Display the result
	print("Export %s is located at 0x%x in %s" % (args.export, exportAddr , args.dll_path))

if __name__ == "__main__":
	main()

