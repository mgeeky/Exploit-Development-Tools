#!/usr/bin/python
# Disasm of 64-bit binary:
#   $ objdump -b binary -D -m i386:x86-64 <file>
#
# Usage:
#   $ ./bin2shellcode.py <file> num
# Where:
#   num - number of bytes to convert into array.
#         `num` can be negative, resulting in `size-num`
#         bytes be converted.
import sys

if __name__ == '__main__':
  if len(sys.argv) < 2 or len(sys.argv) > 3:
    print "Usage: %s <file> [len]" % sys.argv[0] 
  else:
    f = open(sys.argv[1], 'rb')
    bytes = f.read()
    num = len(bytes)
    if len(sys.argv) > 2:
        # if [len] is negative - substract it from
        # total length.
        num0 = int(sys.argv[2])
        if num0 < 0 and -num0 <= num:
            num += num0 -1
        elif -num0 > num:
            print '[!] To large negative value. Fallback to 0.'
        else:
            num = num0

    array = 'char shellcode[%d] = \n\t"' % (num)
    for b in range(len(bytes)):
      if b > num: break 
      if b % 16 == 0 and b > 0:
        array += '"\n\t"'
      array += '\\x%02x' % ord(bytes[b])

    array += '";\n'

    print array