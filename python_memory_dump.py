#!/usr/bin/python

def hex_dump_memory(ptr, num):
    import ctypes
    
    s = ''
    n = 0
    lines = []
    data = list((num * ctypes.c_byte).from_address(ptr))

    if len(data) == 0:
        return '<empty>'

    for i in range(0, num, 16):
        line = ''
        line += '%04x | ' % (i)
        n += 16

        for j in range(n-16, n):
            if j >= len(data): break
            line += '%02x ' % abs(data[j])

        line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

        for j in range(n-16, n):
            if j >= len(data): break
            c = data[j] if not (data[j] < 0x20 or data[j] > 0x7e) else '.'
            line += '%c' % c

        lines.append(line)
    return '\n'.join(lines)


addr = int('0x' + open('/proc/self/maps', 'r').readlines()[0].split('-')[0], 16)
print 'Hex dump from 0x%016x' % addr

print hex_dump_memory(addr, 256)