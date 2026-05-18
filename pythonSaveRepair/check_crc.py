import binascii
import struct

p1 = r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER25_4'
with open(p1, 'rb') as f:
    data = f.read()

actual_crc = binascii.crc32(data) & 0xFFFFFFFF
print('Actual file CRC:', hex(actual_crc))

p2 = r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\saveindex'
with open(p2, 'rb') as f:
    idx = f.read()

pos = idx.find(b'GAMER25_4\0')
if pos != -1:
    size = struct.unpack('<I', idx[pos+32:pos+36])[0]
    crc = struct.unpack('<I', idx[pos+32+4+8+4:pos+32+4+8+4+4])[0]
    print(f'Index Size: {size}')
    print(f'Index CRC:  {hex(crc)}')
else:
    print('Not found in index')
