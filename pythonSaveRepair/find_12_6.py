import sys
import struct
sys.path.insert(0, 'pythonSaveRepair')
from save_repair_tool import read_save

buf = read_save(r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER51_4')
hits = []
for i in range(0, len(buf) - 20):
    if buf[i+8:i+16] == b'\x0c\x00\x00\x00\x06\x00\x00\x00':
        hits.append(i)

for h in hits:
    item_id = buf[h:h+4].hex()
    flag, count = struct.unpack('<HH', buf[h+4:h+8])
    rot, = struct.unpack('<i', buf[h+16:h+20])
    print(f"Found at offset {hex(h)}: ID={item_id}, Flag={flag}, Count={count}, Rot={rot}")
