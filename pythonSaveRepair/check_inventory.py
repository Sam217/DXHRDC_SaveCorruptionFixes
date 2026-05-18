import sys
import os
sys.path.insert(0, 'pythonSaveRepair')
from save_repair_tool import read_save

# Some known item IDs (little-endian uint32 values inferred or guessed)
# We know 0x266a (9834) is Painkillers.
# The structure is:
# [ID (4 bytes)] [Flag (2 bytes)] [Count (2 bytes)] [X (4 bytes)] [Y (4 bytes)] [Rotation/Misc (4 bytes)]

saves = [
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER51_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER1_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER2_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER5_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER25_4',
    r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER63_4'
]

for save_path in saves:
    name = os.path.basename(save_path)
    print(f"\n--- {name} ---")
    try:
        buf = read_save(save_path)
        hits = [i for i in range(len(buf)-4) if buf[i:i+4] == b'\x6a\x26\x00\x00']
        if not hits:
            print("  No Painkillers found.")
            continue
        for h in hits:
            flag = int.from_bytes(buf[h+4:h+6], 'little')
            count = int.from_bytes(buf[h+6:h+8], 'little')
            x = int.from_bytes(buf[h+8:h+12], 'little')
            y = int.from_bytes(buf[h+12:h+16], 'little')
            rot = int.from_bytes(buf[h+16:h+20], 'little', signed=True)
            print(f"  Offset {hex(h)}: Flag={flag}, Count={count}, X={x}, Y={y}, Rot={rot}")
    except Exception as e:
        print(f"  Error reading: {e}")
