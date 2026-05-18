import sys
sys.path.insert(0, 'pythonSaveRepair')
from save_repair_tool import read_save, write_save

in_path = r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER1_4'
out_path = r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\GAMER1_4_test'

b = read_save(in_path)
write_save(out_path, b)

with open(out_path, 'rb') as f:
    print('Repacked:', f.read(32).hex(' '))
