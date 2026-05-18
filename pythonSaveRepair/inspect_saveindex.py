import os

p = r'E:\Windows\Users\samue\OneDrive\source\repos\DXHRDC\DXHRDC_memoryAllocHookFix\238010\remote\saveindex'
with open(p, 'rb') as f:
    data = f.read(128)
print(data.hex(' '))
print('Total file size:', os.path.getsize(p))
