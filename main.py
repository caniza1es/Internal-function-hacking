import pyMeow as pm
import ctypes
from keystone import *

proc = pm.open_process("hl2.exe")
sh_size = 100
shell_parameters = pm.allocate_memory(proc, sh_size)
shell = pm.allocate_memory(proc,sh_size)

ks = Ks(KS_ARCH_X86, KS_MODE_32)

class Modules:
    tier0 = pm.get_module(proc, "tier0.dll")["base"]

class Procs:
    ConColorMsg = Modules.tier0 + 0x38F0 #<void __cdecl ConColorMsg(class Color const &, char const *, ...)>

class Color(ctypes.Structure):
    _fields_ = [
        ("r", ctypes.c_byte),
        ("g", ctypes.c_byte),
        ("b", ctypes.c_byte),
        ("a", ctypes.c_byte),
    ]

shellcode = f"""
    push ebp
    mov ebp,esp
    push {shell_parameters+4} 
    push {shell_parameters}
    call {Procs.ConColorMsg-shell}
    mov esp,ebp
    pop ebp
    ret
"""
encoding, count = ks.asm(shellcode)
pm.w_bytes(proc,shell,encoding)

def ConColorMsg(color,msg):
    pm.w_ctype(proc,shell_parameters,color)
    pm.w_string(proc,shell_parameters+4,msg)
    pm.create_remote_thread(proc,shell,0)
    pm.w_bytes(proc,shell_parameters,bytes(0)*sh_size)

red = Color(r=255, g=0, b=0, a=255)
blue = Color(r=0, g=0, b=255, a=255)
green = Color(r=0, g=255, b=0, a=255)
yellow = Color(r=255, g=255, b=0, a=255)
cyan = Color(r=0, g=255, b=255, a=255)


parameters = [
    ("Helloup_", blue),
    ("from", green),
    ("the", yellow),
    ("Pymeow", cyan),
    ("Community", cyan)
]


for message, color in parameters:
    ConColorMsg(color, message)
