# license format: 1659702335-ZXXXXXXXXXXXXXXXX-2284363008
#                   ^                           ^
#                  numbers                      numbers

from hashlib import sha1
from Crypto.Cipher import AES
from qiling import *
from qiling.const import QL_VERBOSE
from pwn import *
from time import time as t
import os
import sys

rax = 0
lic = b''

class StringBuffer:
    def __init__(self):
        self.buffer = b''

    def read(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return ret

    def readline(self, end=b'\n'):
        ret = b''
        while True:
            c = self.read(1)
            ret += c
            if c == end:
                break
        return ret

    def write(self, string):
        self.buffer += string
        return len(string)

name = raw_input('Name: ')
name = name.split(b'\n')[0]
name = name.ljust(20, b'\0')
mail = raw_input('Email: ')
mail = mail.split(b'\n')[0]
mail = mail.ljust(50, b'\0')

time = int(t()) - 30
lic+=str(time).encode('utf-8')+b'-ZXXXXXXXXXXXXXXXX-'
progpath = sha1(os.path.abspath('./keygen_me').encode('utf-8')).digest()[:10]
username = sha1(os.getlogin().encode('utf-8')).digest()[:10]
k_time = p32(time)
o = AES.new(b'XXXXXXXXXXXXXXXX', AES.MODE_CBC, b'0123456789ABCDEF')
enc = o.encrypt(username+b'*'+progpath+b'-'+progpath)
crc_str = k_time+b'ZXXXXXXXXXXXXXXXX'+enc+name
crc_str = crc_str.ljust(0x49, b'\0')
crc_str += mail
crc_str = crc_str.ljust(0x7b, b'\0')
crc_str += b'I\'m juste a salt :)\0'

ql = Qiling(['./keygen_me'], '../rootfs/x8664_linux/', verbose=QL_VERBOSE.OFF)
base = int(ql.profile.get("OS64", "load_address"), 16)


var = 1000

def evade_fork(ql):
    rbp = ql.arch.regs.rbp
    ql.mem.write(rbp-0x1160, crc_str)
    ql.arch.regs.rip = base+0x1a43

def get_val(ql):
    global lic
    global var
    lic+=str(ql.arch.regs.read("EAX")).encode('utf-8')
    print(type(ql.arch.regs.read("EAX")))
    print(type(33))
    var = 0
    log.info('License generated: '+lic.decode())

def terminate(ql):
    ql.emu_stop()

ql.os.stdin = StringBuffer()
ql.os.stdin.write(b'O\n')
ql.os.stdin.write(name+b'\n')
ql.os.stdin.write(mail+b'\n')
ql.hook_address(evade_fork, base+0x17b0)
ql.hook_address(get_val, base+0x1a57)
ql.hook_address(terminate, base+0x1eb4)
ql.os.stdin.write(str(time).encode('utf-8')+b'-ZXXXXXXXXXXXXXXXX-'+b'1000\n')
ql.run()
print(lic.decode())
print(var)
