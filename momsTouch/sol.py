from qiling import *
from qiling.const import QL_VERBOSE
from pwn import *

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

def get_val(ql: Qiling) -> None:
    v1 = u32(ql.mem.read(ql.arch.regs.esi*4+0x8049144, 4))
    v2 = u32(ql.mem.read(ql.arch.regs.eax*4+0x80492ac, 4))
    v3 = u32(ql.mem.read(ql.arch.regs.ebp*4+0x80492ac, 4))
    print(chr(v1 ^ v2 ^ v3), end='')
    if (ql.arch.regs.esi == 0x48):
        print()
    ql.arch.regs.eip = 0x804881b

if __name__=='__main__':
    ql = Qiling(['./chall'], '../rootfs/x86_linux', verbose=QL_VERBOSE.OFF)
    ql.os.stdin = StringBuffer()
    ql.os.stdin.write(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n')
    ql.hook_address(get_val, 0x8048812)
    ql.run()
