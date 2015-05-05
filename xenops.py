import capstone

MAX_INSN_SIZE = 4

class Analysis(object):
    def __init__(self, data, start_addr, *code_entry_points):
        # save original information
        self.data = data
        self.start_addr = start_addr
        self.code_entry_points = code_entry_points

        # instantiate a disassembler
        self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.md.detail = True

        # disassemble starting at each entry point, adding new code heads as
        # they are found
        code_heads = list(code_entry_points)
        for head in code_heads:
            atom = CodeAtom(data, start_addr, head, self.md)

class CodeAtom(object):
    def __init__(self, data, start_addr, atom_addr, md):
        self.thumb = atom_addr % 2
        self.addr = atom_addr & 0xfffffffe
        md.mode = capstone.CS_MODE_THUMB if self.thumb else capstone.CS_MODE_ARM
        start = self.addr - start_addr
        end = start + MAX_INSN_SIZE
        self.insn = next(md.disasm(data[start:end], self.addr, 1), None)
        print '{:08x}: {:8}{}'.format(self.insn.address, self.insn.mnemonic,
                                      self.insn.op_str)

if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 3:
        with open(sys.argv[1]) as f:
            addrs = [int(a, 0) for a in sys.argv[2:]]
            analysis = Analysis(f.read(), addrs[0], *addrs)
            print analysis

