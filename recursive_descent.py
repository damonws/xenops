import capstone
import reboot
import struct

def rd_disasm(data, start=0, entries=None):
    if entries is None:
        entries = [start]

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = True

    listing = {}
    regs = {}
    max_insn_size = 4

    def opval(insn, i):
        op = insn.operands[i]

        # register
        if op.type == capstone.arm.ARM_OP_REG:
            if op.reg == capstone.arm.ARM_REG_PC:
                return insn.address + 8
            else:
                return regs[insn.address][op.reg]

        # immediate
        elif op.type == capstone.arm.ARM_OP_IMM:
            return op.imm & 0xffffffff

        # memory
        elif op.type == capstone.arm.ARM_OP_MEM:
            if op.mem.index != 0 or op.mem.scale != 1:
                raise KeyError
            if op.mem.base == capstone.arm.ARM_REG_PC:
                base = insn.address + 8
            else:
                base = regs[insn.address][op.reg]
            mem = base + op.mem.disp - start
            if mem + 4 > len(data):
                raise KeyError
            return struct.unpack('<I', data[mem:mem+4])[0]

        # other
        else:
            return None

    def disasm(addr):
        new_entries = []
        if addr not in listing:
            if addr % 2:
                md.mode = capstone.CS_MODE_THUMB
            else:
                md.mode = capstone.CS_MODE_ARM

            insn = next(md.disasm(data[addr-start:addr-start+max_insn_size],
                                  addr, 1), None)

            listing[addr] = {
                'insn' : insn,
            }

            if insn:
                if addr in regs:
                    new_regs = regs[addr]
                    for reg, value in regs[addr].iteritems():
                        print '{}={:x}'.format(insn.reg_name(reg), value)
                else:
                    new_regs = {}
                reboot.print_detail(insn)

                # analyze semantics of instructions
                # - determine possible next instructions
                # - set register state
                if capstone.CS_GRP_JUMP in insn.groups:

                    # add target of jump instructions
                    if insn.operands[0].type == capstone.arm.ARM_OP_IMM:
                        new_entries.append(insn.operands[0].imm & 0xffffffff)
                    else:
                        # TODO: handle jumps to registers (e.g. bx r1)
                        pass

                    # add next instruction for conditional jumps
                    if insn.cc != capstone.arm.ARM_CC_AL:
                        new_entries.append(addr + insn.size)

                else:
                    # add next instruction for everything else
                    new_entries.append(addr + insn.size)

                if insn.id == capstone.arm.ARM_INS_ADD:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1) + opval(insn, 2)
                    except KeyError:
                        print '>>> ADD key error <<<'
                elif insn.id == capstone.arm.ARM_INS_SUB:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1) - opval(insn, 2)
                    except KeyError:
                        print '>>> SUB key error <<<'
                elif insn.id == capstone.arm.ARM_INS_LDR:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1)
                    except KeyError:
                        print '>>> LDR key error <<<'
                elif insn.id == capstone.arm.ARM_INS_MOV:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1)
                    except KeyError:
                        print '>>> MOV key error <<<'

                if new_regs:
                    for entry in new_entries:
                        regs.setdefault(entry, {}).update(new_regs)

        return new_entries

    while entries:
        #print ','.join(hex(e) for e in entries)
        entries.extend(disasm(entries.pop()))

if __name__ == '__main__':
    import sys
    for filename in sys.argv[1:]:
        with open(filename) as f:
            rd_disasm(f.read(), 0x9ff00000)
