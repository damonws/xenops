import capstone
import itertools
import reboot
import struct

def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

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
            if op.mem.base == 0:
                base = 0
            elif op.mem.base == capstone.arm.ARM_REG_PC:
                base = insn.address + 8
            else:
                base = regs[insn.address][op.mem.base]
            index = 0 if op.mem.index == 0 else regs[insn.address][op.mem.index]
            mem = base + index * op.mem.scale + op.mem.disp - start
            if mem + 4 > len(data):
                raise KeyError
            return struct.unpack('<I', data[mem:mem+4])[0]

        # other
        else:
            return None

    def disasm(addr):
        new_entries = []
        thumb = addr % 2
        addr = addr & 0xfffffffe
        if addr not in listing:
            md.mode = capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM

            insn = next(md.disasm(data[addr-start:addr-start+max_insn_size],
                                  addr, 1), None)

            listing[addr] = {
                'insn' : insn,
            }

            if insn:
                if addr in regs:
                    new_regs = regs[addr]
                    print '\n' + '\n'.join('\t' + ' '.join(g)
                            for g in grouper(('{}={:08x}'.format(insn.reg_name(r), v)
                            for r, v in sorted(regs[addr].items())), 4, ''))

                else:
                    new_regs = {}
                reboot.print_detail(insn)

                # analyze semantics of instructions

                # determine possible next instructions
                if capstone.CS_GRP_JUMP in insn.groups:

                    # add target of jump instructions
                    if insn.operands[0].type == capstone.arm.ARM_OP_IMM:
                        new_entries.append(insn.operands[0].imm & 0xffffffff)
                    elif insn.operands[0].type == capstone.arm.ARM_OP_REG:
                        try:
                            new_entries.append(regs[addr][insn.operands[0].reg])
                        except KeyError:
                            print '>>> JMP TO UNK REG <<<'
                    else:
                        print '>>> JMP NIMPL <<<'

                    # add next instruction for conditional jumps
                    if insn.cc != capstone.arm.ARM_CC_AL:
                        new_entries.append(addr + insn.size + thumb)

                else:
                    # add next instruction for everything else
                    new_entries.append(addr + insn.size + thumb)

                # determine resulting register state

                # instructions we don't care about (for now)
                if insn.id in (capstone.arm.ARM_INS_CMP,
                               capstone.arm.ARM_INS_B,
                               capstone.arm.ARM_INS_BX,
                               capstone.arm.ARM_INS_STR,
                               capstone.arm.ARM_INS_DSB,
                               capstone.arm.ARM_INS_ISB,
                               capstone.arm.ARM_INS_MSR,
                              ):
                    pass

                # ADD
                elif insn.id == capstone.arm.ARM_INS_ADD:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1) + opval(insn, 2)
                    except KeyError:
                        print '>>> ADD key error <<<'

                # SUB
                elif insn.id == capstone.arm.ARM_INS_SUB:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1) - opval(insn, 2)
                    except KeyError:
                        print '>>> SUB key error <<<'

                # LDR
                elif insn.id == capstone.arm.ARM_INS_LDR:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1)
                    except KeyError:
                        print '>>> LDR key error <<<'

                # MOV
                elif insn.id == capstone.arm.ARM_INS_MOV:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1)
                    except KeyError:
                        print '>>> MOV key error <<<'

                # AND
                elif insn.id == capstone.arm.ARM_INS_AND:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1) & opval(insn, 2)
                    except KeyError:
                        print '>>> AND key error <<<'

                # ORR
                elif insn.id == capstone.arm.ARM_INS_ORR:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1) | opval(insn, 2)
                    except KeyError:
                        print '>>> ORR key error <<<'

                # EOR
                elif insn.id == capstone.arm.ARM_INS_EOR:
                    try:
                        new_regs[insn.operands[0].reg] = opval(insn, 1) ^ opval(insn, 2)
                    except KeyError:
                        print '>>> EOR key error <<<'

                # BIC
                elif insn.id == capstone.arm.ARM_INS_BIC:
                    try:
                        new_regs[insn.operands[0].reg] = (
                            opval(insn, 1) & (~opval(insn, 2) & 0xffffffff))
                    except KeyError:
                        print '>>> BIC key error <<<'

                # MRS
                elif insn.id == capstone.arm.ARM_INS_MRS:
                    # punting on this one
                    new_regs[insn.operands[0].reg] = 0xdeadbeef

                # STM
                elif insn.id == capstone.arm.ARM_INS_STM:
                    if insn.writeback:
                        new_regs[insn.operands[0].reg] += (len(insn.operands) - 1) * 4

                # catch all
                else:
                    print '>>> INSN NIMPL <<<'

                # set new register state on all possible next instructions
                if new_regs:
                    for entry in new_entries:
                        regs.setdefault(entry & 0xfffffffe, {}).update(new_regs)

        return new_entries

    while entries:
        #print ','.join(hex(e) for e in entries)
        entries.extend(disasm(entries.pop()))

if __name__ == '__main__':
    import sys
    for filename in sys.argv[1:]:
        with open(filename) as f:
            rd_disasm(f.read(), 0x9ff00000)
