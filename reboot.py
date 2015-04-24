import capstone
import binascii

def analyze_file(binary):
    with open(binary) as f:
        data = f.read()
    analyze_buffer(data)

def print_detail(insn):
    if insn is None:
        return

    print '{:08x}: {:8}  {:8}{}'.format(insn.address,
                                      binascii.hexlify(insn.bytes),
                                      insn.mnemonic, insn.op_str)
    return

    if insn.id == capstone.arm.ARM_INS_INVALID:
        return

    if len(insn.regs_read) > 0:
        print "\tImplicit registers read: ",
        for m in insn.regs_read:
            print "%s " % insn.reg_name(m),
        print

    if len(insn.regs_write) > 0:
        print "\tImplicit registers modified: ",
        for m in insn.regs_write:
            print "%s " % insn.reg_name(m),
        print

    if len(insn.groups) > 0:
        print "\tThis instruction belongs to groups: ",
        for m in insn.groups:
            print "%s " % insn.group_name(m),
        print

    if len(insn.operands) > 0:
        print "\top_count: %u" % len(insn.operands)
        c = 0
        for i in insn.operands:
            if i.type == capstone.arm.ARM_OP_REG:
                print "\t\toperands[%u].type: REG = %s" % (c, insn.reg_name(i.reg))
            if i.type == capstone.arm.ARM_OP_IMM:
                print "\t\toperands[%u].type: IMM = 0x%x" % (c, i.imm & 0xffffffff)
            if i.type == capstone.arm.ARM_OP_PIMM:
                print "\t\toperands[%u].type: P-IMM = %u" % (c, i.imm)
            if i.type == capstone.arm.ARM_OP_CIMM:
                print "\t\toperands[%u].type: C-IMM = %u" % (c, i.imm)
            if i.type == capstone.arm.ARM_OP_FP:
                print "\t\toperands[%u].type: FP = %f" % (c, i.fp)
            if i.type == capstone.arm.ARM_OP_SYSREG:
                print "\t\toperands[%u].type: SYSREG = %u" % (c, i.reg)
            if i.type == capstone.arm.ARM_OP_SETEND:
                if i.setend == capstone.arm.ARM_SETEND_BE:
                    print "\t\toperands[%u].type: SETEND = be" % c
                else:
                    print "\t\toperands[%u].type: SETEND = le" % c
            if i.type == capstone.arm.ARM_OP_MEM:
                print "\t\toperands[%u].type: MEM" % c
                if i.mem.base != 0:
                    print "\t\t\toperands[%u].mem.base: REG = %s" \
                        % (c, insn.reg_name(i.mem.base))
                if i.mem.index != 0:
                    print "\t\t\toperands[%u].mem.index: REG = %s" \
                        % (c, insn.reg_name(i.mem.index))
                if i.mem.scale != 1:
                    print "\t\t\toperands[%u].mem.scale: %u" \
                        % (c, i.mem.scale)
                if i.mem.disp != 0:
                    print "\t\t\toperands[%u].mem.disp: 0x%x" \
                        % (c, i.mem.disp & 0xffffffff)

            if i.shift.type != capstone.arm.ARM_SFT_INVALID and i.shift.value:
                print "\t\t\tShift: %u = %u" \
                    % (i.shift.type, i.shift.value)
            if i.vector_index != -1:
                print "\t\t\toperands[%u].vector_index = %u" %(c, i.vector_index)
            if i.subtracted:
                print "\t\t\toperands[%u].subtracted = True" %c

            c += 1

    if insn.update_flags:
        print "\tUpdate-flags: True"
    if insn.writeback:
        print "\tWrite-back: True"
    if not insn.cc in [capstone.arm.ARM_CC_AL, capstone.arm.ARM_CC_INVALID]:
        print "\tCode condition: %u" % insn.cc
    if insn.cps_mode:
        print "\tCPSI-mode: %u" %(insn.cps_mode)
    if insn.cps_flag:
        print "\tCPSI-flag: %u" %(insn.cps_flag)
    if insn.vector_data:
        print "\tVector-data: %u" %(insn.vector_data)
    if insn.vector_size:
        print "\tVector-size: %u" %(insn.vector_size)
    if insn.usermode:
        print "\tUser-mode: True"
    if insn.mem_barrier:
        print "\tMemory-barrier: %u" %(insn.mem_barrier)
    print

def analyze_buffer(data):
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.skipdata = True
    md.detail = True

    for insn in md.disasm(data, 0x9ff00000):
        print_detail(insn)
