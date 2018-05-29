import logging
import struct
l = logging.getLogger("angr.engines.concrete.segment_registers")

GDT_ADDR = 0x4000
GDT_LIMIT = 0x1000


def setup_gdt(state, fs, gs, fs_size=0xFFFFFFFF, gs_size=0xFFFFFFFF):

    A_PRESENT = 0x80
    A_DATA = 0x10
    A_DATA_WRITABLE = 0x2
    A_PRIV_0 = 0x0
    A_DIR_CON_BIT = 0x4
    F_PROT_32 = 0x4
    S_GDT = 0x0
    S_PRIV_0 = 0x0

    normal_entry = create_gdt_entry(0, 0xFFFFFFFF, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
    stack_entry = create_gdt_entry(0, 0xFFFFFFFF, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0, F_PROT_32)
    fs_entry = create_gdt_entry(fs, fs_size, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
    gs_entry = create_gdt_entry(gs, gs_size, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
    state.memory.store(GDT_ADDR + 8, normal_entry + stack_entry + fs_entry + gs_entry)

    state.regs.gdt = (GDT_ADDR << 16 | GDT_LIMIT)
    selector = create_selector(1, S_GDT | S_PRIV_0)
    state.regs.cs = selector
    state.regs.ds = selector
    state.regs.es = selector
    selector = create_selector(2, S_GDT | S_PRIV_0)
    state.regs.ss = selector
    selector = create_selector(3, S_GDT | S_PRIV_0)
    state.regs.fs = selector
    selector = create_selector(4, S_GDT | S_PRIV_0)
    state.regs.gs = selector



def create_selector(idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret


def create_gdt_entry(base, limit, access, flags):
    to_ret = limit & 0xffff
    to_ret |= (base & 0xffffff) << 16
    to_ret |= (access & 0xff) << 40
    to_ret |= ((limit >> 16) & 0xf) << 48
    to_ret |= (flags & 0xff) << 52
    to_ret |= ((base >> 24) & 0xff) << 56
    return struct.pack('<Q', to_ret)

def read_fs_register_linux_x64(concrete_target):
    '''
    Injects small shellcode to leak the fs segment register address. In Linux x64 this address is pointed by fs[0]
    :param concrete_target: ConcreteTarget which will be used to get the fs register address
    :return: fs register address
    '''
    # register used to read the value of the segment register
    exfiltration_reg = "rax"
    # instruction to inject for reading the value at segment value = offset
    read_fs0_x64 = "\x64\x48\x8B\x04\x25\x00\x00\x00\x00\x90\x90\x90\x90"  # mov rax, fs:[0]
    return concrete_target.execute_shellcode(read_fs0_x64, exfiltration_reg)

def read_gs_register_linux_x86(concrete_target):
    '''
    Injects small shellcode to leak the fs segment register address. In Linux x86 this address is pointed by gs[0]
    :param concrete_target: ConcreteTarget which will be used to get the fs register address
    :return: gs register address
    '''
    # register used to read the value of the segment register
    exfiltration_reg = "eax"
    # instruction to inject for reading the value at segment value = offset
    read_gs0_x64 = "\x65\xA1\x00\x00\x00\x00\x90\x90\x90\x90"  # mov eax, gs:[0]
    return concrete_target.execute_shellcode(read_gs0_x64, exfiltration_reg)



def read_fs_register_windows_x86(concrete_target):
    exfiltration_reg = "eax"
    # instruction to inject for reading the value at segment value = offset
    read_fs0_x86 = "\x64\xA1\x18\x00\x00\x00\x90\x90\x90\x90"  # mov eax, fs:[0x18]
    return concrete_target.execute_shellcode(read_fs0_x86, exfiltration_reg)


def read_gs_register_windows_x64(concrete_target):
    exfiltration_reg = "rax"
    # instruction to inject for reading the value at segment value = offset
    read_gs0_x64 = "\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x90\x90\x90\x90"  # mov rax, gs:[0x30]
    return concrete_target.execute_shellcode(read_gs0_x64, exfiltration_reg)