import logging
l = logging.getLogger("angr.engines.concrete.segment_registers")


def read_fs_register_linux_x64(concrete_target):
    '''
    Injects small shellcode to leak the fs segment register address. In Linux x64 this address is pointed by fs[0]
    :param concrete_target: ConcreteTarget which will be used to get the fs register address
    :return: fs register address
    '''
    # register used to read the value of the segment register
    exfiltration_reg = "rax"
    # instruction to inject for reading the value at segment value = offset
    read_fs0_x64 = "\x64\x48\x8B\x04\x25\x00\x00\x00\x00"  # mov rax, fs:[0]
    return concrete_target.execute_shellcode(read_fs0_x64,exfiltration_reg)

def read_gs_register_linux_x86(concrete_target):
    '''
    Injects small shellcode to leak the fs segment register address. In Linux x86 this address is pointed by gs[0]
    :param concrete_target: ConcreteTarget which will be used to get the fs register address
    :return: gs register address
    '''
    # register used to read the value of the segment register
    exfiltration_reg = "eax"
    # instruction to inject for reading the value at segment value = offset
    read_gs0_x64 = "\x65\xA1\x00\x00\x00\x00"  # mov eax, gs:[0]
    return concrete_target.execute_shellcode(read_gs0_x64,exfiltration_reg)



def read_fs_register_windows_x86(concrete_target):
    exfiltration_reg = "eax"
    # instruction to inject for reading the value at segment value = offset
    read_fs0_x86 = "\x64\xA1\x18\x00\x00\x00"  # mov eax, fs:[0x18]
    return concrete_target.execute_shellcode(read_fs0_x86, exfiltration_reg)


def read_gs_register_windows_x64(concrete_target):
    exfiltration_reg = "rax"
    # instruction to inject for reading the value at segment value = offset
    read_gs0_x64 = "\x65\x48\x8B\x04\x25\x30\x00\x00\x00"  # mov rax, gs:[0x30]
    return concrete_target.execute_shellcode(read_gs0_x64, exfiltration_reg)