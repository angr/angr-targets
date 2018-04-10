import logging
l = logging.getLogger("angr_targets.concrete")
#l.setLevel(logging.DEBUG)

class ConcreteTarget(object):
    """
    Concrete target used inside the SimConcreteEngine.
    This object is defined in the Angr script.
    """
    def _init_(self):
        return


    def read_memory(self, address, length, **kwargs):
        raise NotImplementedError()

    def write_memory(self, address, data, **kwargs):
        raise NotImplementedError()

    def is_valid_address(self, address, **kwargs):
        raise NotImplementedError()

    def read_register(self, register, **kwargs):
        raise NotImplementedError()

    def write_register(self, register, value, **kwargs):
        raise NotImplementedError()

    def set_breakpoint(self, address, **kwargs):
        raise NotImplementedError()

    def remove_breakpoint(self, address, **kwargs):
        raise NotImplementedError()

    def set_watchpoint(self, address, **kwargs):
        raise NotImplementedError()

    def remove_watchpoint(self, address, **kwargs):
        raise NotImplementedError()

    def run(self):
        raise NotImplementedError()

    def execute_shellcode(self, shellcode, result_register):
        '''
        Use the methods provided by the ConcreteTarget to inject shellcode in concrete process and get the result of the shellcode in the "result_register" register

        :param concrete_target: ConcreteTarget where the shellcode will be injected
        :param shellcode: shellcode to be executed
        :param result_register: register which will contain the result
        :return: value contained in the result_register
        Example read fs[0] value on x64
            shellcode = "\x64\x48\x8B\x04\x25\x00\x00\x00\x00"    # mov rax, fs:[0]
            result_register = "rax"
            execute_shellcode(target, shellcode, result_register)
        '''
        len_payload = len(shellcode)
        l.debug("encoded shellcode  %s len shellcode %s" % (shellcode.encode("hex"), len_payload))

        pc = self.read_register("pc")
        l.debug("current pc %x" % (pc))

        # save the content of the current instruction
        old_instr_content = self.read_memory(pc, len_payload)
        l.debug("current instruction %s" % (old_instr_content.encode("hex")))

        # saving value of the register which will be used to read segment register
        old_reg_value = self.read_register(result_register)
        l.debug("exfitration reg %s value %x" % (result_register, old_reg_value))

        # writing to pc shellcode
        self.write_memory(pc, shellcode)
        cur_instr_after_write = self.read_memory(pc, len_payload)
        l.debug("current instruction after write %s" % (cur_instr_after_write.encode("hex")))

        self.set_breakpoint(pc + len_payload, temporary=True)
        self.run()
        result_value = self.read_register(result_register)
        l.debug("result value %x " % (result_value))

        # restoring previous pc
        self.write_register("pc", pc)
        # restoring previous instruction
        self.write_memory(pc, old_instr_content)
        # restoring previous rax value
        self.write_register(result_register, old_reg_value)

        pc = self.read_register("pc")
        eax_value = self.read_register(result_register)
        instr_content = self.read_memory(pc, len_payload)
        l.debug("pc %x eax value %x instr content %s " % (pc, eax_value, instr_content.encode("hex")))

        return result_value
