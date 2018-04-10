#from angr_targets.concrete import ConcreteTarget
#from angr.errors import SimMemoryError
import logging
l = logging.getLogger("angr_targets.idagui")
l.setLevel(logging.DEBUG)
import idaapi
import idc
import idautils





USERNAME_STRING_X64 = 0x400915
AFTER_ENTRYPOINT_X64 = 0x400728

def test_registers():
    print("starting debugger")
    idc.StartDebugger("","","")
    idc.GetDebuggerEvent(idc.PROCESS_START,-1)
    ida = IDAConcreteTarget()
    ida.set_breakpoint(AFTER_ENTRYPOINT_X64, temporary=True)
    ida.run()
    print("rip value after breakpoint %x"%(ida.read_register("rip")))
    ida.write_register("rax",0x11223344)
    print("rax value after write rax 0x11223344: %x"%(ida.read_register("rax")))
    idc.StopDebugger()
    idc.GetDebuggerEvent(idc.PROCESS_EXIT,-1)
    print("stopping debugger")


def test_memory():
    print("starting debugger")
    idc.StartDebugger("","","")
    idc.GetDebuggerEvent(idc.PROCESS_START,-1)
    ida = IDAConcreteTarget()
    ida.set_breakpoint(AFTER_ENTRYPOINT_X64, temporary=True)
    ida.run()
    print("rip value after breakpoint %x"%(ida.read_register("rip")))
    print("memory content at 0x%x %s "%(USERNAME_STRING_X64, ida.read_memory(USERNAME_STRING_X64,8)))
    ida.write_memory(USERNAME_STRING_X64,"Go on sir")
    print("memory content at 0x%x after write_memory('Go on sir') %s "%(USERNAME_STRING_X64, ida.read_memory(USERNAME_STRING_X64,9)))
    idc.StopDebugger()
    idc.GetDebuggerEvent(idc.PROCESS_EXIT,-1)
    print("stopping debugger")









def test_watchpoint():
    idc.StartDebugger("","","")
    idc.GetDebuggerEvent(idc.PROCESS_START, -1)
    ida = IDAConcreteTarget()
    ida.set_watchpoint(USERNAME_STRING_X64, temporary=True)
    ida.run()
    print("rip value after watchpoint 0x%x"%(ida.read_register("rip")))
    idc.StopDebugger()
    idc.GetDebuggerEvent(idc.PROCESS_EXIT, -1)
    print("stopping debugger")






class IDAConcreteTarget():


    def exit(self):
        pass

    def read_register(self, register):
        """"
        Reads a register from the target
            :param register: The name of the register
            :return: int value of the register content
            :rtype int
        """
        return idc.get_reg_value(register)

    def write_register(self, register, value):
        """
        Writes a register to the target
            :param register:     The name of the register
            :param value:        int value written to be written register
            :rtype int
        """
        l.debug("ida target write_register at %s value %x " % (register, value))
        return idc.set_reg_value(value,register)

    def read_memory(self, address, nbytes):
        """
        Reading from memory of the target

            :param address:     The address to read from
            :param nbytes:       The amount number of bytes to read
            :return:          The read memory
            :rtype: str
        """

        l.debug("ida target read_memory at %x " % (address))
        try:
            return idc.read_dbg_memory(address, nbytes)
        except Exception:
            #raise SimMemoryError
            return ""


    def write_memory(self, address, value):
        """
        Writing to memory of the target
            :param address:   The address from where the memory-write should
                              start
            :param value:     The actual value written to memory
            :type value:      str
            :returns:         True on success else False
        """
        l.debug("gdb target write memory at %x value %s " % (address, value.encode("hex")))
        written_bytes = idc.write_dbg_memory(address,value)
        if written_bytes == -1:
            return False
        return True


    def set_breakpoint(self, address, temporary=False, hardware=False):
        """Inserts a breakpoint

                :param bool hardware: Hardware breakpoint
                :param bool temporary:  Temporary breakpoint\
                :returns:         True on success else False

        """
        l.debug("ida target set_breakpoint at %x " % (address))
        if hardware:
            bp_flag = idc.BPT_EXEC #default is hardware https://www.hex-rays.com/products/ida/support/sdkdoc/group___b_p_t___h.html
        else:
            bp_flag = (idc.BPT_SOFT|idc.BPT_EXEC)

        idc.add_bpt(address, bp_flag)
        enable_res = idc.enable_bpt(address, True)

        if temporary:
            condition = """
                        enable_bpt(%d,0);
                        return 1;
                        """ % (address) # not best solution but works. Tried different approaches:
                                        # del_bpt(%d); return True:  got error True is undefined
                                        # del_bpt(%d); return 1: breakpoint doesn't stop the execution
            cond_res = idc.SetBptCnd(address, condition)
            l.debug("bp flag value %x  enable_res %s cond_res %s" % (bp_flag, enable_res,cond_res))
            return enable_res and cond_res # return False if:m enable or setting condition fails
        l.debug("bp flag value %x enable_res %s"%(bp_flag,enable_res))
        return enable_res

    def set_watchpoint(self, address, temporary=False):
        """Inserts a watchpoint which is triggered when a read or a write is executed on address

                :param      address: The name of a variable or an address to watch
                :param bool temporary:  Temporary breakpoint
                :returns:         True on success else False


        """
        idc.add_bpt(address)
        bp_flag = idc.BPT_RDWR # BPT_RDWR = 3 https://www.hex-rays.com/products/ida/support/sdkdoc/group___b_p_t___h.html setting Read Write breakpoint because some debuggers (Linux local)  doesn't support
        l.debug("ida target set_watchpoing at %x value" % (address))
        idc.set_bpt_attr(address, idc.BPTATTR_SIZE, 1)
        attr_res = idc.set_bpt_attr(address, idc.BPTATTR_TYPE, bp_flag)
        enable_res = idc.enable_bpt(address, True)


        if temporary:
            condition = """
                        enable_bpt(%d,0);
                        return 1;
                       """ % (address)  # not best solution but works. Tried different approaches:
                                        # del_bpt(%d); return True:  got error True is undefined
                                        # del_bpt(%d); return 1: breakpoint doesn't stop the execution
            cond_res = idc.SetBptCnd(address, condition)
            l.debug("bp flag value %x attr_res %s enable_res %s cond_res %s" % (bp_flag, attr_res, enable_res,cond_res))
            return attr_res and enable_res and cond_res # return False if: enable or setting attributes or setting condition fails

        l.debug("bp flag value %x attr_res %s enable_res %s"%(bp_flag,attr_res,enable_res))
        return attr_res and enable_res # return False if enable or setting attributes fails

    def run(self):
        """
        Resume the execution of the target
        :return:
        """
        l.debug("ida target run")
        idaapi.continue_process()
        idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)


test_registers()
test_memory()
#test_watchpoint()