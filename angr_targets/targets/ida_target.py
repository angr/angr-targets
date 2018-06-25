import logging
import sys

import idaapi
import idc
import ida_funcs

from angr.errors import  SimConcreteRegisterError, SimConcreteMemoryError, SimConcreteBreakpointError
from ..concrete import ConcreteTarget


l = logging.getLogger("angr_targets.idatarget")
#l.setLevel(logging.DEBUG)


class ReadMemoryCallable:
    def __init__(self, address, nbytes, *args, **kwargs):
        self.address = address
        self.nbytes = nbytes
        self.result = None
        self.exception = False

    def __call__(self):
        l.debug("ida target reads memory at %x" % self.address)
        self.result = idc.read_dbg_memory(self.address, self.nbytes)
        if not self.result:
            self.exception = True


class WriteMemoryCallable:
    def __init__(self, address, value, *args, **kwargs):
        self.address = address
        self.value = value
        self.success = False
        self.exception = False

    def __call__(self):
        try:
            l.debug("gdb target write memory at %x value %s " % (self.address, self.value.encode("hex")))
            self.written_bytes = idc.write_dbg_memory(self.address, self.value)
        except Exception as e:
            l.debug("write_memory exception %s"%(e))
            self.exception = True


class ReadRegisterCallable:
    def __init__(self, register, *args, **kwargs):
        self.register = register
        self.result = None
        self.exception = False

    def __call__(self):
        try:
            self.result = idc.get_reg_value(self.register)
        except Exception as e:
            l.debug("read_register exception %s"%(e))
            self.exception = True


class WriteRegisterCallable:
    def __init__(self, register, value, *args, **kwargs):
        self.register = register
        self.value = value
        self.result = None
        self.exception = False

    def __call__(self):
        try:
            self.result = idc.set_reg_value(self.value, self.register)
        except Exception as e:
            l.debug("write_register exception %s"%(e))
            self.exception = True


class SetBreakpointCallable:
    def __init__(self, address, hardware=False, *args, **kwargs):
        self.address = address
        self.hardware = hardware
        self.result = None
        self.exception = False

    def __call__(self):
        try:
            if self.hardware:
                bp_flag = idc.BPT_EXEC  # default is hardware https://www.hex-rays.com/products/ida/support/sdkdoc/group___b_p_t___h.html
            else:
                bp_flag = (idc.BPT_SOFT | idc.BPT_EXEC)

            idc.add_bpt(self.address, bp_flag)
            enable_res = idc.enable_bpt(self.address, True)

            l.debug("bp flag value %x enable_res %s" % (bp_flag, enable_res))

            self.result = enable_res

        except Exception as e:
            l.debug("set_breakpoint exception %s"%(e))
            self.exception = True


class ResumeAndWaitBreakpoint:
    def __init__(self, mode, flag, *args, **kwargs):
        self.mode = mode
        self.flag = flag
        self.result = None
        self.exception = False

    def __call__(self):
        try:
            idaapi.continue_process()
            idc.GetDebuggerEvent(self.mode, self.flag)
            l.debug("Debugger stopped at " + hex(idc.get_reg_value('eip')))
        except Exception:
            self.exception = True


class DeleteBreakpointCallable:
    def __init__(self, address, *args, **kwargs):
        self.address = address
        self.result = None
        self.exception = False

    def __call__(self):
        try:
            self.result = idc.del_bpt(self.address)
        except Exception as e:
            l.debug("remove_breakpoint exception %s"%(e))
            self.exception = True


class MakeUnknown:
    def __init__(self, address, size, *args, **kwargs):
        self.address = address
        self.size = size
        self.exception = False

    def __call__(self):
        try:
            l.debug("Making unknown at " + hex(self.address))
            self.result = idc.MakeUnkn(self.address, self.size)
        except Exception:
            self.exception = True


class MakeCode:
    def __init__(self, address, *args, **kwargs):
        self.address = address
        self.exception = False

    def __call__(self):
        try:
            l.debug("Making code at " + hex(self.address))
            self.result = idc.MakeCode(self.address)
        except Exception:
            self.exception = True


class MakeComment:
    def __init__(self, address, text, *args, **kwargs):
        self.address = address
        self.text = text
        self.exception = False

    def __call__(self):
        try:
            l.debug("Making comment at " + hex(self.address))
            self.result = idc.MakeComm(self.address, self.text)
        except Exception as e:
            self.exception = True


class MakeFunction:
    def __init__(self, address, *args, **kwargs):
        self.address = address
        self.exception = False

    def __call__(self):
        try:
            l.debug("Making function at " + hex(self.address))
            self.result = idc.MakeFunction(self.address)
        except Exception:
            self.exception = True


class SetLineColor:
    def __init__(self, color, address, *args, **kwargs):
        self.color = color
        self.address = address
        self.exception = False

    def __call__(self):
        try:
            self.result = idc.SetColor(self.address, idc.CIC_ITEM, self.color)
        except Exception as e:
            self.exception = True


class EditFunctionBoundaries:
    def __init__(self, start_address, end_address, *args, **kwargs):
        self.start_address = start_address
        self.end_address = end_address
        self.exception = False

    def __call__(self):
        try:
            l.debug("Updating function boundaries of function | start_address: " + hex(self.start_address) + " | end_address: " + hex(self.end_address))
            self.result = ida_funcs.set_func_end(self.start_address, self.end_address)
            l.debug("Updating function boundaries result: " + str(self.result))
        except Exception:
            self.exception = True




class IDAConcreteTarget(ConcreteTarget):

    def __init__(self, headless=False, binary_path=None):
        '''
        Initialize the IdaConcreteTarget. Nothing has to be done if the target is used inside the IDA Debugger but when
        using IDA in headless mode (without the GUI) we need to start the debugger by ourselves.
        :param :bool headless: headless mode is used when IDA is launched without the GUI
        :param :str binary_path: optional path to the binary needed only
        Example
            To run a script in IDA headless mode use:
            > idat.exe -c -A -S"angr_script.py" -t
            > idat -c -A -S"angr_script.py" -t
        '''
        self.headless = headless

        if binary_path and not self.headless:
            l.warn("The binary path is needed only when using IDA in headless mode")

        if self.headless:
            if binary_path is None:
                l.warn("You should provide a binary path when running IDA in headless mode")
                self.exit()

            idc.SetInputFilePath(binary_path)
            l.debug("Running IDA in headless mode. Initializing the debugger")
            idaapi.autoWait()
            if sys.platform is "win32":
                idc.LoadDebugger("win32", 0)
            else:
                idc.LoadDebugger("linux", 0)
            # entry_point = idc.GetLongPrm(INF_START_IP)
            # print("adding breakpoint at %x"%(entry_point))
            idc.SetInputFilePath(binary_path)
            # idc.AddBpt(entry_point)
            idc.SetDebuggerOptions(idc.DOPT_START_BPT)
            idc.StartDebugger("", "", "")
            idc.ResumeProcess()
            idc.GetDebuggerEvent(idc.WFNE_SUSP, -1)

            l.debug("Debugger initialized")

        super(IDAConcreteTarget, self).__init__()

    def exit(self):
        if self.headless:
            idc.Exit(0)

    def read_register(self, register, *args, **kwargs):
        """"
        Reads a register from the target
            :param register: The name of the register
            :return: int value of the register content
            :rtype int
        """
        if register == 'pc':
            if idaapi.get_inf_structure().is_64bit():
                register = 'rip'
            else:
                register = 'eip'

        action = ReadRegisterCallable(register)
        idaapi.execute_sync(action, 0)
        if action.exception:
            raise SimConcreteRegisterError
        else:
            return action.result

    def write_register(self, register, value, *args, **kwargs):
        """
        Writes a register to the target
            :param register:     The name of the register
            :param value:        int value written to be written register
            :rtype int
        """

        if register == 'pc':
            if idaapi.get_inf_structure().is_64bit():
                register = 'rip'
            else:
                register = 'eip'

        action = WriteRegisterCallable(register, value)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise SimConcreteRegisterError
        else:
            return action.result

    def read_memory(self, address, nbytes, *args, **kwargs):
        """
        Reading from memory of the target

            :param address:     The address to read from
            :param nbytes:       The amount number of bytes to read
            :return:          The read memory
            :rtype: str
        """

        l.debug("ida target read_memory at %x " % (address))
        action = ReadMemoryCallable(address, nbytes)
        idaapi.execute_sync(action, 0)

        if action.exception:
            #l.debug("Exception during read!")
            raise SimConcreteMemoryError
        else:
            return action.result

    def write_memory(self, address, value, *args, **kwargs):
        """
        Writing to memory of the target
            :param address:   The address from where the memory-write should
                              start
            :param value:     The actual value written to memory
            :type value:      str
            :returns:         True on success else False
        """
        l.debug("gdb target write memory at %x value %s " % (address, value.encode("hex")))
        action = WriteMemoryCallable(address, value)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise SimConcreteMemoryError
        else:
            return action.written_bytes


    def set_breakpoint(self, address, hardware=False, *args, **kwargs):
        """Inserts a breakpoint

                :param bool hardware: Hardware breakpoint
                :param bool temporary:  Temporary breakpoint\
                :returns:         True on success else False

        """

        l.debug("ida target set_breakpoint at %x " % (address))

        action = SetBreakpointCallable(address, hardware)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise SimConcreteBreakpointError
        else:
            return action.result

    def remove_breakpoint(self, address, *args, **kwargs):
        l.debug("ida_target removing breakpoint at %x " % (address))

        action = DeleteBreakpointCallable(address)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise SimConcreteBreakpointError
        else:
            return action.result

    def set_watchpoint(self, address, *args, **kwargs):
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

        l.debug("bp flag value %x attr_res %s enable_res %s"%(bp_flag,attr_res,enable_res))
        return attr_res and enable_res # return False if enable or setting attributes fails


    def make_unknown(self,address,size):

        action = MakeUnknown(address, size)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise Exception
        else:
            return action.result

    def make_code(self, address):

        action = MakeCode(address)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise Exception
        else:
            return action.result

    def make_function(self, address):
        action = MakeFunction(address)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise Exception
        else:
            return action.result

    def make_comment(self, address, comment):
        action = MakeComment(address, comment)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise Exception
        else:
            return action.result


    def set_line_color(self, color, address):

        action = SetLineColor(color, address)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise Exception
        else:
            return action.result

    def edit_function_boundaries(self, start_address, end_address):

        action = EditFunctionBoundaries(start_address, end_address)
        idaapi.execute_sync(action, 0)

        if action.exception:
            raise Exception
        else:
            return action.result


    def run(self, *args, **kwargs):
        """
        Resume the execution of the target
        :return:
        """
        action = ResumeAndWaitBreakpoint(idc.WFNE_SUSP, -1)
        idaapi.execute_sync(action, 0)


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

        shellcode_address = idaapi.get_imagebase()

        old_pc = self.read_register("eip")
        l.debug("current pc %x" % (old_pc))

        # save the content of the current instruction
        old_instr_content = self.read_memory(shellcode_address, len_payload)

        l.debug("current data %s" % (old_instr_content.encode("hex")))

        # saving value of the register which will be used to read segment register
        old_reg_value = self.read_register(result_register)
        l.debug("exfiltration reg %s value %x" % (result_register, old_reg_value))

        # writing to pc shellcode
        self.write_memory(shellcode_address, shellcode)

        self.make_unknown(shellcode_address, len_payload)
        print("making code at %s size %s" % (shellcode_address,len_payload))
        for addr in range(shellcode_address, shellcode_address+len_payload):
            self.make_code(shellcode_address)

        # -2 is to avoid the warning from IDA about rip pointing to data and not code
        self.set_breakpoint(shellcode_address + len_payload-2, temporary=True)

        self.write_register("eip", shellcode_address)

        self.run()

        result_value = self.read_register(result_register)
        l.debug("result value %s " % (hex(result_value)))

        # restoring previous pc
        self.write_register("eip", old_pc)

        l.debug("Current eip value is %x " % (self.read_register("eip")))

        self.remove_breakpoint(shellcode_address + len_payload-2)

        # restoring previous instruction
        self.write_memory(shellcode_address, old_instr_content)

        # restoring previous rax value
        self.write_register(result_register, old_reg_value)

        return result_value


