from avatar2 import *
from angr_targets.concrete import ConcreteTarget
from angr.errors import SimMemoryError
import logging
l = logging.getLogger("angr_targets.avatar_gdb")
l.setLevel(logging.DEBUG)


class AvatarGDBConcreteTarget(ConcreteTarget):
   
    def __init__(self,architecture, gdbserver_ip, gdbserver_port ):
        # Creation of the avatar-object
        self.avatar = Avatar(arch=architecture)
        self.target = self.avatar.add_target(GDBTarget, gdb_executable="gdb", gdb_ip=gdbserver_ip, gdb_port=gdbserver_port)
        self.avatar.init_targets()

    def exit(self):
        self.avatar.shutdown()

    def read_memory(self,address, nbytes, **kwargs):
        """
a        Reading from memory of the target

            :param address:     The address to read from
            :param nbytes:       The amount number of bytes to read (default: 1)
            :param raw:         Whether the read memory is returned unprocessed
            :return:          The read memory
            :rtype: str
        """
        try:
            res =  self.target.read_memory(address, 1, nbytes, raw=True,**kwargs)
            if(0xf7df7000 < address < 0xf7df9700 ):
                l.debug("----------- GS READ gdb target read_memory at %x " % (address))
                l.debug(res.encode("hex"))
            #l.debug("gdb target read_memory at %x "%(address))

            return res
        except Exception:
            raise SimMemoryError


    def write_memory(self,address, value, **kwargs):
        """
        Writing to memory of the target
            :param address:   The address from where the memory-write should
                              start
            :param value:     The actual value written to memory
            :type value:      str
            :returns:         True on success else False
        """
        l.debug("gdb target write memory at %x value %s "%(address,value.encode("hex")))
        return self.target.write_memory(address, 1, value, raw=True, **kwargs)
   
    def is_valid_address(self,address, **kwargs):
        raise NotImplementedError("ConcreteTarget is_valid_address not implemented")
   
    def read_register(self,register,**kwargs):
        """"
        Reads a register from the target
            :param register: The name of the register
            :return: int value of the register content
            :rtype int
        """
        return self.target.read_register(register)

    def write_register(self, register, value, **kwargs):
        """
        Writes a register to the target
            :param register:     The name of the register
            :param value:        int value written to be written register
            :rtype int
        """
        l.debug("gdb target write_register at %s value %x "%(register,value))
        return self.target.write_register(register, value)
    
    def set_breakpoint(self,address, **kwargs):
        """Inserts a breakpoint

                :param bool hardware: Hardware breakpoint
                :param bool tempory:  Tempory breakpoint
                :param str regex:     If set, inserts breakpoints matching the regex
                :param str condition: If set, inserts a breakpoint with the condition
                :param int ignore_count: Amount of times the bp should be ignored
                :param int thread:    Thread cno in which this breakpoints should be added
        """
        l.debug("gdb target set_breakpoint at %x "%(address))
        return self.target.set_breakpoint(address, **kwargs)

    def set_watchpoint(self,address, **kwargs):
        """Inserts a watchpoint

                :param      variable: The name of a variable or an address to watch
                :param bool write:    Write watchpoint
                :param bool read:     Read watchpoint
        """
        l.debug("gdb target set_watchpoing at %x value"%(address))
        return self.target.set_watchpoint(address, **kwargs)

    def run(self):
        """
        Resume the execution of the target
        :return:
        """
        l.debug("gdb target run")
        self.target.cont()
        self.target.wait()
    


