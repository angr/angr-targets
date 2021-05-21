
import logging
import os

from avatar2 import *
from angr.errors import SimConcreteMemoryError, SimConcreteRegisterError, SimConcreteBreakpointError

from ..concrete import ConcreteTarget
from ..memory_map import MemoryMap
from ..target_states import TargetStates

l = logging.getLogger("angr_targets.avatar_gdb")
#l.setLevel(logging.DEBUG)

# Disable unnecessary avatar logs...
logging.getLogger("avatar").disabled = True

class AvatarGDBConcreteTarget(ConcreteTarget):
   
    def __init__(self,architecture, gdbserver_ip, gdbserver_port ):
        # Creation of the avatar-object
        self.avatar = Avatar(arch=architecture)
        self.architecture = architecture
        self.target = self.avatar.add_target(GDBTarget, gdb_executable="gdb-multiarch", gdb_ip=gdbserver_ip, gdb_port=gdbserver_port)
        self.avatar.init_targets()
        self.page_size = 0x1000  # I want this to be passed by the project in a clean way..
        super(AvatarGDBConcreteTarget, self).__init__()

    def exit(self):
        self.avatar.shutdown()

    def read_memory(self, address, nbytes, **kwargs):
        try:
            l.debug("AvatarGDBConcreteTarget read_memory at %x "%(address))
            page_end = (address | (self.page_size-1)) + 1

            if address + nbytes > page_end:
                nbytes = page_end - address

            res = self.target.read_memory(address, 1, int(nbytes), raw=True)
            return res
        except Exception as e:
            l.debug("AvatarGDBConcreteTarget can't read_memory at address %x exception %s"%(address,e))
            raise SimConcreteMemoryError("AvatarGDBConcreteTarget can't read_memory at address %x exception %s" % (address, e))

    def write_memory(self,address, value, **kwargs):
        # l.debug("AvatarGDBConcreteTarget write_memory at %x value %s " %(address, value.encode("hex")))
        try:
            res = self.target.write_memory(address, 1, value, raw=True)
            if not res:
                l.warning("AvatarGDBConcreteTarget failed write_memory at %x value %s" % (address,value))
                raise SimConcreteMemoryError("AvatarGDBConcreteTarget failed write_memory to address %x" % (address))
        except Exception as e:
            l.warning("AvatarGDBConcreteTarget write_memory at %x value %s exception %s" % (address, value, e))
            raise SimConcreteMemoryError("AvatarGDBConcreteTarget write_memory at %x value %s exception %s" % (address, str(value), e))

   
    def read_register(self,register,**kwargs):
        try:
            #l.debug("AvatarGDBConcreteTarget read_register at %s "%(register))
            register_value = self.target.read_register(register)
        except Exception as e:
            #l.debug("AvatarGDBConcreteTarget read_register %s exception %s %s "%(register,type(e).__name__,e))
            raise SimConcreteRegisterError("AvatarGDBConcreteTarget can't read register %s exception %s" % (register, e))
        # when accessing xmm registers and ymm register gdb return a list of 4/8 32 bit values
        # which need to be shifted appropriately to create a 128/256 bit value
        if type(register_value) is list:
            i = 0
            result = 0
            for val in register_value:
                cur_val = val << i * 32
                result |= cur_val
                i += 1
            return result
        else:
            return register_value

    def write_register(self, register, value, **kwargs):
        try:
            l.debug("AvatarGDBConcreteTarget write_register at %s value %x "%(register,value))
            res = self.target.write_register(register, value)
            if not res:
                l.warning("AvatarGDBConcreteTarget write_register failed reg %s value %x "%(register,value))
                raise SimConcreteRegisterError("AvatarGDBConcreteTarget write_register failed reg %s value %x " % (register, value))
        except Exception as e:
            l.warning("AvatarGDBConcreteTarget write_register exception write reg %s value %x %s "%(register,value,e))
            raise SimConcreteRegisterError("AvatarGDBConcreteTarget write_register exception write reg %s value %x %s " % (register, value, e))


    def set_breakpoint(self,address, **kwargs):
        """
        Inserts a breakpoint

        :param int address: The address at which to set the breakpoint
        :param optional bool hardware: Hardware breakpoint
        :param optional bool temporary:  Tempory breakpoint
        :param optional str regex:     If set, inserts breakpoints matching the regex
        :param optional str condition: If set, inserts a breakpoint with the condition
        :param optional int ignore_count: Amount of times the bp should be ignored
        :param optional int thread:    Thread cno in which this breakpoints should be added
        :raise angr.errors.ConcreteBreakpointError:
        """
        l.debug("AvatarGDBConcreteTarget set_breakpoint at %x "%(address))
        res = self.target.set_breakpoint(address, **kwargs)
        if res == -1:
            raise SimConcreteBreakpointError("AvatarGDBConcreteTarget failed to set_breakpoint at %x" % (address))

    def remove_breakpoint(self, address, **kwargs):
        l.debug("AvatarGDBConcreteTarget remove_breakpoint at %x "%(address))
        res = self.target.remove_breakpoint(address, **kwargs)
        if res == -1:
            raise SimConcreteBreakpointError("AvatarGDBConcreteTarget failed to set_breakpoint at %x" % (address))

    def set_watchpoint(self,address, **kwargs):
        """
        Inserts a watchpoint

        :param address: The name of a variable or an address to watch
        :param optional bool write:    Write watchpoint
        :param optional bool read:     Read watchpoint
        :raise angr.errors.ConcreteBreakpointError
        """
        l.debug("gdb target set_watchpoing at %x value", address)
        res = self.target.set_watchpoint(address, **kwargs)
        if res == -1:
            raise SimConcreteBreakpointError("AvatarGDBConcreteTarget failed to set_breakpoint at %x" % (address))

    def get_mappings(self):
        """
        Returns the mmap of the concrete process
        """

        l.debug("getting the vmmap of the concrete process")
        mapping_output = self.target.protocols.memory.get_mappings()

        mapping_output = mapping_output[1].split("\n")[4:]

        vmmap = []

        for map in mapping_output:
            map = map.split(" ")

            # removing empty entries
            map = list(filter(lambda x: x not in ["\\t", "\\n", ''], map))

            try:
                map_start_address = map[0].replace("\\n", '')
                map_start_address = map_start_address.replace("\\t", '')
                map_start_address = int(map_start_address, 16)
                map_end_address = map[1].replace("\\n", '')
                map_end_address = map_end_address.replace("\\t", '')
                map_end_address = int(map_end_address, 16)
                offset = map[3].replace("\\n", '')
                offset = offset.replace("\\t", '')
                offset = int(offset, 16)
                map_name = map[4].replace("\\n", '')
                map_name = map_name.replace("\\t", '')
                map_name = os.path.basename(map_name)
                vmmap.append(MemoryMap(map_start_address, map_end_address, offset, map_name))
            except (IndexError, ValueError):
                l.debug("Can't process this vmmap entry")
                pass

        return vmmap

    def is_running(self):
        return self.target.get_status() == TargetStates.RUNNING

    def stop(self):
        self.target.stop()

    def shutdown(self):
        self.target.shutdown()

    def run(self):
        """
        Resume the execution of the target
        """
        if not self.is_running():
            l.debug("gdb target run")
            #pc = self.read_register('pc')
            #print("Register before resuming: %#x" % pc)
            self.target.cont()
            self.target.wait()
        else:
            l.debug("gdb target is running!")
