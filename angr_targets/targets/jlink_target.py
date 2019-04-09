
import logging
from angr.errors import SimConcreteMemoryError, SimConcreteRegisterError, SimConcreteBreakpointError
import re
from ..concrete import ConcreteTarget

l = logging.getLogger("jlink_target")
l.setLevel(logging.DEBUG)

try:
    import pylink
except ImportError:
    pylink = None


class JLinkConcreteTarget(ConcreteTarget):
   
    def __init__(self, jlink):
        self.jlink = jlink
        super(JLinkConcreteTarget, self).__init__()
        self._update_reg_table()

    def _update_reg_table(self):
        # Stupid JLink and its stupid register scheme...
        self.reg_table = {}
        altname_re = re.compile(r'(\S+) \((\S+)\)')
        for rn in self.jlink.register_list():
            name = self.jlink.register_name(rn)
            m = altname_re.match(name)
            if m:
                name1 = m.group(1).lower()
                name2 = m.group(2).lower()
                self.reg_table[name1] = rn
                self.reg_table[name2] = rn
            else:
                self.reg_table[name.lower()] = rn

    def exit(self):
        self.jlink.close()

    def read_memory(self, address, nbytes, **kwargs):
        """
        Reading from memory of the target

            :param int address: The address to read from
            :param int nbytes:  The amount number of bytes to read
            :return:        The memory read
            :rtype: str
            :raise angr.errors.SimMemoryError
        """
        l.debug("JLinkConcreteTarget read_memory at %x "%(address))

        try:
            bs = self.jlink.memory_read(addr, nbytes)
        except pylink.JLinkException:
            raise SimConcreteMemoryError(error)

        return bytes(bs)

    def write_memory(self,address, value, **kwargs):
        """
        Writing to memory of the target
            :param int address:   The address from where the memory-write should start
            :param bytes value:     The actual value written to memory
            :raise angr.errors.ConcreteMemoryError
        """

        assert type(value) is bytes, 'write_memory value is actually type {}'.format(type(value))

        l.debug("JLinkConcreteTarget write_memory at %x value %s " %(address, value))

        try:
            self.jlink.memory_write(address, value)
        except Exception as e:
            l.exception("JLinkConcreteTarget write_memory at %x value %s exception %s"%(address,value,e))
            raise SimConcreteMemoryError("JLinkConcreteTarget write_memory at %x value %s exception %s" % (address, str(value), e))

    def read_register(self,register,**kwargs):
        """"
        Reads a register from the target
            :param str register: The name of the register
            :return: int value of the register content
            :rtype int
            :raise angr.errors.ConcreteRegisterError in case the register doesn't exist or any other exception
        """
        try:
            rn = self.reg_table[register.lower()]
        except KeyError:
            raise SimConcreteRegisterError("Register %s does not exist", register)
        try:
            return self.jlink.register_read(rn)
        except pylink.JLinkException:
            l.exception("Error reading register %s", register)

    def write_register(self, register, value, **kwargs):
        """
        Writes a register to the target
            :param str register:     The name of the register
            :param int value:        int value written to be written register
            :raise angr.errors.ConcreteRegisterError
        """
        try:
            rn = self.reg_table[register.lower()]
        except KeyError:
            raise SimConcreteRegisterError("Register %s does not exist", register)
        try:
            return self.jlink.register_write(rn, value)
        except pylink.JLinkException:
            l.exception("Error writing register %s", register)

    def set_breakpoint(self, address, **kwargs):
        """Inserts a breakpoint

                :param optional bool hardware: Hardware breakpoint
                :param optional bool temporary:  Tempory breakpoint
                :param optional str regex:     If set, inserts breakpoints matching the regex
                :param optional str condition: If set, inserts a breakpoint with the condition
                :param optional int ignore_count: Amount of times the bp should be ignored
                :param optional int thread:    Thread cno in which this breakpoints should be added
                :raise angr.errors.ConcreteBreakpointError
        """

        if kwargs != {}:
            l.warning('JLinkConcreteTarget set_breakpoint called with extra args "{}". Currently, R2 is not handling these and will set breakpoint as normal software breakpoint.'.format(kwargs))

        l.debug("JLinkConcreteTarget set_breakpoint at %x "%(address))
        try:
            self.jlink.breakpoint_set(addr)
        except pylink.JLinkException:
            l.exception("Error setting breakpoint at %#08x", address)
            raise SimConcreteBreakpointError()

    def remove_breakpoint(self, address, **kwargs):
        bn = self.jlink.breakpoint_find(address)
        if bn == 0:
            raise SimConcreteBreakpointError("Breakpoint does not exist!")
        self.jlink.breakpoint_clear(bn)

    def set_watchpoint(self,address, **kwargs):
        """Inserts a watchpoint

                :param address: The name of a variable or an address to watch
                :param optional bool write:    Write watchpoint
                :param optional bool read:     Read watchpoint
                :raise angr.errors.ConcreteBreakpointError
        """

        read = kwargs.pop('read', False)
        write = kwargs.pop('write', False)
        try:
            self.jlink.watchpoint_set(address, read=read, write=write)
        except pylink.JLinkException:
            l.exception("Error setting watchpoint at %#08x", address)
            raise SimConcreteBreakpointError()

    def remove_watchpoint(self,address, **kwargs):
        """Removes a watchpoint

                :param address: The name of a variable or an address to watch
                :raise angr.errors.ConcreteBreakpointError
        """
        wn = self.jlink.watchpoint_find(address)
        if wn == 0:
            raise SimConcreteBreakpointError("Watchpoint does not exist!")
        self.jlink.watchpoint_clear(bn)

    def get_mappings(self):
        """Returns the mmap of the concrete process
        :return:
        """
        # TODO: We should technically be able to do this.
        # but I think jlink's library is missing some bits
        raise NotImplementedError("That's cute.")

    def reset(self, halt=False):
        self.jlink.reset(halt=halt)
        
    def is_running(self):
        return self.jlink.halted() is False

    def stop(self):
        self.jlink.halt()
        if not self.jlink.halted():
            raise SimConcreteBreakpointError("Failed to halt target!")

    def run(self):
        """
        Resume the execution of the target
        :return:
        """
        self.jlink.restart()

    @property
    def architecture(self):
        # JLink only supports ARM, you monsters!
        name = self.jlink.core_name()
        if 'Cortex-M' in name:
            return "ARMCortexM"
        elif 'Cortex-A' in name:
            return "AArch64"
        else:
            return "ARMEL"
        # TODO: Technically we can debug armbe, but who the hell does that??

    @property
    def bits(self):
        if '64' in self.architecture:
            return 64
        else:
            return 32


def create_jlink(serial=None, ip_addr=None, target=None):
    """
    Get a JLinkConcreteTarget for the given ip/serial, and core target descriptor


    :param serial: The JLink adapter's serial number OR
    :param ip_addr: The JLink adapter's IP address (for JLink/JTrace PRO)
    :param target: The JLink terget descriptor. Usually tne model name of the CPU (e.g., 'STM32L152RE' or somesuch)
    :return: A JLink target
    """
    # TODO: Add some heavy kwargs stuff here
    if not pylink:
        raise RuntimeError("You should install pylink-square before using this")
    try:
        # Setup the JLink DLL
        j = pylink.JLink()
    except:
        l.exception("Could not open JLink.  Either JLink is already in use, or the JLink software is not installed!")
        raise RuntimeError("Could not open JLink.  Either JLink is already in use, or the JLink software is not installed!")
    try:
        if serial:
            j.open(serial_no=serial)
        elif ip_addr:
            j.open(ip_addr=ip_addr)
        else:
            raise ValueError("Must supply either serial or ip_addr")
    except pylink.JLinkException:
        l.exception("Could not conenct to JLink!")
        raise RuntimeError("Could not connect to JLink! Is your JLink plugged in?")
    if not target:
        raise RuntimeError("Must supply a target type")
    try:
        j.connect(target)
    except pylink.JLinkException:
        l.exception("Could not connect to target of type %s", target)
        raise RuntimeError("Could not connect to target of type %s", target)
    ct = JLinkConcreteTarget(j)
    return ct
