import logging
from angr.errors import SimConcreteMemoryError, SimConcreteRegisterError

from ..concrete import ConcreteTarget
from ..memory_map import MemoryMap

l = logging.getLogger("angr_targets.panda")

class PandaConcreteTarget(ConcreteTarget):
    '''
    Unlike other concrete targets, the PandaConcreteTarget is not initialized with a binary.
    Instead, a user controls the PANDA instance directly and uses PANDA callbacks to pause
    execution when they wish to initalize and run a symbolic execution using Symbion.

    Note we could expand this interface to also support a mode where a binary is passed in
    and concretely executed to a breakpoint. However, this is pretty much what the
    AvatarConcreteTarget does, so maybe there's no need. If we wanted to do that, we'd need
    to implement the various NYI methods at the end of this file.
    '''
    def __init__(self, panda, *args, **kwargs):
        self.panda = panda
        self.architecture = panda.arch_name
        super().__init__(*args, **kwargs)


    def read_memory(self, address, nbytes, **kwargs):
        try:
            l.debug("PandaConcreteTarget read_memory at %x", address)
            res = self.panda.virtual_memory_read(self.panda.get_cpu(), address, nbytes)
            return res
        except Exception as exn:
            l.debug("PandaConcreteTarget can't read_memory at address %x exception" \
                     " %s", address, exn)

            raise SimConcreteMemoryError("PandaConcreteTarget can't read_memory at" \
                                         f" address {address:x}") from exn

    def write_memory(self,address, value, **kwargs):
        l.debug("PandaConcreteTarget write_memory at %x value %s", address, value)
        try:
            self.panda.virtual_memory_write(self.panda.get_cpu(), address, value)
        except Exception as exn:
            l.warning("PandaConcreteTarget write_memory at %x value %s exception %s",
                      address, value, exn)
            raise SimConcreteMemoryError(f"PandaConcreteTarget write_memory at {address:x}" \
                                         f" value {value}") from exn

    def read_register(self, register, **kwargs):
        # TODO: doesn't support xmm/ymm registers
        try:
            if self.architecture == 'x86_64' and register.endswith('_seg'):
                register = register.split('_seg')[0]
            elif self.architecture in ['mips', 'mipsel'] and register == 's8':
                register = 'R30'

            register_value = self.panda.arch.get_reg(self.panda.get_cpu(), register)

            l.debug("PandaConcreteTarget read_register %s value %x", register, register_value)
            return register_value
        except Exception as exn:
            l.debug("PandaConcreteTarget read_register %s exception %s %s",
                      register, type(exn).__name__, exn)
            raise SimConcreteRegisterError("PandaConcreteTarget can't read register" \
                                           f" {register}") from exn

    def write_register(self, register, value, **kwargs):
        l.debug("PandaConcreteTarget write_register at %s value %x ", register,value)
        try:
            self.panda.write_register(register, value)
        except Exception as exn:
            l.warning("PandaConcreteTarget write_register exception write reg %s value %x: %s",
                      register, value, exn)
            raise SimConcreteRegisterError(f"PandaConcreteTarget write_register exception write" \
                                           f" reg {register} value {value:x}") from exn


    def get_mappings(self):
        """
        Returns the memory mappings of the currently-running process using PANDA's
        operating system introspection.
        """
        l.debug("getting the vmmap of the concrete process")
        mapping_output = self.panda.get_mappings(self.panda.get_cpu())

        vmmap = []
        for mapping in mapping_output:
            if mapping.file == self.panda.ffi.NULL:
                continue # Unknown name
            filename = self.panda.ffi.string(mapping.file).decode()
            vmmap.append(MemoryMap(mapping.base, mapping.base + mapping.size, mapping.offset,
                                   filename))

        return vmmap

    def execute_shellcode(self, shellcode, result_register):
        # We don't support executing shellcode. But SimLinux wants to read some registers
        # using shellcode. So if we detect one of these requests, just return the value
        # from the concrete panda state.
        if self.architecture == "x86_64":
            read_gs0_x64 = b"\x65\xA1\x00\x00\x00\x00\x90\x90\x90\x90" # mov eax, gs:[0]
            read_fs0_x64 = b"\x64\x48\x8B\x04\x25\x00\x00\x00\x00\x90\x90\x90\x90" # mov rax, fs:[0]

            if shellcode == read_fs0_x64:
                return self.panda.get_cpu().env_ptr.segs[4].base # FS

            if shellcode == read_gs0_x64:
                return self.panda.get_cpu().env_ptr.segs[5].base # GS

        raise NotImplementedError("execute_shellcode not implemented for panda target")

    # If we want this class to be more like the standard concrete targets, we should implement
    # the following methods.
    def is_running(self):
        raise NotImplementedError("is_running not implemented for panda target")

    def add_breakpoint(self, address):
        raise NotImplementedError("add_breakpoint not implemented for panda target")

    def remove_breakpoint(self, address, **kwargs):
        raise NotImplementedError("remove_breakpoint not implemented for panda target")

    def wait_for_breakpoint(self, which=None):
        raise NotImplementedError("wait_for_breakpoint not implemented for panda target")

    def set_watchpoint(self, address, **kwargs):
        raise NotImplementedError("set_watchpoint not implemented for panda target")

    def remove_watchpoint(self, address, **kwargs):
        raise NotImplementedError("remove_watchpoint not implemented for panda target")

    def run(self, **kwargs):
        raise NotImplementedError("run not implemented for panda target")

    def step(self, **kwargs):
        raise NotImplementedError("step not implemented for panda target")

    def stop(self, **kwargs):
        raise NotImplementedError("stop not implemented for panda target")
