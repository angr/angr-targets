from avatar2 import *
import subprocess
from angr_targets.targets.avatar_gdb import AvatarGDBConcreteTarget
import os
from angr_targets.segment_registers import *

binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','x86_64','windows','simple_crackme_x64.exe'))

binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','i386','windows','simple_crackme'))
GDB_SERVER_IP = '192.168.56.101'
GDB_SERVER_PORT = 9999

ENTRY_POINT_X64 = 0x401500
ENTRY_POINT_X86 = 0x401500


class TestAvatarGDBTargetWindowsX86(object):

    def setUp(self):
        print("Configure a windows machine with a static IP  %s. "
              "Check windows firewall configurations to be sure that the connections to %s:%s are not blocked\n"
              "Install gdbserver on the machine, be careful the architecture (x86 or x64) of gdbserver should match the one of the debugged binary.\n"
              "Currently using MinGW for 32 bit gdbserver and Cygwin for 64 bit gdbserver" % (
              GDB_SERVER_IP, GDB_SERVER_IP, GDB_SERVER_PORT))
        print("On windows machine execute gdbserver %s:%s path/to/simple_crackme.exe" % (
        GDB_SERVER_IP, GDB_SERVER_PORT))
        raw_input("Press enter when the gdbserver is listening")
        self.concrete_target = AvatarGDBConcreteTarget(archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)

    def teardown(self):
        self.concrete_target.exit()

    def test_read_segment_register(self):

        # Reach  the instruction after the canary read  (mov    rax, qword ptr fs:[0x28]) to get the canary real value
        self.concrete_target.set_breakpoint(ENTRY_POINT_X64)
        self.concrete_target.run()

        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("eax")
        instr_content = self.concrete_target.read_memory(pc,0x10)
        print("Before segment register read:\n pc %x\n eax value %s\n instr content %s "%(pc,eax_value,instr_content.encode("hex")))

        canary_val = read_fs_register_windows_x86(self.concrete_target)
        print("FS  value %x " % (canary_val))

        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("eax")
        instr_content = self.concrete_target.read_memory(pc, 0x10)
        print("After segment register read:\n pc %x\n eax value %s\n instr content %s " % (pc, eax_value, instr_content.encode("hex")))



class TestAvatarGDBTargetWindowsX64(object):

    def setUp(self):
        print("Configure a windows machine with a static IP  %s."
              "Check windows firewall configurations to be sure that the connections to %s:%s are not blocked\n"
              "Install gdbserver on the machine be careful the architecture (x86 or x64) of gdbserver should match the one of the debugged binary.\n"
              "Currently using MinGW for 32 bit gdbserver and Cygwin for 64 bit gdbserver" % (
                  GDB_SERVER_IP, GDB_SERVER_IP, GDB_SERVER_PORT))
        print("On windows machine execute gdbserver %s:%s path/to/simple_crackme.exe" % (
            GDB_SERVER_IP, GDB_SERVER_PORT))
        raw_input("Press enter when the gdbserver is listening")

        self.concrete_target = AvatarGDBConcreteTarget(archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)

    def teardown(self):
        self.concrete_target.exit()


    def test_read_segment_register(self):

        # Reach  the instruction after the canary read  (mov    rax, qword ptr fs:[0x28]) to get the canary real value
        self.concrete_target.set_breakpoint(ENTRY_POINT_X64)
        self.concrete_target.run()

        print("after run")
        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("rax")
        instr_content = self.concrete_target.read_memory(pc,0x10)
        print("Before segment register read:\n pc %x\n eax value %s\n instr content %s "%(pc,eax_value,instr_content.encode("hex")))

        canary_val = read_gs_register_windows_x64(self.concrete_target)
        print("GS value %x " % (canary_val))

        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("rax")
        instr_content = self.concrete_target.read_memory(pc, 0x10)
        print("After segment register read:\n pc %x\n eax value %s\n instr content %s " % (pc, eax_value, instr_content.encode("hex")))



def test_gdbtarget_windows_x86():
    test_avatar_target_windows_x86 = TestAvatarGDBTargetWindowsX86()
    test_avatar_target_windows_x86.setUp()
    test_avatar_target_windows_x86.test_read_segment_register()


def test_gdbtarget_windows_x64():
    test_avatar_target_windows_x64 = TestAvatarGDBTargetWindowsX64()
    test_avatar_target_windows_x64.setUp()
    test_avatar_target_windows_x64.test_read_segment_register()


test_gdbtarget_windows_x64()