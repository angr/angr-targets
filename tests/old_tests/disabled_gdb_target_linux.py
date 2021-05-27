from avatar2 import *
import subprocess
from angr_targets.targets.avatar_gdb import AvatarGDBConcreteTarget
import os
from angr_targets.segment_registers import *
import nose

binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','x86_64','fauxware'))

binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','i386','fauxware'))

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999

ENTRY_POINT_X64 = 0x40071D
ADDRESS_USERNAME_X64 = 0x400915
WATCHPOINT_TRIGGER_X64 = 0x7ffff7a9874a

ENTRY_POINT_X86 = 0x80485FC
ADDRESS_USERNAME_X86 = 0x8048801
WATCHPOINT_TRIGGER_X86 = 0xf7e705d1

class TestAvatarGDBTargetLinuxX64(object):

    def setUp(self):
        subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64), shell=True)
        self.concrete_target = AvatarGDBConcreteTarget(archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)

    def teardown(self):
        self.concrete_target.exit()

    @nose.tools.timed(5)
    def test_breakpoint(self):
        print("test breakpoint ")
        self.concrete_target.set_breakpoint(ENTRY_POINT_X64)
        self.concrete_target.run()
        pc_value = self.concrete_target.read_register('pc')
        nose.tools.assert_true(pc_value == ENTRY_POINT_X64)

    @nose.tools.timed(5)
    def test_watchpoint(self):
        print("test watchpoint ")
        self.concrete_target.set_watchpoint(ADDRESS_USERNAME_X64, write=False,read=True)
        self.concrete_target.run()
        pc_value = self.concrete_target.read_register('pc')
        #nose.tools.assert_true((pc_value & 0xfff) == (WATCHPOINT_TRIGGER_X64) # address inside printf may change based on libc version

    def test_read_memory(self):
        print("test read memory")
        mem = self.concrete_target.read_memory(ADDRESS_USERNAME_X64, 8)
        nose.tools.assert_true(mem == "Username")



    def test_writing_memory(self):
        print("test write memory")
        self.concrete_target.write_memory(ADDRESS_USERNAME_X64, "\xaa\xaa\xaa\xaa")
        mem = self.concrete_target.read_memory(ADDRESS_USERNAME_X64,4)
        nose.tools.assert_true(mem == "\xaa\xaa\xaa\xaa")


    def test_writing_register(self):
        print("test write register")
        self.concrete_target.write_register('rax', 0x11223344)
        reg = self.concrete_target.read_register('rax')
        nose.tools.assert_true(reg == 0x11223344)


    def test_read_segment_register(self):
        print("test read segment register")
        self.concrete_target.set_breakpoint(ENTRY_POINT_X64)
        self.concrete_target.run()

        old_pc = self.concrete_target.read_register("pc")
        old_eax_value = self.concrete_target.read_register("rax")
        old_instr_content = self.concrete_target.read_memory(old_pc,0x10)
        print("Before segment register read: pc %x\n eax value %s\n instr content %s "%(old_pc,old_eax_value,old_instr_content.encode("hex")))

        fs_value = read_fs_register_linux_x64(self.concrete_target)
        print("FS value %x " % (fs_value))

        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("rax")
        instr_content = self.concrete_target.read_memory(pc, 0x10)

        nose.tools.assert_true((fs_value & 0xfff) == (0x7ffff7fd3700 & 0xfff), "Wrong address of fs (gdb always make fs point to 0x7ffff7fd3700 )") # Checking
        nose.tools.assert_true(old_pc == pc, "PC not correctly restored")
        nose.tools.assert_true(old_eax_value == eax_value, "EAX not correctly restored")
        nose.tools.assert_true(old_instr_content == instr_content, "Old instruction not correctly restored")

        print("After segment register read: pc %x eax value %s instr content %s " % (pc, eax_value, instr_content.encode("hex")))


class TestAvatarGDBTargetLinuxX86(object):

    def setUp(self):
        subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x86), shell=True)
        self.concrete_target = AvatarGDBConcreteTarget(archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)

    def teardown(self):
        self.concrete_target.exit()

    @nose.tools.timed(5)
    def test_breakpoint(self):
        self.concrete_target.set_breakpoint(ENTRY_POINT_X86)
        self.concrete_target.run()
        pc_value = self.concrete_target.read_register('pc')
        nose.tools.assert_true(pc_value == ENTRY_POINT_X86)

    @nose.tools.timed(5)
    def test_watchpoint(self):
        self.concrete_target.set_watchpoint(ADDRESS_USERNAME_X86, write=False,read=True)
        self.concrete_target.run()
        pc_value = self.concrete_target.read_register('pc')
        print("pc value after watchpoint %x should be %x"%(pc_value,WATCHPOINT_TRIGGER_X86))
        #nose.tools.assert_true((pc_value & 0xfff) == (WATCHPOINT_TRIGGER_X86 & 0xfff)) # address inside printf may change based on libc versions

    def test_read_memory(self):
        mem = self.concrete_target.read_memory(ADDRESS_USERNAME_X86, 8)
        nose.tools.assert_true(mem == "Username")

    def test_writing_memory(self):
        self.concrete_target.write_memory(ADDRESS_USERNAME_X86, "\xaa\xaa\xaa\xaa")
        mem = self.concrete_target.read_memory(ADDRESS_USERNAME_X86,4)
        nose.tools.assert_true(mem == "\xaa\xaa\xaa\xaa")

    def test_writing_register(self):
        self.concrete_target.write_register('eax', 0x11223344)
        reg = self.concrete_target.read_register('eax')
        nose.tools.assert_true(reg == 0x11223344)


    def test_read_segment_register(self):
        print("test read segment register")
        self.concrete_target.set_breakpoint(ENTRY_POINT_X86)
        self.concrete_target.run()

        old_pc = self.concrete_target.read_register("pc")
        old_eax_value = self.concrete_target.read_register("eax")
        old_instr_content = self.concrete_target.read_memory(old_pc,0x10)
        print("Before segment register read: pc %x\n eax value %s\n instr content %s "%(old_pc,old_eax_value,old_instr_content.encode("hex")))

        fs_value = read_gs_register_linux_x86(self.concrete_target)
        print("FS value %x " % (fs_value))

        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("eax")
        instr_content = self.concrete_target.read_memory(pc, 0x10)

        nose.tools.assert_true( (fs_value & 0xfff) == (0xf7dfa700 & 0xfff), "Wrong address of fs (gdb always make fs point to 0xf7dfa700 )") # Checking
        nose.tools.assert_true(old_pc == pc, "PC not correctly restored")
        nose.tools.assert_true(old_eax_value == eax_value, "EAX not correctly restored")
        nose.tools.assert_true(old_instr_content == instr_content, "Old instruction not correctly restored")

        print("After segment register read: pc %x eax value %s instr content %s " % (pc, eax_value, instr_content.encode("hex")))









