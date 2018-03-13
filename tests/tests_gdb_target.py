from avatar2 import *
import subprocess
import nose
from angr_targets.avatar_gdb_target import AvatarGDBConcreteTarget
import os

binary = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','x86_64','fauxware'))



class TestAvatarGDBTarget(object):

    def setUp(self):
        subprocess.Popen("gdbserver 127.0.0.1:1234 %s" % (binary), shell=True)
        self.concrete_target = AvatarGDBConcreteTarget(archs.x86.X86_64, "127.0.0.1", 1234)

    def teardown(self):
        self.concrete_target.exit()

    @nose.tools.timed(5)
    def test_breakpoint(self):
        self.concrete_target.set_breakpoint(0x40071D)
        self.concrete_target.run()
        pc_value = self.concrete_target.read_register('pc')
        nose.tools.assert_true(pc_value == 0x40071D)

    @nose.tools.timed(5)
    def test_watchpoint(self):
        self.concrete_target.set_watchpoint(0x400915, write=False,read=True)
        self.concrete_target.run()
        pc_value = self.concrete_target.read_register('pc')
        nose.tools.assert_true(pc_value == 0x7ffff7a9874a) # address inside printf

    def test_read_memory(self):
        mem = self.concrete_target.read_memory(0x400915, 8)
        nose.tools.assert_true(mem == "Username")

    def test_writing_memory(self):
        self.concrete_target.write_memory(0x400915, "\xaa\xaa\xaa\xaa")
        mem = self.concrete_target.read_memory(0x400915,4)
        nose.tools.assert_true(mem == "\xaa\xaa\xaa\xaa")

    def test_writing_register(self):
        self.concrete_target.write_register('rax', 0x11223344)
        reg = self.concrete_target.read_register('rax')
        nose.tools.assert_true(reg == 0x11223344)

