from avatar2 import *
import subprocess
import nose
import struct
from angr_targets.avatar_gdb_target import GDBConcreteTarget
import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'binaries/hello'))
import logging
l = logging.getLogger("gdb_targets.test")
from nose.util import ln



class TestAvatarGDBTarget(object):

    def setUp(self):
        subprocess.Popen("gdbserver 127.0.0.1:1234 %s" % (test_location), shell=True)
        self.concrete_target = GDBConcreteTarget(archs.x86.X86_64, "127.0.0.1", 1234)

    def teardown(self):
        self.concrete_target.exit()

    @nose.tools.timed(5)
    def test_breakpoint(self):
        self.concrete_target.set_breakpoint(0x400526)
        self.concrete_target.run()
        pc_value = self.concrete_target.read_register('pc')
        nose.tools.assert_true(pc_value == 0x400526)
        print("----- address %s " % (self.concrete_target.read_register('pc')))

    @nose.tools.timed(5)
    def test_watchpoint(self):
        self.concrete_target.set_watchpoint(0x4005C4, write=False,read=True)
        self.concrete_target.run()
        pc_value = self.concrete_target.read_register('pc')
        nose.tools.assert_true(pc_value == 0x7ffff7aa3787) # address inside printf



    def test_read_memory(self):
        mem = self.concrete_target.read_memory(0x4005C4, 4, words=3)
        mem_string = struct.pack("%sI"%(len(mem)),*mem)
        nose.tools.assert_true(mem_string == "Hello World!")

    def test_writing_memory(self):
        self.concrete_target.write_memory(0x400624, 4, 0xaaaaaaaa)
        mem = self.concrete_target.read_memory(0x400624,4)
        nose.tools.assert_true(mem == 0xaaaaaaaa)

    def test_writing_register(self):
        self.concrete_target.write_register('rax', 0x11223344)
        reg = self.concrete_target.read_register('rax')
        nose.tools.assert_true(reg == 0x11223344)

