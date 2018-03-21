from avatar2 import *
import subprocess
import nose
import struct
from angr_targets.avatar_gdb_target import AvatarGDBConcreteTarget
import os

binary = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','x86_64','checkbyte'))



class TestAvatarGDBTarget(object):

    def setUp(self):
        subprocess.Popen("gdbserver 127.0.0.1:9999 %s" % (binary), shell=True)
        self.concrete_target = AvatarGDBConcreteTarget(archs.x86.X86_64, "127.0.0.1", 9999)

    def teardown(self):
        self.concrete_target.exit()
    '''
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
    '''
    def test_read_segment_register(self):

        # Brean to the instruction after the canary read  (mov    rax, qword ptr fs:[0x28]) to get the canary real value
        self.concrete_target.set_breakpoint(0x4005fe)
        self.concrete_target.run()
        real_canary_val = self.concrete_target.read_register("rax")
        print("real canary value %x"%(real_canary_val))

        #execute until the instruction which removes the canary value from rax
        self.concrete_target.set_breakpoint(0x400604)
        self.concrete_target.run()


        print("--- Before executing segment read")
        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("rax")
        instr_content = self.concrete_target.read_memory(pc,0x10)
        print("--- pc %x\n eax value %s\n instr content %s "%(pc,eax_value,instr_content.encode("hex")))
        #for i in range(0x20,0x50,8):
        #   print("-----------------------------------")
        #    canary_val  = self.read_fs_register(0x28)
        #    print("fs value read at offset %x value %x "%(i,canary_val))

        print("-----------------------------------")
        canary_val  = self.read_fs_register(0x28)
        print("fs value read at offset 0x28 value %x " % ( canary_val))
        print("-----------------------------------")
        canary_val = self.read_fs_register(0x28)
        print("fs value read at offset 0x28 value %x " % (canary_val))
        print("-----------------------------------")

        print("--- After executing segment read")
        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("rax")
        instr_content = self.concrete_target.read_memory(pc, 0x10)
        print("--- pc %x eax value %s instr content %s " % (pc, eax_value, instr_content.encode("hex")))




    def read_fs_register(self,offset):
        '''
                asm_get_fs = asm(mov eax fs:[0xoffset])
                eip = get_register("eip")
                eax_val = read_register("eax")
                old_instruction = read_memory("eip",len(asm_get_fs))
                write_memory("eip", asm_get_fs)
                Set breakpoint(eip+len(asm_get_fs))
                run()
                Gs_val = Read_register(eax)
                set_register("eax",eax_val)
                set_register("eip",eip)
                write_memory("eip", old_instruction)
        '''
        # register used to read the value of the segment register
        exfiltration_reg = "rax"
        # instruction to inject for reading the value at segment value = offset
        #read_fs_x64 = "\x64\x48\x8B\x04\x25" + (struct.pack("B",offset)) + "\x00\x00\x00"
        read_fs_x64 = "\x64\x48\x8B\x04\x25{}\x00\x00\x00"
        read_fs_x64_with_offset = read_fs_x64.format( struct.pack("B",offset))
        len_payload = len(read_fs_x64_with_offset)
        print("encoded shellcode  %s len shellcode %s"%(read_fs_x64_with_offset.encode("hex"),len_payload))



        pc = self.concrete_target.read_register("pc")
        print("current pc %x"%(pc))

        #save the content of the current instruction
        old_instr_content = self.concrete_target.read_memory(pc,len_payload)
        print("current instruction %s"%(old_instr_content.encode("hex")))

        # saving value of the register which will be used to read segment register
        exfiltration_reg_val = self.concrete_target.read_register(exfiltration_reg)
        print("exfitration reg %s value %x"%(exfiltration_reg,exfiltration_reg_val))

        #writing to eip ( mov    eax, dword ptr fs:[0x28])
        self.concrete_target.write_memory(pc,read_fs_x64_with_offset)
        cur_instr_after_write = self.concrete_target.read_memory(pc,len_payload)
        print("current instruction after write %s"%(cur_instr_after_write.encode("hex")))

        self.concrete_target.set_breakpoint(pc+len_payload)
        self.concrete_target.run()
        fs_value = self.concrete_target.read_register(exfiltration_reg)
        print("fs value %x "%(fs_value))

        # restoring previous pc
        self.concrete_target.write_register("pc",pc)
        # restoring previous instruction
        self.concrete_target.write_memory(pc, old_instr_content)
        # restoring previous rax value
        self.concrete_target.write_register(exfiltration_reg,exfiltration_reg_val)

        pc = self.concrete_target.read_register("pc")
        eax_value = self.concrete_target.read_register("rax")
        instr_content = self.concrete_target.read_memory(pc, 0x10)
        print("--- pc %x eax value %s instr content %s " % (pc, eax_value, instr_content.encode("hex")))

        return fs_value














