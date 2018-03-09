from avatar2 import *
from angr.engines import ConcreteTarget




'''
 User need to define its target inside the Angr script 
 like this. 
'''

class GDBConcreteTarget(ConcreteTarget):
   
    def __init__(self,architecture, gdbserver_ip, gdbserver_port ):
        # Creation of the avatar-object
        self.avatar = Avatar(arch=architecture)
        self.target = self.avatar.add_target(GDBTarget, gdb_executable="gdb", gdb_ip=gdbserver_ip, gdb_port=gdbserver_port)
        self.avatar.init_targets()

    def exit(self):
        self.avatar.shutdown()

    def read_memory(self,address, size, **kwargs):
        """
                Reading from memory of the target

                :param address:     The address to read from
                :param size:        The size of a read word
                :param words:       The amount of words to read (default: 1)
                :param raw:         Whether the read memory is returned unprocessed
                :return:          The read memory
        """
        return self.target.read_memory(address, size, **kwargs)

    def write_memory(self,address, size, value, **kwargs):
        """
                Writing to memory of the target

                :param address:   The address from where the memory-write should
                                  start
                :param size:      The size of the memory write
                :param value:     The actual value written to memory
                :type val:        int if num_words == 1 and raw == False
                                  list if num_words > 1 and raw == False
                                  str or byte if raw == True
                :param num_words: The amount of words to read
                :param raw:       Specifies whether to write in raw or word mode
                :returns:         True on success else False
        """
        print(address,size)
        return self.target.write_memory(address, size, value, **kwargs)
   
    def is_valid_address(self,address, **kwargs):
        raise NotImplementedError("ConcreteTarget is_valid_address not implemented")
   
    def read_register(self,register,**kwargs):
        """"
        Reads a register from the target
        :param register: The name of the register
        :return: int value of the register content
        """
        return self.target.read_register(register)

    def write_register(self, register, value, **kwargs):
        """
        Writes a register to the target
        :param register:     The name of the register
        :param value:        int value written to be written register
        """
        return self.target.write_register(register, value)
    
    def set_breakpoint(self,address, **kwargs):
        """Inserts a breakpoint

                :param bool hardware: Hardware breakpoint
                :param bool tempory:  Tempory breakpoint
                :param str regex:     If set, inserts breakpoints matching the regex
                :param str condition: If set, inserts a breakpoint with the condition
                :param int ignore_count: Amount of times the bp should be ignored
                :param int thread:    Threadno in which this breakpoints should be added
        """
        return self.target.set_breakpoint(address, **kwargs)

    def set_watchpoint(self,address, **kwargs):
        """Inserts a watchpoint

                :param      variable: The name of a variable or an address to watch
                :param bool write:    Write watchpoint
                :param bool read:     Read watchpoint
        """
        return self.target.set_watchpoint(address, **kwargs)

    def run(self):
        self.target.cont()
        self.target.wait()
    


