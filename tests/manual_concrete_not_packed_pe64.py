import angr
import avatar2
import claripy
import os

from angr_targets import AvatarGDBConcreteTarget


binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'x86_64',
                                       'windows', 'not_packed_pe64.exe'))


GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999

STARTING_DECISION_ADDRESS = 0x401786
DROP_V1 = 0x4017FC
DROP_V2 = 0x401827
MALWARE_EXECUTION_END = 0x401863
FAKE_CC = 0x40184D
VENV_DETECTED = 0x401835


avatar_gdb = None

'''
def setup_x64():
    print("Configure a windows machine with a static IP  %s. "
          "Check windows firewall configurations to be sure that the connections to %s:%s are not blocked\n"
          "Install gdbserver on the machine, b"
          "e careful the architecture (x86 or x64) of gdbserver should be the same as the debugged binary.\n"
          "Currently using Cygwin for 32 bit gdbserver and Cygwin for 64 bit gdbserver" % (GDB_SERVER_IP,
                                                                                           GDB_SERVER_IP,
                                                                                           GDB_SERVER_PORT))

    print("On windows machine execute gdbserver %s:%s path/to/simple_crackme.exe" % (GDB_SERVER_IP, GDB_SERVER_PORT))
    input("Press enter when gdbserver has been executed")
'''

def teardown():
    global avatar_gdb
    if avatar_gdb:
        avatar_gdb.exit()


def test_concrete_engine_windows_x64_no_simprocedures():
    #print("test_concrete_engine_windows_x64_no_simprocedures")
    global avatar_gdb
    try:
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x64, concrete_target=avatar_gdb, use_sim_procedures=False,
                         page_size=0x1000)
        entry_state = p.factory.entry_state()
        entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
        entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        solv_concrete_engine_windows_x64(p, entry_state)
    except ValueError:
        #print("Failing executing test")
        pass

def test_concrete_engine_windows_x64_simprocedures():
    #print("test_concrete_engine_windows_x64_simprocedures")
    global avatar_gdb
    try:
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x64, concrete_target=avatar_gdb, use_sim_procedures=True,
                         page_size=0x1000)
        entry_state = p.factory.entry_state()
        entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
        entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        solv_concrete_engine_windows_x64(p, entry_state)
    except ValueError:
        #print("Failing executing test")
        pass


def test_concrete_engine_windows_x64_unicorn_no_simprocedures():
    #print("test_concrete_engine_windows_x64_unicorn_no_simprocedures")
    global avatar_gdb
    try:
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x64, concrete_target=avatar_gdb, use_sim_procedures=False,
                         page_size=0x1000)
        entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
        entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
        entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        solv_concrete_engine_windows_x64(p, entry_state)
    except ValueError:
        #print("Failing executing test")
        pass


def test_concrete_engine_windows_x64_unicorn_simprocedures():
    #print("test_concrete_engine_windows_x64_unicorn_simprocedures")
    global avatar_gdb
    try:
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x64, concrete_target=avatar_gdb, use_sim_procedures=True,
                         page_size=0x1000)
        entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
        entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
        entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        solv_concrete_engine_windows_x64(p, entry_state)
    except ValueError:
        #print("Failing executing test")
        pass


def execute_concretly(p, state, address, memory_concretize=[], register_concretize=[], timeout=0):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], memory_concretize=memory_concretize,
                                                            register_concretize=register_concretize, timeout=timeout))
    exploration = simgr.run()
    return exploration.stashes['found'][0]


def solv_concrete_engine_windows_x64(p, entry_state):
    #print("[1]Executing malware concretely until address: " + hex(STARTING_DECISION_ADDRESS))
    new_concrete_state = execute_concretly(p, entry_state, STARTING_DECISION_ADDRESS, [])

    # declaring symbolic buffer
    arg0 = claripy.BVS('arg0', 8 * 32)
    symbolic_buffer_address = new_concrete_state.regs.rbp - 0x60
    new_concrete_state.memory.store(new_concrete_state.solver.eval(symbolic_buffer_address), arg0)

    #print("[2]Symbolically executing malware to find dropping of second stage [ address:  " + hex(DROP_V1) + " ]")
    simgr = p.factory.simgr(new_concrete_state)
    exploration = simgr.explore(find=DROP_V1, avoid=[FAKE_CC, DROP_V2, VENV_DETECTED])
    new_symbolic_state = exploration.stashes['found'][0]

    #print("[3]Executing malware concretely with solution found until the end " + hex(MALWARE_EXECUTION_END))
    execute_concretly(p, new_symbolic_state, MALWARE_EXECUTION_END, [(symbolic_buffer_address, arg0)], [])

    #print("[4]Malware execution ends, the configuration value downloaded from C&C is: " + hex(
    #    new_symbolic_state.solver.eval(arg0, cast_to=int)))
