import angr
import claripy
import nose
import os
import subprocess

try:
    import avatar2
    from angr_targets import AvatarGDBConcreteTarget
except ImportError:
    raise nose.SkipTest()


binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'i386', 'packed_elf32'))

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999

UNPACKING_BINARY = 0xc51466
BINARY_OEP = 0x8048a15
BINARY_DECISION_ADDRESS = 0x8048B30
DROP_STAGE2_V1 = 0x8048BB8
DROP_STAGE2_V2 = 0x08048BED
VENV_DETECTED = 0x8048BFF
FAKE_CC = 0x8048C1C
BINARY_EXECUTION_END = 0x8048C49

avatar_gdb = None


def setup_x86():
    subprocess.Popen("gdbserver %s:%s '%s'" % (GDB_SERVER_IP, GDB_SERVER_PORT, binary_x86), stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, shell=True)


def teardown():
    global avatar_gdb
    if avatar_gdb:
        avatar_gdb.exit()


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_no_simprocedures():
    global avatar_gdb
    # pylint: disable=no-member
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=False,
                     page_size=0x1000)
    entry_state = p.factory.entry_state()
    entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
    entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
    solve_concrete_engine_linux_x86(p, entry_state)


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_unicorn_no_simprocedures():
    global avatar_gdb
    # pylint: disable=no-member
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=False,
                     page_size=0x1000)
    entry_state = p.factory.entry_state(add_options=angr.options.unicorn)
    entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
    entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
    solve_concrete_engine_linux_x86(p, entry_state)


def execute_concretly(p, state, address, memory_concretize=[], register_concretize=[], timeout=0):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], memory_concretize=memory_concretize,
                                                            register_concretize=register_concretize, timeout=timeout))
    exploration = simgr.run()
    return exploration.stashes['found'][0]


def solve_concrete_engine_linux_x86(p, entry_state):
    # until unpacking of stub
    new_concrete_state = entry_state

    # now until stub instructions
    for _ in range(0, 4):
        new_concrete_state = execute_concretly(p, new_concrete_state, UNPACKING_BINARY, [])

    new_concrete_state = execute_concretly(p, new_concrete_state, BINARY_DECISION_ADDRESS, [])

    arg0 = claripy.BVS('arg0', 8*32)
    symbolic_buffer_address = new_concrete_state.regs.ebp-0xa0
    new_concrete_state.memory.store(symbolic_buffer_address, arg0)

    # symbolic exploration
    simgr = p.factory.simgr(new_concrete_state)
    exploration = simgr.explore(find=DROP_STAGE2_V1, avoid=[DROP_STAGE2_V2, VENV_DETECTED, FAKE_CC])
    new_symbolic_state = exploration.stashes['found'][0]

    binary_configuration = new_symbolic_state.solver.eval(arg0, cast_to=int)

    execute_concretly(p, new_symbolic_state, BINARY_EXECUTION_END, [(symbolic_buffer_address, arg0)], [])

    correct_solution = 0xa000000f9ffffff000000000000000000000000000000000000000000000000
    nose.tools.assert_true(binary_configuration == correct_solution)
