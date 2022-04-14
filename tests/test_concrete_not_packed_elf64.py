import os
import unittest
import subprocess
import angr
import claripy


try:
    import avatar2
except ImportError:
    avatar2 = None

try:
    from angr_targets import AvatarGDBConcreteTarget
except  ImportError:
    AvatarGDBConcreteTarget = None


binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'not_packed_elf64'))

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999


BINARY_OEP = 0x4009B2
BINARY_DECISION_ADDRESS = 0x400AF3
DROP_STAGE2_V1 = 0x400B87
DROP_STAGE2_V2 = 0x400BB6
VENV_DETECTED = 0x400BC2
FAKE_CC = 0x400BD6
BINARY_EXECUTION_END = 0x400C03


@unittest.skipUnless(AvatarGDBConcreteTarget is not None, "skip")
@unittest.skipUnless(avatar2 is not None, "skip")
class TestConcrete(unittest.TestCase):
    @classmethod
    def setUp(self):
        subprocess.Popen("gdbserver %s:%s '%s'" % (GDB_SERVER_IP, GDB_SERVER_PORT, binary_x64), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=True)

    avatar_gdb = None

    @classmethod
    def tearDown(self):
        self.avatar_gdb
        if avatar_gdb:
            avatar_gdb.exit()

    def test_concrete_engine_linux_x64_simprocedures(self):
        global avatar_gdb
        # pylint: disable=no-member
        avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
        p = angr.Project(binary_x64, concrete_target=avatar_gdb, use_sim_procedures=True,
                         page_size=0x1000)
        entry_state = p.factory.entry_state()
        entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
        entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        self.solv_concrete_engine_linux_x64(p, entry_state)

    def execute_concretly(self, p, state, address, memory_concretize=[], register_concretize=[], timeout=0):
        simgr = p.factory.simgr(state)
        simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], memory_concretize=memory_concretize,
                                                                register_concretize=register_concretize,
                                                                timeout=timeout))
        exploration = simgr.run()
        return exploration.stashes['found'][0]

    def solv_concrete_engine_linux_x64(self, p, state):
        new_concrete_state = self.execute_concretly(p, state, BINARY_DECISION_ADDRESS, [])
        the_sp = new_concrete_state.solver.eval(new_concrete_state.regs.sp)
        concrete_memory = new_concrete_state.memory.load(the_sp,20)
        assert not concrete_memory.symbolic

        arg0 = claripy.BVS('arg0', 8*32)
        symbolic_buffer_address = new_concrete_state.regs.rbp-0xc0

        concrete_memory_2 = new_concrete_state.memory.load(symbolic_buffer_address, 36)
        assert not concrete_memory_2.symbolic
        new_concrete_state.memory.store(symbolic_buffer_address, arg0)

        # We should read symbolic data from the page now
        symbolic_memory = new_concrete_state.memory.load(symbolic_buffer_address, 36)
        assert symbolic_memory.symbolic

        # symbolic exploration
        simgr = p.factory.simgr(new_concrete_state)
        find_addr=DROP_STAGE2_V2
        avoid_addrs=[DROP_STAGE2_V1, VENV_DETECTED, FAKE_CC]

        simgr.use_technique(angr.exploration_techniques.DFS())
        simgr.use_technique(angr.exploration_techniques.Explorer(find=find_addr, avoid=avoid_addrs))

        new_concrete_state.globals["hit_malloc_sim_proc"] = False
        new_concrete_state.globals["hit_memcpy_sim_proc"] = False

        def check_hooked_simproc(state):
            sim_proc_name = state.inspect.simprocedure_name
            if sim_proc_name == "malloc":
                state.globals["hit_malloc_sim_proc"] = True
            elif sim_proc_name == "memcpy":
                state.globals["hit_memcpy_sim_proc"] = True

        new_concrete_state.inspect.b('simprocedure', action=check_hooked_simproc)
        simgr.explore()

        new_symbolic_state = simgr.stashes['found'][0]

        # Assert we hit the re-hooked SimProc.
        assert new_symbolic_state.globals["hit_malloc_sim_proc"]
        assert new_symbolic_state.globals["hit_memcpy_sim_proc"]

        binary_configuration = new_symbolic_state.solver.eval(arg0, cast_to=int)

        new_concrete_state = self.execute_concretly(p, new_symbolic_state, DROP_STAGE2_V2,
            [(symbolic_buffer_address, arg0)], [])

        # Asserting we reach the dropping of stage 2
        assert new_concrete_state.solver.eval(new_concrete_state.regs.pc) == DROP_STAGE2_V2

        # Go to the end.
        new_concrete_state = self.execute_concretly(p, new_concrete_state, BINARY_EXECUTION_END, [], [])
        assert new_concrete_state.solver.eval(new_concrete_state.regs.pc) == BINARY_EXECUTION_END

    def run_all(self):
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
                        all_functions[f].tearDown()

if __name__ == "__main__":
    unittest.main()
