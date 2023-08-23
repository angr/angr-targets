import os
import unittest
import angr
import claripy

try:
    import pandare
except ImportError:
    pandare = None

try:
    from angr_targets import PandaConcreteTarget
except ImportError:
    PandaConcreteTarget = None


binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'x86_64',
                                       'not_packed_elf64'))


# Relative addresses just to prove we can
BINARY_OEP = 0x9B2
BINARY_DECISION_ADDRESS = 0xAF3
DROP_STAGE2_V1 = 0xB87
DROP_STAGE2_V2 = 0xBB6
VENV_DETECTED = 0xBC2
FAKE_CC = 0xBD6
BINARY_EXECUTION_END = 0xC03

@unittest.skipUnless(pandare is not None, "requires pandare")
class TestPanda(unittest.TestCase):
    '''
    Test the PandaConcreteTarget by running a PANDA guest, then switching
    to a symbolic execution with angr when we hit BINARY_DECISION_ADDRESS.
    '''
    def test_concrete_engine_linux_x64_simprocedures(self):
        '''
        Create a PANDA object and run an x86_64 guest system.  Inside the guest,
        copy our target binary and run it until it reaches the decision point.
        At the decision point, run a symbolic execution to find the path
        we're looking for. Then use that info to change concrete state
        and resume the PANDA execution.
        '''
        panda = pandare.Panda(generic="x86_64")
        panda_target = PandaConcreteTarget(panda)

        # Register function to drive the PANDA guest once it starts
        @panda.queue_blocking
        def driver():
            '''
            Drive the PANDA guest during emulation.
            First revert to a snapshot, then copy our binary in,
            and finally run it. Assert if we don't see the "stage 2" output
            that we should see if the symex finds the right path.
            '''
            panda.revert_sync("root")
            panda.copy_to_guest(binary_x64)
            # Run the command
            output = panda.run_serial_cmd("./not_packed_elf64/not_packed_elf64")
            assert "Executing stage 2" in output, f"Unexpected output: {output}"
            panda.end_analysis()

        @panda.ppp("proc_start_linux", "on_rec_auxv")
        def proc_start(cpu, _, auxv):
            '''
            Use PANDA's proc_start_linux plugin to detect the start of every
            process. When we see the target process start, use it's base load
            address to register a hook on the target function. When that hook
            triggers, we'll switch to angr for symex.
            '''
            name = panda.ffi.string(auxv.argv[0]).decode()

            if name.split("/")[-1] != 'not_packed_elf64':
                return # Not our target

            # Get memory maps and find where executable is loaded
            # This might be handled by target.get_mappings() automatically?
            code_base = None
            for mapping in panda.get_mappings(cpu):
                map_name = panda.ffi.string(mapping.name).decode()
                # First map with matching name is the one we want
                if map_name == 'not_packed_elf64':
                    print(f"Found target {map_name} with base {mapping.base:x}")
                    code_base = mapping.base
                    break
            else:
                raise RuntimeError("Could not find target binary in maps")

            print(f"Registering hook at {BINARY_DECISION_ADDRESS+code_base:x}")
            @panda.hook(BINARY_DECISION_ADDRESS+code_base)
            def decision_hook(_cpu, _tb, hook):
                '''
                This hook will be called when the target binary hits the
                specified address. In here, we'll launch our symex.
                When this returns, the concrete guest will resume.
                '''
                # Craft our angr project while panda guest is stopped here
                proj = angr.Project(binary_x64,
                                    concrete_target=panda_target,
                                    use_sim_procedures=True)

                entry_state = proj.factory.entry_state()
                entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
                entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

                # Sync state from panda into angr
                entry_state.concrete.sync()

                # Run a symex to find a valid solution
                soln_addr, soln = self.solv_concrete_engine_linux_x64(proj, entry_state, code_base)

                # Write the solution back into the concrete guest's memory
                panda_target.write_memory(soln_addr, soln)

                # Disable this hook so it doesn't trigger again
                hook.enabled = False

        # Start the emulation
        panda.run()

    @staticmethod
    def solv_concrete_engine_linux_x64(proj, new_concrete_state, base_address):
        '''
        Run a symbolic execution from the decision point with the stack set
        to unconstrained symbolic data. Find a path to the DROP_STAGE2_V2
        address while avoiding the DROP_STAGE2_V1, VENV_DETECTED, and
        FAKE_CC addresses. Return the address of the solution and the
        solution itself. Also assert that we hit malloc and memcpy as
        we'd expect to during the symex.

        '''
        # Read the stack and make sure it's concrete
        the_sp = new_concrete_state.solver.eval(new_concrete_state.regs.sp)
        assert not new_concrete_state.memory.load(the_sp,20).symbolic

        # Ensure the original stack buffer is concrete, then replace it with symbolic data
        arg0 = claripy.BVS('arg0', 8*32)
        symbolic_buffer_address = new_concrete_state.regs.rbp-0xc0
        assert not new_concrete_state.memory.load(symbolic_buffer_address, 36).symbolic
        new_concrete_state.memory.store(symbolic_buffer_address, arg0)

        # Ensure that the new buffer is symbolic
        assert new_concrete_state.memory.load(symbolic_buffer_address, 36).symbolic

        # Run our symbolic execution
        simgr = proj.factory.simgr(new_concrete_state)

        find_addr=DROP_STAGE2_V2+base_address
        avoid_addrs=[x + base_address for x in [DROP_STAGE2_V1, VENV_DETECTED, FAKE_CC]]

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

        # Return a concrete address (int) and buffer (bytes) that will reach our goal
        conc_buffer_address = new_symbolic_state.solver.eval(symbolic_buffer_address)
        binary_configuration = new_symbolic_state.solver.eval(arg0, cast_to=bytes)
        return (conc_buffer_address, binary_configuration)

if __name__ == "__main__":
    unittest.main()
