
import logging
#logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger('tests_r2_target_linux')

import os
import sys
from angr_targets import R2ConcreteTarget
import nose
import r2pipe

import angr, claripy

#
# x86_64
#

binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries','tests','x86_64','known_values_x64'))

binary_x64_breakpoint = 0x004011fa

rax = 0x3ec373b4667e84c0
rbx = 0xa602acd4c227da1d
rcx = 0x8807e4e63e154dbd
rdx = 0x7644b4b3b2bd76ad
rsi = 0x73b245d4fe9f7039
rdi = 0xab648b4505db20b6
r8  = 0xcdc3550dc8584425
r9  = 0xe3efe87851d603f5
r10 = 0x7c34483ec98d7bb7
r11 = 0xb4b176ca868be1ed
r12 = 0xf418c58fa13e485c
r13 = 0x1803882a9c2c801a
r14 = 0xecedb671e137e92f
r15 = 0x9dce02118db26baa
xmm0 = 0x43e6ca2beab80cd143defc418b1477ce
st7  = 0x3ffee8e8276e6a138800

#binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
#                                          os.path.join('..', '..', 'binaries','tests','i386','fauxware'))


def test_r2_target_linux_x64_read_registers():
    r2 = r2pipe.open(binary_x64, ['-d'])
    r2db = R2ConcreteTarget(r2)

    proj = angr.Project(r2.cmdj('ij')['core']['file'], concrete_target=r2db, use_sim_procedures=True)
    simgr = proj.factory.simulation_manager()
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[binary_x64_breakpoint]))
    simgr.run()

    nose.tools.assert_true(len(simgr.found) == 1)
    state = simgr.found[0]
    
    nose.tools.assert_true(state.solver.eval(state.regs.rax == rax))
    nose.tools.assert_true(state.solver.eval(state.regs.rbx == rbx))
    nose.tools.assert_true(state.solver.eval(state.regs.rcx == rcx))
    nose.tools.assert_true(state.solver.eval(state.regs.rdx == rdx))
    nose.tools.assert_true(state.solver.eval(state.regs.rsi == rsi))
    nose.tools.assert_true(state.solver.eval(state.regs.rdi == rdi))
    nose.tools.assert_true(state.solver.eval(state.regs.r8 == r8))
    nose.tools.assert_true(state.solver.eval(state.regs.r9 == r9))
    nose.tools.assert_true(state.solver.eval(state.regs.r10 == r10))
    nose.tools.assert_true(state.solver.eval(state.regs.r11 == r11))
    nose.tools.assert_true(state.solver.eval(state.regs.r12 == r12))
    nose.tools.assert_true(state.solver.eval(state.regs.r13 == r13))
    nose.tools.assert_true(state.solver.eval(state.regs.r14 == r14))
    nose.tools.assert_true(state.solver.eval(state.regs.r15 == r15))
    nose.tools.assert_true(state.solver.eval(state.regs.xmm0 == xmm0))
    # TODO: For the moment, ST regs are not being sync'd to angr. Re-add this once they are being sync'd.
    #nose.tools.assert_true(state.solver.eval(state.regs.st7 == st7))

    r2db.exit()

def test_r2_target_linux_x64_write_registers():
    r2 = r2pipe.open(binary_x64, ['-d'])
    r2db = R2ConcreteTarget(r2)
    
    new_value = 0x1212121245454545
    r2db.write_register('rax', new_value)
    nose.tools.assert_true(r2db.read_register('rax') == new_value)
    r2db.exit()

def test_r2_target_linux_x64_read_write_memory():
    r2 = r2pipe.open(binary_x64, ['-d'])
    r2db = R2ConcreteTarget(r2)

    proj = angr.Project(r2.cmdj('ij')['core']['file'], concrete_target=r2db, use_sim_procedures=True)
    simgr = proj.factory.simulation_manager()
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[binary_x64_breakpoint]))
    simgr.run()

    nose.tools.assert_true(len(simgr.found) == 1)
    state = simgr.found[0]

    # Pre-existing values in program
    nose.tools.assert_true( state.mem[state.regs.rbp-0x16].string.concrete == b'Test string 2' )
    nose.tools.assert_true( state.mem[0x00404030].string.concrete == b'Test string 1' )

    # Write some stuff
    new_string = b'This is my shiny new string. ZOMG!'
    r2db.write_memory(0x00404030, new_string)

    state.concrete.sync()
    nose.tools.assert_true( state.mem[0x00404030].string.concrete == new_string )
    
    r2db.exit()


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
