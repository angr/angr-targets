## Overview
This repository contains the currently implemented angr concrete targets.

An angr concrete target is the implementation of the ConcreteTarget interface which allows angr 
to synchronize a SimState with the state of running process inside a debugging environment (gdbserver, IDA debugger...). 
After that you can continue to analyse the binary with angr using as a memory backend the concrete process memory.
Finally, you can use the results of the analysis to modify the process memory and control its execution path. 

The angr concrete target needs to implement the ConcreteTarget interface which means:
- `read_memory(address,nbytes)`: Mandatory
- `write_memory(address, value)`: Mandatory
- `read_register(register)`: Mandatory
- `write_register(register, value)`: Mandatory
- `set_breakpoint(address)`: Mandatory
- `remove_breakpoint(self, address)`: Mandatory
- `set_watchpoint(self, address)`: Optional
- `remove_watchpoint(self, address)`: Optional
- `run(self)`: Mandatory

In the ConcreteTarget class docstrings you can find the detailed definition of the methods and the types of arguments/return values

Currently we have implemented 2 targets:
- `AvatarGDBTarget`: Connects to a gdbserver instance which is running the process to synchronize the state with.
- `RadareTarget`: Connects to a r2 instance.
- `IDAConcreteTarget`: Uses the memory backend provided by the IDA Pro debugger.

## Install

```sh
$ cd angr-targets
$ pip install --process-dependency-links -e .
```

