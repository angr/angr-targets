from .concrete import ConcreteTarget
# The availability of the target depends on the environment in which angr is installed
# For example on the idaPython interpreter the IDAConcreteTarget is available but not the AvatarGDBConcreteTarget 
try: 
  from .targets.avatar_gdb import AvatarGDBConcreteTarget
  from .targets.ida_gui import IDAConcreteTarget
except Exception:
    pass
