from .concrete import ConcreteTarget
import logging
l = logging.getLogger("angr_targets.init")
#l.setLevel(logging.DEBUG)
# The availability of the target depends on the environment in which angr is installed
# For example on the idaPython interpreter the IDAConcreteTarget is available but not the AvatarGDBConcreteTarget 
try: 
  from .targets.avatar_gdb import AvatarGDBConcreteTarget
except Exception:
    l.info("Impossible to load AvatarGDBConcreteTarget")


try:
    from .targets.ida_target import IDAConcreteTarget
except Exception:
    l.info("Impossible to load IDAConcreteTarget")
