from .concrete import ConcreteTarget
import logging
l = logging.getLogger("angr_targets.init")
#l.setLevel(logging.DEBUG)
# The availability of the target depends on the environment in which angr is installed
# For example on the idaPython interpreter the IDAConcreteTarget is available but not the AvatarGDBConcreteTarget 
try:
    from .targets.avatar_gdb import AvatarGDBConcreteTarget
except Exception as e:
    l.error("Impossible to load AvatarGDBConcreteTarget exception %s"%(e))

try:
    from .targets.r2_target import R2ConcreteTarget
except Exception as e:
    l.error("Impossible to load R2ConcreteTarget exception %s"%(e))

'''
try:
    from .targets.ida_target import IDAConcreteTarget
except Exception as e:
    l.error("Impossible to load IDAConcreteTarget exception %s"%(e))
'''
