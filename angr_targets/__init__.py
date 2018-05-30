from .concrete import ConcreteTarget
from .targets.avatar_gdb import AvatarGDBConcreteTarget

try:
 from .targets.ida_gui import IDAConcreteTarget
except Exception:
    pass

