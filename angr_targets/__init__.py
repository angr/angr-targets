from .targets.avatar_gdb import AvatarGDBConcreteTarget
from .concrete import ConcreteTarget

try:
    from .targets.ida_gui import IDAConcreteTarget
except Exception:
    pass