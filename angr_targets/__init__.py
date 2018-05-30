from .concrete import ConcreteTarget
<<<<<<< HEAD
from .targets.avatar_gdb import AvatarGDBConcreteTarget

try:
 from .targets.ida_gui import IDAConcreteTarget
except Exception:
    pass

=======

try:
    from .targets.ida_gui import IDAConcreteTarget
except Exception:
    pass
>>>>>>> 4e927e55700aa1d35982b5b1af4ccd00a1c26818
