
class TargetStates(IntEnum):
    """
    Enum copied from avatar target
    A simple Enum for the different states a target can be in.
    """
    CREATED = 0x1
    INITIALIZED = 0x2
    STOPPED = 0x4
    RUNNING = 0x8
    SYNCING = 0x10
    EXITED = 0x20
    NOT_RUNNING = INITIALIZED | STOPPED
