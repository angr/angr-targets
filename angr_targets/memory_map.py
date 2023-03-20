
class MemoryMap:
    """
    Describing a memory range inside the concrete
    process.
    """
    def __init__(self, start_address, end_address, offset, name, perms):
        self.start_address = start_address
        self.end_address = end_address
        self.offset = offset
        self.name = name
        self.perms = perms

    def __str__(self):
        my_str = "MemoryMap[start_address: 0x%x | end_address: 0x%x | name: %s" \
              % (self.start_address,
                 self.end_address,
                 self.name)
        if self.perms:
            my_str += " | perms: %s"%self.perms

        return my_str
