from enum import IntEnum


class Role(IntEnum):
    ADMIN = 0
    CLIENT = 1

ROLES = [('ADMIN', 'Admin'), ('CLIENT', 'Client')]
