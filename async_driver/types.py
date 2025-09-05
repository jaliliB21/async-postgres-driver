def parse_int(value: bytes) -> int:
    """Parses a byte string into an integer."""
    return int(value.decode('utf-8'))


def parse_bool(value: bytes) -> bool:
    """Parses a byte string into a boolean."""
    return value.decode('utf-8') == 't'


def parse_str(value: bytes) -> str:
    """Parses a byte string into a string."""
    return value.decode('utf-8')

# A mapping of PostgreSQL Type OIDs to Python parsing functions.
# You can find more OIDs in the pg_type table of PostgreSQL.
OID_MAP = {
    16: parse_bool,   # BOOL
    23: parse_int,    # INT4
    25: parse_str,    # TEXT
    1043: parse_str,  # VARCHAR
}


def get_parser(oid: int):
    """
    Returns the appropriate parsing function for a given Type OID.
    Defaults to a string parser if the OID is unknown.
    """
    return OID_MAP.get(oid, parse_str)