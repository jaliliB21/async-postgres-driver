import struct


def create_startup_message(user: str, database: str) -> bytes:
    """
    Builds the StartupMessage for the initial handshake.

    Args:
        user: The username for the connection.
        database: The database name to connect to.

    Returns:
        A bytes object representing the complete StartupMessage.
    """
    user_bytes = user.encode('utf-8')
    database_bytes = database.encode('utf-8')
    
    params = b'user\x00' + user_bytes + b'\x00' + b'database\x00' + database_bytes + b'\x00\x00'
    protocol_version = 196608 # Protocol version 3.0
    
    # Length includes the length field itself (4 bytes)
    length = 4 + 4 + len(params)
    
    startup_message = struct.pack('!I', length) + struct.pack('!I', protocol_version) + params
    return startup_message


def create_query_message(query_string: str) -> bytes:
    """
    Builds a Simple Query message ('Q' type).

    Args:
        query_string: The SQL query string to be executed.

    Returns:
        A bytes object representing the complete Query message.
    """
    # The query must be null-terminated
    query_bytes = query_string.encode('utf-8') + b'\x00'
    
    # Message format: 'Q' + MessageLength + Null-terminated QueryString
    return b'Q' + struct.pack('!I', 4 + len(query_bytes)) + query_bytes