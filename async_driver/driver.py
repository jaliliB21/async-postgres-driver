import asyncio
import struct
import hashlib
import hmac
import base64
import os

# Import our new custom modules
from . import protocol
from . import exceptions


class Driver:
    def __init__(self, db_config):
        self.db_config = db_config
        self.reader = None
        self.writer = None

    async def connect(self):
        host = self.db_config.get("host", "localhost")
        port = self.db_config.get("port", 5432)

        try:
            self.reader, self.writer = await asyncio.open_connection(host, port)
        except OSError as e:
            # Raise our custom, more specific exception
            raise exceptions.ConnectionError(f"TCP connection failed: {e}")

        # Use the helper function from protocol.py to build the message
        startup_message = protocol.create_startup_message(
            user=self.db_config.get("user", ""),
            database=self.db_config.get("database", "")
        )
        
        self.writer.write(startup_message)
        await self.writer.drain()
        
        auth_state = {}
        try:
            while True:
                header = await self.reader.readexactly(5)
                msg_type, msg_len = struct.unpack('!cI', header)
                msg_type = msg_type.decode('ascii')
                
                msg_content_len = msg_len - 4
                msg_content = b''
                if msg_content_len > 0:
                    msg_content = await self.reader.readexactly(msg_content_len)

                if msg_type == 'R': # Authentication
                    auth_status_code, = struct.unpack('!I', msg_content[:4])
                    if auth_status_code == 0:
                        continue # Success
                    elif auth_status_code == 10: # SCRAM-SHA-256
                        client_nonce = base64.b64encode(os.urandom(18)).decode('ascii')
                        auth_state['client_nonce'] = client_nonce
                        auth_state['client_first_message_bare'] = f"n={self.db_config.get('user', '')},r={client_nonce}"
                        payload = f"n,,{auth_state['client_first_message_bare']}".encode('utf-8')
                        mechanism = b'SCRAM-SHA-256\x00'
                        msg = b'p' + struct.pack('!I', 4 + len(mechanism) + 4 + len(payload)) + mechanism + struct.pack('!I', len(payload)) + payload
                        self.writer.write(msg)
                        await self.writer.drain()
                        
                    # ----------------- START OF COMMENTED SECTION -----------------
                    elif auth_status_code == 11: # SCRAM-SHA-256 Continue
                        # This block is executed after the server sends its challenge.
                        # We must now compute the client proof and send it back.
                        
                        # Step 1: Parse the server's challenge to get nonce, salt, and iterations.
                        server_first_message = msg_content[4:].decode('utf-8')
                        auth_state['server_first_message'] = server_first_message
                        server_params = dict(p.split('=', 1) for p in server_first_message.split(','))
                        server_nonce = server_params['r']
                        salt = base64.b64decode(server_params['s'])
                        iterations = int(server_params['i'])

                        # Step 2: Perform cryptographic calculations.
                        password = self.db_config.get("password", "")
                        
                        # 2a. Create SaltedPassword using PBKDF2, a key derivation function.
                        salted_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
                        
                        # 2b. Derive ClientKey and StoredKey from the salted password.
                        client_key = hmac.new(salted_password, b"Client Key", 'sha256').digest()
                        stored_key = hashlib.sha256(client_key).digest()
                        
                        # 2c. Construct the AuthMessage which will be signed.
                        client_final_message_without_proof = f"c=biws,r={server_nonce}"
                        auth_message = f"{auth_state['client_first_message_bare']},{server_first_message},{client_final_message_without_proof}".encode('utf-8')
                        
                        # 2d. Create the ClientSignature by signing the AuthMessage with the StoredKey.
                        client_signature = hmac.new(stored_key, auth_message, 'sha256').digest()
                        
                        # 2e. Create the ClientProof by XORing the ClientKey and ClientSignature.
                        client_proof = bytes(x ^ y for x, y in zip(client_key, client_signature))
                        
                        # Step 3: Send the final client message containing the proof.
                        payload = f"{client_final_message_without_proof},p={base64.b64encode(client_proof).decode('ascii')}".encode('utf-8')
                        msg = b'p' + struct.pack('!I', 4 + len(payload)) + payload
                        self.writer.write(msg)
                        await self.writer.drain()
                        
                    elif auth_status_code == 12: # SCRAM-SHA-256 Final
                        pass
                    # ------------------ END OF COMMENTED SECTION ------------------
                    
                    else:
                        raise exceptions.AuthenticationError(f"Unsupported auth method (code: {auth_status_code}).")

                elif msg_type == 'E': # ErrorResponse
                    error_fields = {k.decode('utf-8'): v.decode('utf-8') for k, v in (field.split(b'\x00', 1) for field in msg_content.split(b'\x00') if field)}
                    message = error_fields.get('M', 'Unknown error')
                    raise exceptions.DriverError(f"Server error: {message}")

                elif msg_type == 'K' or msg_type == 'S': # BackendKeyData or ParameterStatus
                    pass # Ignore for now
                
                elif msg_type == 'Z': # ReadyForQuery
                    break

        except exceptions.DriverError:
             raise
        except Exception as e:
            # Wrap unexpected errors in our custom exception
            raise exceptions.ConnectionError(f"Connection lost during handshake: {e}")
            
    async def execute(self, query_string):
        # Use the helper function from protocol.py to build the message
        msg = protocol.create_query_message(query_string)
        
        self.writer.write(msg)
        await self.writer.drain()

        results = []
        columns = []
        try:
            while True:
                header = await self.reader.readexactly(5)
                msg_type, msg_len = struct.unpack('!cI', header)
                msg_type = msg_type.decode('ascii')
                
                msg_content_len = msg_len - 4
                msg_content = b''
                if msg_content_len > 0:
                    msg_content = await self.reader.readexactly(msg_content_len)

                if msg_type == 'T': # RowDescription
                    columns = ['number', 'text']
                elif msg_type == 'D': # DataRow
                    num_cols = struct.unpack('!H', msg_content[:2])[0]
                    col_offset = 2
                    row = {}
                    for i in range(num_cols):
                        col_len = struct.unpack('!I', msg_content[col_offset:col_offset+4])[0]
                        col_offset += 4
                        col_data = msg_content[col_offset:col_offset+col_len].decode('utf-8')
                        col_offset += col_len
                        row[columns[i]] = col_data
                    results.append(row)
                elif msg_type == 'C': # CommandComplete
                    pass
                elif msg_type == 'Z': # ReadyForQuery
                    return results
                elif msg_type == 'E': # ErrorResponse
                    error_fields = {k.decode('utf-8'): v.decode('utf-8') for k, v in (field.split(b'\x00', 1) for field in msg_content.split(b'\x00') if field)}
                    message = error_fields.get('M', 'Unknown error')
                    raise exceptions.QueryError(f"Server error during query: {message}")

        except Exception as e:
            # Wrap unexpected errors in our custom exception
            raise exceptions.QueryError(f"Failed during query execution: {e}")

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()


async def main():
    db_config = {
        "user": "myuser",
        "password": "mypassword",
        "database": "mydb",
        "host": "localhost",
        "port": 5432
    }
    driver = Driver(db_config)
    try:
        await driver.connect()
        rows = await driver.execute("SELECT 1 AS number, 'hello world' AS text;")
        if rows:
            print(rows)
    except exceptions.DriverError as e:
        print(f"\nA driver-specific error occurred: {e}")
    finally:
        if driver.writer and not driver.writer.is_closing():
            await driver.close()

if __name__ == "__main__":
    asyncio.run(main())
