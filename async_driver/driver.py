import asyncio
import struct
import hashlib
import hmac
import base64
import os

# Import our custom modules
from . import protocol
from . import exceptions
from . import types


class Driver:
    def __init__(self, db_config):
        """
        Initializes the driver with database configuration.
        """
        self.db_config = db_config
        self.reader = None
        self.writer = None

    async def connect(self):
        """
        Establishes a connection and handles the server handshake and authentication process.
        """
        host = self.db_config.get("host", "localhost")
        port = self.db_config.get("port", 5432)

        try:
            self.reader, self.writer = await asyncio.open_connection(host, port)
        except OSError as e:
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
                    
                    else:
                        raise exceptions.AuthenticationError(f"Unsupported auth method (code: {auth_status_code}).")

                elif msg_type == 'E': # ErrorResponse
                    # The corrected, safe way to parse error messages.
                    fields = {}
                    offset = 0
                    while offset < len(msg_content) and msg_content[offset] != 0:
                        field_type = chr(msg_content[offset])
                        offset += 1
                        null_idx = msg_content.find(b'\x00', offset)
                        field_value = msg_content[offset:null_idx].decode('utf-8')
                        offset = null_idx + 1
                        fields[field_type] = field_value
                    message = fields.get('M', 'Unknown server error')
                    raise exceptions.DriverError(f"Server error: {message}")

                elif msg_type == 'K' or msg_type == 'S': # BackendKeyData or ParameterStatus
                    pass # Ignore for now
                
                elif msg_type == 'Z': # ReadyForQuery
                    break

        except exceptions.DriverError:
             raise
        except Exception as e:
            raise exceptions.ConnectionError(f"Connection lost during handshake: {e}")

    async def execute(self, query_string: str, params: list = []):
        """
        Executes a parameterized query using the Extended Query Protocol.
        This is the single, secure way to run all queries.
        For queries without parameters, pass an empty list for params.
        """
        # --- Extended Query Protocol Steps ---
        
        # 1. PARSE: Send the query template to the server for validation.
        query_bytes = query_string.encode('utf-8') + b'\x00'
        parse_msg = b'P' + struct.pack('!I', 4 + 1 + len(query_bytes) + 2) + b'\x00' + query_bytes + struct.pack('!H', 0)
        
        # 2. BIND: Send the actual parameters to bind to the parsed statement.
        param_bytes = b''
        for p in params:
            p_bytes = str(p).encode('utf-8')
            param_bytes += struct.pack('!I', len(p_bytes)) + p_bytes
        
        bind_msg = b'B' + struct.pack('!I', 4 + 1 + 1 + 2 + 2 + len(param_bytes) + 2) + \
           b'\x00\x00' + \
           struct.pack('!H', 0) + \
           struct.pack('!H', len(params)) + param_bytes + \
           struct.pack('!H', 0)
                   
        # 3. DESCRIBE: Ask the server to describe the results of the query.
        describe_msg = b'D' + struct.pack('!I', 4 + 1 + 1) + b'P\x00'

        # 4. EXECUTE: Tell the server to run the bound statement.
        execute_msg = b'E' + struct.pack('!I', 4 + 1 + 4) + b'\x00' + struct.pack('!I', 0)
        
        # 5. SYNC: Tell the server we are done and expect it to finish and respond.
        sync_msg = b'S' + struct.pack('!I', 4)

        # --- Send all messages in a single batch for efficiency ---
        self.writer.write(parse_msg + bind_msg + describe_msg + execute_msg + sync_msg)
        await self.writer.drain()
        
        # --- Response Handling Loop ---
        results = []
        column_info = []
        done = False
        while not done:
            header = await self.reader.readexactly(5)
            msg_type, msg_len = struct.unpack('!cI', header)
            msg_type = msg_type.decode('ascii')
            
            msg_content_len = msg_len - 4
            msg_content = b''
            if msg_content_len > 0:
                msg_content = await self.reader.readexactly(msg_content_len)

            if msg_type == '1' or msg_type == '2': # ParseComplete or BindComplete
                pass
            elif msg_type == 't': # ParameterDescription
                pass
            elif msg_type == 'n': # NoData
                 pass
            elif msg_type == 'T': # RowDescription
                column_info.clear()
                num_fields = struct.unpack('!H', msg_content[:2])[0]
                offset = 2
                for _ in range(num_fields):
                    null_idx = msg_content.find(b'\x00', offset)
                    col_name = msg_content[offset:null_idx].decode('utf-8')
                    offset = null_idx + 1
                    _table_oid, _col_attr_num, type_oid, _type_size, _type_mod, _format_code = struct.unpack('!IHihih', msg_content[offset:offset+18])
                    offset += 18
                    column_info.append({'name': col_name, 'type_oid': type_oid})
            elif msg_type == 'D': # DataRow
                num_cols = struct.unpack('!H', msg_content[:2])[0]
                offset = 2
                row = {}
                for i in range(num_cols):
                    col_len, = struct.unpack('!i', msg_content[offset:offset+4])
                    offset += 4
                    if col_len == -1: # Handle NULL values
                        parsed_value = None
                    else:
                        col_data_bytes = msg_content[offset:offset+col_len]
                        col_meta = column_info[i]
                        parser = types.get_parser(col_meta['type_oid'])
                        parsed_value = parser(col_data_bytes)
                        offset += col_len
                    row[column_info[i]['name']] = parsed_value
                results.append(row)
            elif msg_type == 'C': # CommandComplete
                pass
            elif msg_type == 'Z': # ReadyForQuery
                done = True
            elif msg_type == 'E': # ErrorResponse
                fields = {}
                offset = 0
                while offset < len(msg_content) and msg_content[offset] != 0:
                    field_type = chr(msg_content[offset])
                    offset += 1
                    null_idx = msg_content.find(b'\x00', offset)
                    field_value = msg_content[offset:null_idx].decode('utf-8')
                    offset = null_idx + 1
                    fields[field_type] = field_value
                message = fields.get('M', 'Unknown server error')
                raise exceptions.QueryError(f"Server error: {message}")
        
        return results

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
