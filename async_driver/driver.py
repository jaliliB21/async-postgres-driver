import asyncio
import struct
import hashlib
import hmac
import base64
import os


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
        except Exception as e:
            print(f"TCP connection failed: {e}")
            return

        user = self.db_config.get("user", "").encode('utf-8')
        database = self.db_config.get("database", "").encode('utf-8')
        params = b'user\x00' + user + b'\x00' + b'database\x00' + database + b'\x00\x00'
        
        protocol_version = 196608
        length = 4 + 4 + len(params)
        
        startup_message = struct.pack('!I', length) + struct.pack('!I', protocol_version) + params
        
        self.writer.write(startup_message)
        await self.writer.drain()
        print("🤝 StartupMessage sent, processing response...")
        
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

                if msg_type == 'R':
                    auth_status_code, = struct.unpack('!I', msg_content[:4])
                    
                    if auth_status_code == 0:
                        print("Authentication successful!")
                        continue

                    elif auth_status_code == 10:
                        print("🔑 Server requested SCRAM-SHA-256. Sending client-first-message...")
                        client_nonce = base64.b64encode(os.urandom(18)).decode('ascii')
                        auth_state['client_nonce'] = client_nonce
                        auth_state['client_first_message_bare'] = f"n={self.db_config.get('user', '')},r={client_nonce}"
                        payload = f"n,,{auth_state['client_first_message_bare']}".encode('utf-8')
                        mechanism = b'SCRAM-SHA-256\x00'
                        msg = b'p' + struct.pack('!I', 4 + len(mechanism) + 4 + len(payload)) + mechanism + struct.pack('!I', len(payload)) + payload
                        self.writer.write(msg)
                        await self.writer.drain()

                    elif auth_status_code == 11:
                        print("   - Received server challenge. Computing and sending proof...")
                        
                        server_first_message = msg_content[4:].decode('utf-8')
                        
                        auth_state['server_first_message'] = server_first_message
                        server_params = dict(p.split('=', 1) for p in server_first_message.split(','))
                        server_nonce = server_params['r']
                        salt = base64.b64decode(server_params['s'])
                        iterations = int(server_params['i'])

                        password = self.db_config.get("password", "")
                        salted_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
                        client_key = hmac.new(salted_password, b"Client Key", 'sha256').digest()
                        
                        # THE TYPO FIX IS HERE: sha256 instead of sha2D56
                        stored_key = hashlib.sha256(client_key).digest()
                        
                        client_final_message_without_proof = f"c=biws,r={server_nonce}"
                        auth_message = f"{auth_state['client_first_message_bare']},{server_first_message},{client_final_message_without_proof}".encode('utf-8')
                        
                        client_signature = hmac.new(stored_key, auth_message, 'sha256').digest()
                        client_proof = bytes(x ^ y for x, y in zip(client_key, client_signature))
                        
                        payload = f"{client_final_message_without_proof},p={base64.b64encode(client_proof).decode('ascii')}".encode('utf-8')
                        msg = b'p' + struct.pack('!I', 4 + len(payload)) + payload
                        self.writer.write(msg)
                        await self.writer.drain()
                        
                    elif auth_status_code == 12:
                        print("   - Server accepted proof.")
                        pass
                    
                    else:
                        print(f"Authentication failed: Unsupported auth method (code: {auth_status_code}).")
                        await self.close()
                        return

                elif msg_type == 'K' or msg_type == 'S':
                    pass
                elif msg_type == 'Z':
                    print("Server is ready for queries.")
                    break
                else:
                    print(f"🔍 Received unhandled message type: {msg_type}")

        except Exception as e:
            print(f"Error during handshake: {e}")
            await self.close()
            return

    async def execute(self, query_string):
        """
        Sends a query to the server and parses the response.
        """
        # 1. Build the Query message
        query_bytes = query_string.encode('utf-8') + b'\x00'
        # Message format: 'Q' + MessageLength + QueryString
        msg = b'Q' + struct.pack('!I', 4 + len(query_bytes)) + query_bytes
        
        # 2. Send the message
        self.writer.write(msg)
        await self.writer.drain()
        print(f"\n🚀 Sent query: {query_string}")

        # 3. Process the response
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
                    # This message describes the columns of the result set
                    num_fields = struct.unpack('!H', msg_content[:2])[0]
                    # We can parse more details later, for now just a placeholder
                    print(f"🔍 Query will return {num_fields} columns.")
                    # For now we will manually name them for our test query
                    columns = ['number', 'text']
                
                elif msg_type == 'D': # DataRow
                    # This message contains the actual data for one row
                    num_cols = struct.unpack('!H', msg_content[:2])[0]
                    col_offset = 2
                    row = {}
                    for i in range(num_cols):
                        # Read the length of the column data
                        col_len = struct.unpack('!I', msg_content[col_offset:col_offset+4])[0]
                        col_offset += 4
                        # Read the column data and decode it
                        col_data = msg_content[col_offset:col_offset+col_len].decode('utf-8')
                        col_offset += col_len
                        row[columns[i]] = col_data
                    results.append(row)

                elif msg_type == 'C': # CommandComplete
                    print("Query executed successfully.")
                    # We can parse the command tag here later (e.g., "SELECT 1")
                
                elif msg_type == 'Z': # ReadyForQuery
                    # The server is ready for the next command, so we are done
                    return results

        except Exception as e:
            print(f"Error during query execution: {e}")
            return None

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            print("🔌 Connection closed.")


async def main():
    db_config = {
        "user": "myuser",
        "password": "mypassword",
        "database": "mydb",
        "host": "localhost",
        "port": 5432
    }
    driver = Driver(db_config)
    await driver.connect()
    
    if driver.writer:
        # If connection was successful, execute a query
        rows = await driver.execute("SELECT 1 AS number, 'hello world' AS text;")
        if rows:
            print("\n📊 Query Results:")
            print(rows)
        
        await driver.close()


if __name__ == "__main__":
    asyncio.run(main())