# Async PG Driver

A minimalist, asynchronous PostgreSQL driver for Python, built from scratch using asyncio. This project demonstrates a deep, practical understanding of low-level database protocols and secure, non-blocking network programming.

## Motivation

This project was undertaken as a deep dive into the fundamentals of how database drivers work. By implementing the PostgreSQL wire protocol directly, without relying on external libraries for the core logic, it showcases the ability to work with network protocols, handle complex authentication flows, and manage data at the byte level.

Disclaimer: This driver is an educational project built for a portfolio. For production applications, please use mature and battle-tested libraries like asyncpg.

## Key Features

- **Secure Authentication:** Implements the modern SCRAM-SHA-256 challenge-response mechanism from scratch for secure password authentication.

- **SQL Injection Protection:** Uses the Extended Query Protocol (Parse/Bind/Execute) for all queries, making it secure by default against SQL injection attacks.

- **Automatic Data Type Conversion:** Intelligently parses RowDescription messages to convert PostgreSQL data types (like INT, BOOL, TEXT, VARCHAR) into their proper Python equivalents (int, bool, str). Also handles NULL values correctly.

- **Clean, Asynchronous API:** Provides a simple, object-oriented API built entirely on Python's asyncio for non-blocking I/O.

- **Zero Core Dependencies:** The driver's core logic relies only on Python's standard library.


## Usage Example

The driver provides a clean and straightforward API for connecting and executing queries securely.
```python
import asyncio
from async_driver import Driver, exceptions

# Database configuration
DB_CONFIG = {
    "user": "myuser",
    "password": "mypassword",
    "database": "mydb",
    "host": "localhost",
    "port": 5432
}

async def main():
    driver = Driver(DB_CONFIG)
    try:
        await driver.connect()
        print("Connection successful!")

        # Execute a secure, parameterized query
        query = "SELECT id, name, is_active FROM test_data WHERE id = $1;"
        params = [1]
        rows = await driver.execute(query, params)

        print("\nQuery Results:")
        print(rows)

        # Verify the data types
        if rows:
            first_row = rows[0]
            print("\nVerified Data Types:")
            for col, val in first_row.items():
                print(f"  - Column '{col}' is of type: {type(val)}")

    except exceptions.DriverError as e:
        print(f"An error occurred: {e}")
    finally:
        if driver.writer and not driver.writer.is_closing():
            await driver.close()

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Development Setup

To run this project locally for development or testing, you'll need Python +3.8 and Docker.

1. **Clone the Repository:**
```bash
git clone https://github.com/[Your-GitHub-Username]/async-postgres-driver.git
cd async-postgres-driver
```

2. **Start the Database:**
The included docker-compose.yml file will start a PostgreSQL instance.
```bash
docker-compose up -d
```

3. **Create Test Table:**
For the tests to run, you need to create a simple table in the database. 

```bash
docker exec -it postgres_for_driver psql -U myuser -d mydb -c "CREATE TABLE test_data (id INT PRIMARY KEY, name TEXT, is_active BOOLEAN); INSERT INTO test_data VALUES (1, 'Alice', TRUE), (2, 'Bob', FALSE);"
```

4. **Install Dependencies:**
Set up a virtual environment and install testing tools.
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


## Running Tests

After setting up the environment and creating the test table, you can run the full test suite.

```bash 
pytest
```

## Future Improvements

**This project provides a solid foundation. Future work could include:**

* Connection Pooling: To manage and reuse connections efficiently.

* Expanded Data Type Support: Adding parsers for more types like TIMESTAMP, JSONB, UUID, and NUMERIC.

* Full Transaction Management: A cleaner API for handling BEGIN, COMMIT, and ROLLBACK.
