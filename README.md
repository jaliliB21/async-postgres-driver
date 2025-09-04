# Async PG Driver

A minimalist, asynchronous PostgreSQL driver for Python, built from scratch using `asyncio` for educational purposes.



## Project Goal

This project is a deep dive into the fundamentals of database connectivity. It implements the PostgreSQL wire protocol directly to gain a practical understanding of low-level network programming and asynchronous communication, without relying on external libraries for the core logic.

---

## Project Roadmap & Features

This project is currently in the initial development phase. The goal is to build a robust, low-level driver with the following features:

### Core Functionality (In Progress)
* **Asynchronous Connection:** Establish a non-blocking connection to a PostgreSQL server.
* **Direct Protocol Communication:** Send and receive data packets according to the PostgreSQL wire protocol.
* **Raw SQL Execution:** A core function to execute raw SQL queries asynchronously and parse the results.

### Planned Features (The Vision)
* **Clean, Object-Oriented API:** A user-friendly `Driver` class to manage connections and state.
* **Secure Parameter Binding:** Support for prepared statements to prevent SQL injection.
* **Connection Pooling:** A simple connection pool to manage and reuse connections efficiently.
* **Transaction Management:** Clean handling of `BEGIN`, `COMMIT`, and `ROLLBACK` commands.

---

## Quickstart: Environment Setup

To get the project running locally, you'll need **Python 3.8+** and **Docker**.

1.  **Clone the Repository**


2.  **Start the Database**
    ```bash
    docker-compose up -d
    ```

3.  **Install Dependencies**
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

---

## Target API Design

The following example demonstrates the intended API design we are working towards. **Note: This functionality is not yet implemented.**

```python
import asyncio
from async_driver import Driver

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
    print("Connection successful!")

    # Execute a simple query
    result = await driver.execute("SELECT version();")
    print(result)

    await driver.close()

if __name__ == "__main__":
    asyncio.run(main())

```

Running Tests

Tests will be added as features are implemented. You can run the test suite using pytest.

pytest


