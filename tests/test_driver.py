import pytest
from async_driver.driver import Driver
from async_driver import exceptions


# Configuration for our test database
DB_CONFIG = {
    "user": "myuser",
    "password": "mypassword",
    "database": "mydb",
    "host": "localhost",
    "port": 5432
}

@pytest.mark.asyncio
async def test_successful_connection():
    """
    Tests if the driver can connect and close the connection without errors.
    """
    driver = Driver(DB_CONFIG)
    await driver.connect()
    # If connect() doesn't raise an exception, the test is successful.
    assert driver.writer is not None
    await driver.close()
    assert driver.writer.is_closing() is True


@pytest.mark.asyncio
async def test_simple_query_and_data_types():
    """
    Tests a simple query and verifies that data types are converted correctly.
    """
    driver = Driver(DB_CONFIG)
    await driver.connect()
    
    rows = await driver.execute("SELECT 1 AS num, 'test' AS txt, true AS bool;", [])
    
    assert len(rows) == 1
    row = rows[0]
    
    assert row['num'] == 1
    assert isinstance(row['num'], int)
    
    assert row['txt'] == 'test'
    assert isinstance(row['txt'], str)
    
    assert row['bool'] is True
    assert isinstance(row['bool'], bool)
    
    await driver.close()


@pytest.mark.asyncio
async def test_fetch_from_table():
    """
    Tests fetching data from the actual test table we created.
    """
    driver = Driver(DB_CONFIG)
    await driver.connect()
    
    rows = await driver.execute("SELECT id, name, is_active FROM test_data WHERE id = $1;", [1])
    
    assert len(rows) == 1
    alice = rows[0]
    
    assert alice['id'] == 1
    assert alice['name'] == 'Alice'
    assert alice['is_active'] is True
    
    await driver.close()
    
    
# --- THIS IS THE CRUCIAL SECURITY TEST ---
@pytest.mark.asyncio
async def test_sql_injection_prevention():
    """
    Tests that the driver is NOT vulnerable to SQL injection.
    We try to inject a malicious string to delete a user.
    """
    driver = Driver(DB_CONFIG)
    await driver.connect()
    
    # This is a classic SQL injection payload.
    # If the driver were vulnerable, this would find user 'Alice' AND delete user 'Bob'.
    malicious_input = "'Alice' OR 1=1; DELETE FROM test_data WHERE id = 2; --"
    
    # We pass the malicious input as a PARAMETER.
    # A secure driver will treat this entire string as a single piece of data,
    # not as part of the SQL command.
    rows = await driver.execute("SELECT * FROM test_data WHERE name = $1;", [malicious_input])
    
    # ASSERTION 1: The query should return ZERO rows, because there is no
    # user with the literal name "'Alice' OR 1=1;...".
    assert len(rows) == 0
    
    # ASSERTION 2 (The most important one): Check if Bob was deleted.
    # We run a separate, clean query to check if Bob still exists.
    # If the injection was successful, this query would return 0 rows.
    bob_check = await driver.execute("SELECT * FROM test_data WHERE id = 2;", [])
    
    # If Bob is still there, the injection failed, and our driver is SECURE.
    assert len(bob_check) == 1
    assert bob_check[0]['name'] == 'Bob'
    
    await driver.close()