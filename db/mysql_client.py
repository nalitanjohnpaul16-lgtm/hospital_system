"""
MySQL client module for hospital management system.
Provides database connection and basic operations.
"""

import mysql.connector
from mysql.connector import pooling, Error
import os
import logging

logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "jjppbbnn"),
    "database": os.getenv("MYSQL_DB", "hospital_system"),
    "autocommit": True
}

# Global connection pool
_connection_pool = None

def init_connection_pool():
    """Initialize the MySQL connection pool."""
    global _connection_pool
    try:
        _connection_pool = pooling.MySQLConnectionPool(
            pool_name="hospital_pool",
            pool_size=int(os.getenv("MYSQL_POOL_SIZE", "5")),
            **DB_CONFIG
        )
        logger.info("MySQL connection pool initialized successfully")
        return True
    except Error as e:
        logger.error(f"Failed to initialize connection pool: {e}")
        _connection_pool = None
        return False

def get_connection():
    """Get a database connection from the pool or create a new one."""
    global _connection_pool
    
    # Try to get connection from pool
    if _connection_pool is not None:
        try:
            conn = _connection_pool.get_connection()
            logger.debug("Got connection from pool")
            return conn
        except Error as e:
            logger.error(f"Error getting connection from pool: {e}")
    
    # Fall back to direct connection
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        logger.debug("Created new direct database connection")
        return conn
    except Error as e:
        logger.error(f"Error connecting to database: {e}")
        return None

def execute_query(query, params=None, fetch=False):
    """Execute a query and return results if fetch=True."""
    conn = get_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params or ())
        
        if fetch:
            result = cursor.fetchall()
        else:
            result = cursor.rowcount
            
        cursor.close()
        conn.close()
        return result
    except Error as e:
        logger.error(f"Database query error: {e}")
        if conn:
            conn.close()
        return None

def test_connection():
    """Test database connectivity."""
    try:
        conn = get_connection()
        if not conn:
            return False
        
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return result is not None
    except Error as e:
        logger.error(f"Connection test failed: {e}")
        return False

# Initialize connection pool when module is imported
init_connection_pool()