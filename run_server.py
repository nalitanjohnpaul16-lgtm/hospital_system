#!/usr/bin/env python3
"""
Simple server startup script for the Hospital Management System.
Run this file to start the web application.
"""

import os
import sys

def main():
    """Start the Flask web application."""
    print("=" * 60)
    print("Hospital Management System - Web Application")
    print("=" * 60)
    print()
    
    # Check if required dependencies are installed
    try:
        import flask
        import mysql.connector
        import cryptography
        print("✓ All required dependencies are installed")
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return 1
    
    # Set default environment variables if not set
    env_vars = {
        "MYSQL_HOST": "localhost",
        "MYSQL_PORT": "3306", 
        "MYSQL_USER": "root",
        "MYSQL_PASSWORD": "jjppbbnn",
        "MYSQL_DB": "hospital_system"
    }
    
    for key, default_value in env_vars.items():
        if key not in os.environ:
            os.environ[key] = default_value
            print(f"Set {key} = {default_value}")
    
    print()
    print("Starting web server...")
    print("Access the application at: http://127.0.0.1:5000")
    print("Press Ctrl+C to stop the server")
    print()
    
    # Import and run the Flask app
    try:
        from web_app import app
        app.run(host="127.0.0.1", port=5000, debug=True)
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        return 0
    except Exception as e:
        print(f"Error starting server: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())