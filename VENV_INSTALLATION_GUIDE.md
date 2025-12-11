# Virtual Environment Installation Guide

This guide provides comprehensive instructions for setting up the Python virtual environment for the Enterprise Security System.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Method 1: Using Pre-built Virtual Environment](#method-1-using-pre-built-virtual-environment)
- [Method 2: Creating Fresh Virtual Environment](#method-2-creating-fresh-virtual-environment)
- [Method 3: Manual Installation](#method-3-manual-installation)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Package Details](#package-details)

## Prerequisites

Before starting, ensure you have:
- **Python 3.8 or higher** installed on your system
- **pip** package manager (usually comes with Python)
- **Administrative privileges** (for some installations)

### Check Python Installation
```bash
python --version
# or
python3 --version
```

### Check pip Installation
```bash
pip --version
# or
pip3 --version
```

## Method 1: Using Pre-built Virtual Environment

If you downloaded the split virtual environment files, follow these steps:

### Step 1: Download Required Files
Ensure you have downloaded:
- `venv_part1.zip` (20.00 MB)
- `venv_part2.zip` (17.96 MB)
- `reassemble_venv.bat` (Windows) or create equivalent script for other OS
- `Enterprise_Security_final.zip` (main project)

### Step 2: Extract Main Project
```bash
# Extract the main project
unzip Enterprise_Security_final.zip
```

### Step 3: Reassemble Virtual Environment

#### Windows:
```cmd
# Run the batch script
reassemble_venv.bat
```

#### Linux/macOS:
```bash
# Combine the split files
cat venv_part1.zip venv_part2.zip > Enterprise_Security_venv_complete.zip

# Extract to the project directory
unzip Enterprise_Security_venv_complete.zip -d Enterprise_Security/

# Clean up
rm Enterprise_Security_venv_complete.zip venv_part1.zip venv_part2.zip
```

### Step 4: Activate Virtual Environment

#### Windows:
```cmd
cd Enterprise_Security
venv\Scripts\activate.bat
```

#### Linux/macOS:
```bash
cd Enterprise_Security
source venv/bin/activate
```

## Method 2: Creating Fresh Virtual Environment

This is the recommended method for most users.

### Step 1: Extract Main Project
```bash
unzip Enterprise_Security_final.zip
cd Enterprise_Security
```

### Step 2: Create Virtual Environment

#### Windows:
```cmd
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate.bat

# Install requirements
pip install -r requirements.txt
```

#### Linux/macOS:
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### Step 3: Use Automated Script (Windows Only)
Alternatively, you can use the included setup script:
```cmd
setup_venv.bat
```

## Method 3: Manual Installation

If you prefer to install packages manually:

### Step 1: Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate.bat

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Packages Individually
```bash
pip install flask>=3.0.0
pip install mysql-connector-python>=8.0.0
pip install cryptography>=42.0.0
pip install pillow>=10.0.0
```

### Step 3: Verify Installation
```bash
pip list
```

## Verification

After setting up the virtual environment, verify the installation:

### Step 1: Check Installed Packages
```bash
pip list
```

Expected output should include:
```
Package                   Version
------------------------- -------
blinker                   1.9.0
cffi                      2.0.0
click                     8.3.1
cryptography              46.0.3
flask                     3.1.2
mysql-connector-python    9.5.0
pillow                    12.0.0
# ... and other dependencies
```

### Step 2: Test Application Import
```bash
python -c "from web_app import app; print('✅ Application imports successfully!')"
```

### Step 3: Run Application
```bash
python web_app.py
```

The application should start and display:
```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

## Troubleshooting

### Common Issues and Solutions

#### Issue: "python: command not found"
**Solution:** 
- On Windows: Use `py` instead of `python`
- On Linux/macOS: Use `python3` instead of `python`
- Ensure Python is added to your system PATH

#### Issue: "pip: command not found"
**Solution:**
```bash
# Windows
py -m pip install --upgrade pip

# Linux/macOS
python3 -m pip install --upgrade pip
```

#### Issue: Permission denied errors
**Solution:**
- Run terminal/command prompt as administrator (Windows)
- Use `sudo` for system-wide installations (Linux/macOS)
- Or use `--user` flag: `pip install --user package_name`

#### Issue: SSL certificate errors
**Solution:**
```bash
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
```

#### Issue: Virtual environment not activating
**Solution:**
- Ensure you're in the correct directory
- Check file permissions
- Try recreating the virtual environment:
  ```bash
  rm -rf venv  # Linux/macOS
  rmdir /s venv  # Windows
  python -m venv venv
  ```

#### Issue: MySQL connector issues
**Solution:**
```bash
# Alternative MySQL connector
pip uninstall mysql-connector-python
pip install mysql-connector-python-rf
```

#### Issue: Pillow installation fails
**Solution:**
```bash
# Install system dependencies first (Linux)
sudo apt-get install python3-dev python3-setuptools
sudo apt-get install libtiff5-dev libjpeg8-dev libopenjp2-7-dev zlib1g-dev libfreetype6-dev liblcms2-dev libwebp-dev tcl8.6-dev tk8.6-dev python3-tk libharfbuzz-dev libfribidi-dev libxcb1-dev

# Then install Pillow
pip install pillow
```

### Environment Variables

If you encounter database connection issues, set these environment variables:

#### Windows:
```cmd
set MYSQL_HOST=localhost
set MYSQL_PORT=3306
set MYSQL_USER=root
set MYSQL_PASSWORD=your_password
set MYSQL_DB=hospital_system
```

#### Linux/macOS:
```bash
export MYSQL_HOST=localhost
export MYSQL_PORT=3306
export MYSQL_USER=root
export MYSQL_PASSWORD=your_password
export MYSQL_DB=hospital_system
```

## Package Details

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Flask | ≥3.0.0 | Web framework |
| mysql-connector-python | ≥8.0.0 | MySQL database connectivity |
| cryptography | ≥42.0.0 | Encryption and security |
| Pillow | ≥10.0.0 | Image processing |

### Automatic Dependencies
These packages are installed automatically:
- **blinker** - Signal support for Flask
- **click** - Command line interface creation
- **itsdangerous** - Secure data serialization
- **Jinja2** - Template engine
- **MarkupSafe** - String handling for templates
- **Werkzeug** - WSGI utility library
- **cffi** - Foreign function interface
- **pycparser** - C parser for cffi

## Deactivating Virtual Environment

When you're done working:
```bash
deactivate
```

## Updating Packages

To update all packages to their latest versions:
```bash
pip install --upgrade -r requirements.txt
```

## Creating Requirements File

If you need to recreate the requirements file:
```bash
pip freeze > requirements.txt
```

---

## Quick Start Commands

### Windows Quick Setup:
```cmd
unzip Enterprise_Security_final.zip
cd Enterprise_Security
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
python web_app.py
```

### Linux/macOS Quick Setup:
```bash
unzip Enterprise_Security_final.zip
cd Enterprise_Security
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python web_app.py
```

---

**Need Help?** 
- Check the troubleshooting section above
- Ensure all prerequisites are met
- Verify your Python and pip versions
- Try creating a fresh virtual environment if issues persist