#!/bin/bash

# Update the package list
sudo apt-get update

# Install Python 3 and pip3 if not already installed
sudo apt-get install -y python3 python3-pip

# Install Python dependencies from requirements.txt
pip3 install -r requirements.txt

# Make the script executable
chmod +x spidix.py

echo "Installation completed. You can now run the script using 'python3 spidix.py'"
