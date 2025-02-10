#!/bin/bash

# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip

# Install Python dependencies
pip3 install requests colorama rich beautifulsoup4 selenium webdriver_manager aiohttp

# Clone the repository
git clone https://github.com/yourusername/xss_vibes.git
cd xss_vibes

# Make the script executable
chmod +x xss_vibes_merged.py

echo "Installation completed. You can now run the script using './spidex.py'"