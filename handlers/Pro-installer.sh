#!/bin/bash

echo "🚀 Installing Vortex Panel Pro..."

# Install dependencies
sudo apt update
sudo apt install -y curl software-properties-common git

# Install Node.js
curl -sL https://deb.nodesource.com/setup_23.x | sudo bash -
sudo apt install -y nodejs

# Clone and build the panel
git clone https://github.com/spookyMC123/vortex-panel-pro-v1.git
cd vortex-panel-pro-v1 || exit

npm install
npm run build:user
npm run seed
node .

echo "✅ Installation complete!"
echo "🔗 Run with: node ."
echo "🌐 Access the panel at: http://localhost:3001"
