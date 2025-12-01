#!/bin/bash

# PP-TIO Web Dashboard Startup Script

echo "🚀 Starting PP-TIO Web Dashboard..."
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run 'python3 -m venv venv' first."
    exit 1
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Check if dependencies are installed
if ! python -c "import flask" 2>/dev/null; then
    echo "📥 Installing dependencies..."
    pip install -r requirements.txt
fi

# Start the web server
echo ""
echo "✅ Starting Flask server..."
echo "🌐 Dashboard will be available at: http://localhost:5001"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

cd "$(dirname "$0")"
python src/web/app.py
