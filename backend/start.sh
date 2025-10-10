#!/bin/bash
# Secure Authentication Backend - Startup Script

echo "🔒 Starting Secure Authentication Backend..."
echo "=============================================="

# Change to backend directory
cd "$(dirname "$0")"

# Activate virtual environment
PYTHON="/home/vishal/Desktop/prot/.venv/bin/python"

# Check if Python is available
if [ ! -f "$PYTHON" ]; then
    echo "❌ Error: Python virtual environment not found"
    echo "Please run: python3 -m venv /home/vishal/Desktop/prot/.venv"
    exit 1
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  Warning: .env file not found, copying from .env.example"
    cp .env.example .env
fi

# Check if dependencies are installed
echo "📦 Checking dependencies..."
$PYTHON -c "import flask" 2>/dev/null || {
    echo "❌ Dependencies not installed. Installing..."
    $PYTHON -m pip install -r requirements.txt
}

# Set PYTHONPATH
export PYTHONPATH="/home/vishal/Desktop/prot/Automated-Attendance/backend:$PYTHONPATH"

# Start the server
echo ""
echo "✅ Starting Flask server on port 5001..."
echo "📍 Health Check: http://localhost:5001/api/health"
echo "📍 API Docs: See README.md for endpoint documentation"
echo ""
echo "Press CTRL+C to stop the server"
echo "=============================================="
echo ""

$PYTHON app.py
