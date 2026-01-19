#!/bin/bash

set -e

# 1. Ensure structure exists
mkdir -p dns_auditor
mkdir -p app
mkdir -p tests

# 2. Find and update imports in your main scripts
echo "Fixing imports in CLI and app..."
for f in cli.py app/app.py tests/*.py; do
    if [ -f "$f" ]; then
        sed -i 's/from dns_tools /from dns_auditor.dns_tools /g' "$f"
        sed -i 's/import dns_tools/import dns_auditor.dns_tools/g' "$f"
    fi
done

# 3. (Optional) Create venv and install requirements
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
fi

# 4. Final reminders for manual steps
echo ""
echo "==== Project setup complete! ===="
echo "Project structure:"
echo "  dns_auditor/   # Main code"
echo "  app/app.py     # Streamlit web app"
echo "  cli.py         # CLI entry point"
echo "  tests/         # Tests"
echo ""
echo "If you have any code in the wrong place, move it now."
echo ""
echo "To run the Streamlit app:   streamlit run app/app.py"
echo "To run the CLI:             python cli.py example.com"
echo "To run the tests:           pytest"
echo ""
echo "If you see 'ModuleNotFoundError', check your imports match:"
echo "  from dns_auditor.dns_tools import ..."

deactivate
echo "Setup script complete!"

