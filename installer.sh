#!/bin/bash
set -e

# --- CONFIGURATION ---
APP_NAME="locker"                     # Name of the global command (e.g., /usr/local/bin/locker)
VENV_NAME="cipherEnv"                 # Virtual environment folder name
MAIN_SCRIPT="src/lockerpy/locker.py"  # Relative path to the executable entry point
# ---------------------

# Determine absolute project path from where installer is run
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Creating virtual environment ($VENV_NAME)..."
virtualenv "$PROJECT_DIR/$VENV_NAME" --python=3

echo "==> Installing dependencies..."
source "$PROJECT_DIR/$VENV_NAME/bin/activate"
pip install --upgrade pip
if [ -f "$PROJECT_DIR/requirements.txt" ]; then
    pip install -r "$PROJECT_DIR/requirements.txt"
fi

echo "==> Generating global wrapper script..."
WRAPPER_PATH="/usr/local/bin/$APP_NAME"

# Write the wrapper script (requires sudo/root privileges)
sudo tee "$WRAPPER_PATH" > /dev/null <<EOF
#!/bin/bash
export ORIGINAL_PWD="\$PWD"
cd "$PROJECT_DIR"
source "$VENV_NAME/bin/activate"
exec python3 "$MAIN_SCRIPT" "\$@"
EOF

sudo chmod +x "$WRAPPER_PATH"

echo "==> Installation complete! '$APP_NAME' is now available globally."
