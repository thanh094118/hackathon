#!/bin/bash

echo "Setting up project environment..."

echo "Checking Python environment..."
if command -v python3 &> /dev/null; then
    PYTHON_BIN="python3"
elif command -v python &> /dev/null; then
    PYTHON_BIN="python"
else
    echo "Python not found. Please install Python 3.11+ first."
    exit 1
fi

PYTHON_VERSION=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$($PYTHON_BIN -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$($PYTHON_BIN -c "import sys; print(sys.version_info.minor)")
if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]; }; then
    echo "Python $PYTHON_VERSION detected. This project requires Python >= 3.11."
    exit 1
fi
echo "Using $PYTHON_BIN (Python $PYTHON_VERSION)"

mkdir -p data

cd data

echo ""
echo "Downloading dataset from Google Drive..."
echo "File: input.zip"
echo ""

FILE_ID="1QeCCZT1QBgnCjt1x-l7q-kCO5zysJ4fd"
OUTPUT_FILE="input.zip"

download_with_gdown() {
    if ! command -v gdown &> /dev/null; then
        echo "gdown not found. Installing gdown..."
        $PYTHON_BIN -m pip install gdown
    fi
    
    echo "Downloading file using gdown..."
    gdown "https://drive.google.com/uc?id=${FILE_ID}" -O "${OUTPUT_FILE}" \
    || gdown "https://drive.google.com/file/d/${FILE_ID}/view?usp=sharing" -O "${OUTPUT_FILE}"
}

download_with_python_gdown() {
    $PYTHON_BIN -c "
import gdown
import os

file_id = '${FILE_ID}'
url = f'https://drive.google.com/uc?id={file_id}'
gdown.download(url, '${OUTPUT_FILE}', quiet=False, fuzzy=True, use_cookies=False)
" 2>/dev/null
}

if command -v gdown &> /dev/null; then
    download_with_gdown
elif $PYTHON_BIN -c "import gdown" 2>/dev/null; then
    download_with_python_gdown
else
    echo "Installing gdown..."
    $PYTHON_BIN -m pip install gdown -q
    download_with_gdown
fi

if [ $? -eq 0 ]; then
    echo ""
    echo "Dataset downloaded successfully to ./data/${OUTPUT_FILE}"
    if [ -f "${OUTPUT_FILE}" ]; then
        echo "Extracting ${OUTPUT_FILE}..."
        unzip -o "${OUTPUT_FILE}" -d . >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "Extracted successfully into ./data/"
        else
            echo "Warning: unzip failed. Please extract ./data/${OUTPUT_FILE} manually."
        fi
    fi
else
    echo ""
    echo "Download failed. Trying alternative method..."
    echo "Please manually download from:"
    echo "https://drive.google.com/file/d/${FILE_ID}/view?usp=sharing"
    echo "and place ${OUTPUT_FILE} in ./data/ folder"
fi

cd ..

echo ""
echo "=========================================="
echo "Installing Python dependencies..."
echo "=========================================="

if [ -f "requirements.txt" ]; then
    echo "Found requirements.txt"

    $PYTHON_BIN -m pip install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "Dependencies installed successfully"
    else
        echo ""
        echo "Failed to install dependencies"
    fi
else
    echo "requirements.txt not found in current directory"
    echo "Please create requirements.txt with necessary packages"
fi

echo ""
echo "=========================================="
echo "Setup complete!"
echo "=========================================="
echo ""
echo "Data location: ./data/"
echo ""
echo "To verify:"
echo "  ls -la ./data/"
echo ""
