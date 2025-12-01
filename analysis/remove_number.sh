#!/bin/bash

# Check if a filename was provided as an argument
if [ $# -eq 0 ]; then
    echo "Error: No filename provided."
    echo "Usage: $0 filename"
    exit 1
fi

filename=$1

# Check if the file exists
if [ ! -f "$filename" ]; then
    echo "Error: File '$filename' not found."
    exit 1
fi

# Extract the base filename and the extension
base="${filename%.*}"
extension="${filename##*.}"

# Check if the extension is numeric
if [[ $extension =~ ^[0-9]+$ ]]; then
    # Extract the original extension before the numeric part
    original_extension="${base##*.}"
    base="${base%.*}"
    
    # Rename the file
    new_filename="${base}.${extension}.${original_extension}"
    mv "$filename" "$new_filename"
    echo "Renamed '$filename' to '$new_filename'"
else
    echo "No numeric suffix found in '$filename'. No changes made."
fi
