#!/bin/bash

# Check if both arguments are provided
if [ $# -ne 2 ]; then
    echo "Error: Two arguments required. Usage: $0 <directory> <search_string>"
    exit 1
fi

filesdir=$1
searchstr=$2

# Check if the given path is a directory
if [ ! -d "$filesdir" ]; then
    echo "Error: Directory '$filesdir' does not exist."
    exit 1
fi

# Count the number of files in the directory and subdirectories
file_count=$(find "$filesdir" -type f | wc -l)

# Count the number of matching lines
match_count=$(grep -r "$searchstr" "$filesdir" 2>/dev/null | wc -l)

# Output the result
echo "The number of files are $file_count and the number of matching lines are $match_count"

exit 0

