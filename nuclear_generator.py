#!/usr/bin/env python3
"""
DECOYABLE Nuclear Generator - Creates Massive Test Dataset

Generates a large codebase with embedded security vulnerabilities
for extreme stress testing of DECOYABLE's performance and detection capabilities.
"""

import os
import random
import string
from pathlib import Path
import secrets

# Nuclear test configuration (scaled for testing)
TARGET_SIZE_GB = 0.1  # Generate 100MB of test code
FILES_TO_CREATE = 50  # 50 Python files
VULNERABILITIES_PER_FILE = 3  # Average vulnerabilities per file

def generate_vulnerable_code(filename, file_index):
    """Generate a Python file with embedded vulnerabilities."""
    lines = []

    # Add file header
    lines.append('"""')
    lines.append(f'Generated test file {filename} - Nuclear stress test')
    lines.append('"""')
    lines.append('')

    # Add imports
    lines.append('import os')
    lines.append('import subprocess')
    lines.append('')

    # Generate vulnerable code
    user_input = f'user_input_{file_index}'

    # Add some vulnerabilities
    vulnerabilities = [
        f'API_KEY = "sk-{secrets.token_hex(8)}"',
        f'os.system(f"ls {user_input}")',
        f'subprocess.run(["bash", "-c", user_input])',
        f'password = "{secrets.token_hex(4)}"',
    ]

    for vuln in random.sample(vulnerabilities, VULNERABILITIES_PER_FILE):
        lines.append(f'# VULNERABILITY TEST')
        lines.append(vuln)
        lines.append('')

    # Add filler code to increase size
    for i in range(100):
        lines.append(f'x{i} = {random.randint(1, 1000)}')
        lines.append(f'y{i} = "{random.choice(string.ascii_letters) * 20}"')

    return '\n'.join(lines)

def create_nuclear_dataset():
    """Create the nuclear test dataset."""
    print("🧪 DECOYABLE Nuclear Generator")
    print("=" * 40)
    print(f"Target: {TARGET_SIZE_GB}GB codebase")
    print(f"Files: {FILES_TO_CREATE}")
    print()

    # Create nuclear test directory
    nuclear_dir = Path("nuclear_test_dataset")
    nuclear_dir.mkdir(exist_ok=True)

    print("🚀 Generating nuclear test dataset...")

    total_size = 0
    for i in range(FILES_TO_CREATE):
        # Create nested directory structure
        subdir = nuclear_dir / f"module_{i % 10}"
        subdir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        filename = f"test_file_{i:03d}.py"
        filepath = subdir / filename

        # Generate vulnerable code
        code = generate_vulnerable_code(filename, i)

        # Write file
        filepath.write_text(code, encoding='utf-8')

        # Track size
        total_size += len(code.encode('utf-8'))

        # Progress reporting
        if (i + 1) % 10 == 0:
            progress = (i + 1) / FILES_TO_CREATE * 100
            print(f"📈 Progress: {i+1}/{FILES_TO_CREATE} files ({progress:.1f}%)")

    # Final statistics
    final_size_mb = total_size / (1024**2)
    print("\n✅ Nuclear dataset generation complete!")
    print(f"📊 Final size: {final_size_mb:.2f}MB")
    print(f"📁 Files created: {FILES_TO_CREATE}")
    print(f"🎯 Expected vulnerabilities: {FILES_TO_CREATE * VULNERABILITIES_PER_FILE}")

    return nuclear_dir

if __name__ == "__main__":
    create_nuclear_dataset()