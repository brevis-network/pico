import os
import re
import pandas as pd
from pathlib import Path
import subprocess

def get_current_branch():
    result = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            check=True)
    return result.stdout.strip()

# Example usage
branch_name = get_current_branch()

# Pattern for folder names like T2_R3
folder_pattern = re.compile(r"T(\d+)_R(\d+)")
# Pattern for file names like result-1-12345-branch.txt
file_pattern = re.compile(r"result-(\d+)-(\d+)-{re.escape(branch_name)}\.txt")

data = []

base_path = Path('./logs/')

for folder in base_path.iterdir():
    if not folder.is_dir():
        continue

    match = folder_pattern.match(folder.name)
    if not match:
        continue

    emulator_threads = int(match.group(1))
    riscv_threads = int(match.group(2))
    
    for file in folder.iterdir():
        if not file.name.startswith("result-") or not file.name.endswith(".txt"):
            continue

        file_match = file_pattern.match(file.name)
        if not file_match:
            continue

        prover_id = int(file_match.group(1))
        block_id = int(file_match.group(2))

        try:
            with file.open() as f:
                while True:
                    first_line = f.readline().strip()
                    if first_line.startswith("E2E_total = "):
                        e2e_str = first_line.split('=')[1].strip().rstrip('s')
                        e2e = float(e2e_str)
                        data.append({
                            'block_id': block_id,
                            'emulator_threads': emulator_threads,
                            'riscv_preparer_threads': riscv_threads,
                            'e2e': e2e
                        })
                        break
        except Exception as e:
            print(f"Error reading {file}: {e}")

# Convert to DataFrame and sort by all columns with left-to-right priority
df = pd.DataFrame(data)
if df.empty:
    print("No matching results found. Exiting.")
    exit(0)
    
df.sort_values(by=['block_id', 'e2e', 'emulator_threads', 'riscv_preparer_threads'], inplace=True)

# Output the result
print(df.to_string(index=False))

# Optional: save to CSV
# df.to_csv('summary.csv', index=False)
