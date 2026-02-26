# Hitag2

A Python-based implementation of the paper Lock It and Still Lose It - On the (In)Security of Automotive Remote Keyless Entry Systems by Flavio D. Garcia et al.

## Repository Structure
```text
.
├── project1_report_v4.pdf # final project report
├── hitag.py             # Implementation of the Hitag2 cipher
├── attack.py            # Attack script on Hitag2
├── decoder/             # Decoding of two example key fob traces
│   ├── decode.py        # Decoding script
│   ├── console.txt      # Result of decoding
│   ├── trace_01.sub     # Trace 1
│   └── trace_02.sub     # Trace 2
├── console/             # Terminal output of the performed attacks
│   ├── console_out0.txt # Output experiment 0
│   ├── ...             
│   └── console_out6.txt # Output experiment 6
├── out0/                # Candidate output files of experiment 0
├── hitag_print.py       # Implementation of the Hitag2 cipher with 
│                        #   print statements to understand the 
│                        #   internal processes of the LFSR
└── example.txt          # Output of hitag_print.py
```

## Requirements

* PyPy https://pypy.org/download.html (tested with pyp y3.11-v7.3.20-win64)

## Usage

The attack.py script should be run using pypy to achieve a acceptable runtime. The configuration of both scripts is purely done inside the script itelf. 

The decode.py script can be run with a normal Python 3.x version.

```bash
#### Attack
pypy3.11-v7.3.20-win64\python.exe attack.py

#### Decode
python decode.py