#!/usr/bin/env python3
import sys

# Software optimized 48-bit Philips/NXP Mifare Hitag2 PCF7936/46/47/52 stream cipher algorithm
# Ported to Python based on the C implementation by I.C. Wiener (2006-2007).
# For educational purposes only.

# --- Constants ---

HT2_F4A = 0x2C79         # 0010 1100 0111 1001
HT2_F4B = 0x6671         # 0110 0110 0111 0001
HT2_F5C = 0x7907287B     # 0111 1001 0000 0111 0010 1000 0111 1011

# --- Helper Functions (Macros translation) ---

def rev8(x):
    """Reverses the bits within a single byte."""
    x &= 0xFF
    # Pythonic bit reversal for 8 bits
    return int('{:08b}'.format(x)[::-1], 2)

def rev16(x):
    """Reverses bits within each byte, preserving byte order (Little Endian logic from macros)."""
    return rev8(x) + (rev8(x >> 8) << 8)

def rev32(x):
    """Reverses bits within each byte, preserving byte order."""
    return rev16(x) + (rev16(x >> 16) << 16)

def rev64(x):
    """Reverses bits within each byte, preserving byte order."""
    return rev32(x) + (rev32(x >> 32) << 32)

def i4(x, a, b, c, d):
    """Extracts specific bits to form a 4-bit index."""
    return ((((x >> a) & 1) * 1) +
            (((x >> b) & 1) * 2) +
            (((x >> c) & 1) * 4) +
            (((x >> d) & 1) * 8))

# --- Core Hitag2 Functions ---

def f20(x):
    """Non-linear filter function."""
    i5 = (
        ((HT2_F4A >> i4(x, 1, 2, 4, 5)) & 1) * 1 +
        ((HT2_F4B >> i4(x, 7, 11, 13, 14)) & 1) * 2 +
        ((HT2_F4B >> i4(x, 16, 20, 22, 25)) & 1) * 4 +
        ((HT2_F4B >> i4(x, 27, 28, 30, 32)) & 1) * 8 +
        ((HT2_F4A >> i4(x, 33, 42, 43, 45)) & 1) * 16
    )
    return (HT2_F5C >> i5) & 1

def hitag2_init(key, serial, IV):
    """Initializes the cipher state."""
    # State x is effectively 48 bits, but we use Python's arbitrary precision ints.
    # We must mask outputs to behave like C logic where necessary.
    
    # x = ((key & 0xFFFF) << 32) + serial
    x = ((key & 0xFFFF) << 32) + serial
    x &= 0xFFFFFFFFFFFF # Keep x within 48-bit bounds for cleanliness, though logic handles it.

    for i in range(32):
        x >>= 1
        # Calculate feedback
        # (key >> (i + 16)) shifts the key to access bits 16..47 sequentially
        val = f20(x) ^ (((IV >> i) ^ (key >> (i + 16))) & 1)
        x += (val << 47)
        x &= 0xFFFFFFFFFFFF # Ensure we stay within 48 bits simulation

    return x

def hitag2_round(state):
    """Performs one round of LFSR update and returns the filter output."""
    x = state
    
    # LFSR Feedback polynomial taps
    feedback = (
        (x >> 0) ^ (x >> 2) ^ (x >> 3) ^ (x >> 6) ^
        (x >> 7) ^ (x >> 8) ^ (x >> 16) ^ (x >> 22) ^
        (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41) ^
        (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)
    ) & 1

    x = (x >> 1) + (feedback << 47)
    x &= 0xFFFFFFFFFFFF # Mask to 48 bits
    
    return x, f20(x) # Return new state and output bit

def hitag2_byte(state):
    """Generates a full byte of keystream."""
    c = 0
    for i in range(8):
        # We need to update state and get the bit
        state, bit_out = hitag2_round(state)
        # The C code does: c += (u32)hitag2_round(x) << (i ^ 7);
        # i ^ 7 reverses the bit order filling (MSB first logic in a loop 0..7)
        c += bit_out << (i ^ 7)
    
    return state, c

# --- Main Execution ---

def main():
    # "MIKRON"      =  O  N  M  I  K  R
    # Key           = 4F 4E 4D 49 4B 52     - Secret 48-bit key
    # Serial        = 49 43 57 69           - Serial number of the tag
    # Random        = 65 6E 45 72           - Random IV
    
    # Expected Output: D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6

    key_input = 0x524B494D4E4F
    serial_input = 0x69574349
    iv_input = 0x72456E65

    # Note: The C code wraps constants in rev64/rev32 calls. 
    # This essentially bit-reverses every byte individually but keeps byte order.
    
    state = hitag2_init(
        rev64(key_input), 
        rev32(serial_input), 
        rev32(iv_input)
    )

    output_bytes = []
    for i in range(16):
        state, byte_val = hitag2_byte(state)
        output_bytes.append(byte_val)

    # Print formatted hex
    print(" ".join(f"{b:02X}" for b in output_bytes))

if __name__ == "__main__":
    main()