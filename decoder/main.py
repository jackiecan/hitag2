# raw data looks like this:
# 0A AA AA AA AA AA AA AA ... 00 00 00 00 00 00 00 00 00 00 00 00 40

# this is encoded with manchester encoding
# https://en.wikipedia.org/wiki/Manchester_code

def hex_to_bin(hex_str):
    """Converts hex string to a binary string."""
    # Remove spaces and convert to binary
    clean_hex = hex_str.replace(" ", "")
    scale = 16
    num_of_bits = len(clean_hex) * 4
    return bin(int(clean_hex, scale))[2:].zfill(num_of_bits)


def manchester_decode(bin_str):
    """
    Attempts to decode a binary string using Manchester logic.
    Manchester: '01' -> 1, '10' -> 0 (or inverse).
    Returns the decoded list of bits.
    """
    decoded = []
    # Process in pairs
    for i in range(0, len(bin_str) - 1, 2):
        pair = bin_str[i:i + 2]
        if pair == '01':
            decoded.append(1)
        elif pair == '10':
            decoded.append(0)
        else:
            # '00' or '11' are violations in strict Manchester,
            # but usually happen at boundaries. We mark as None.
            decoded.append(None)
    return decoded


def parse_hitag2_packet(bits):
    """
    Parses a list of bits into Hitag2 fields.
    Structure (Fig 11): UID(32) + BTN(4) + LCTR(10) + KS(32) + CHK(8)
    """
    if len(bits) < 86:
        return None

    # Convert list of bits to integer helper
    def to_int(bit_list):
        val = 0
        for b in bit_list:
            if b is None: return 0  # Treat errors as 0 for parsing attempts
            val = (val << 1) | b
        return val

    # Extract fields
    uid_bits = bits[0:32]
    btn_bits = bits[32:36]
    lctr_bits = bits[36:46]
    ks_bits = bits[46:78]
    chk_bits = bits[78:86]

    return {
        "UID": hex(to_int(uid_bits)),
        "BTN": bin(to_int(btn_bits)),
        "LCTR": int(to_int(lctr_bits)),  # Keep as int for math
        "KS": hex(to_int(ks_bits)),
        "CHK": hex(to_int(chk_bits))
    }


def read_raw_data(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

if __name__ == "__main__":

    # --- YOUR RAW DATA PROCESSING ---

    # I took the clearest block from your data (after the AA preamble):
    # "CB 32 D4 D4 AD 53 4B 33 2B 32 D2 AD 2A D4 B2 CD 4B 52 B5 4B 2C B3 20"
    raw_hex_payload = "CB32D4D4AD534B332B32D2AD2AD4B2CD4B52B54B2CB320"

    # 1. Convert to binary
    binary_stream = hex_to_bin(raw_hex_payload)

    print(f"Raw Binary Stream Length: {len(binary_stream)}")

    # 2. Try Decoding (We test offsets because we don't know where the 'pair' starts)
    # We look for a valid decoding that doesn't have too many errors.
    for offset in range(2):
        shifted_stream = binary_stream[offset:]
        decoded_bits = manchester_decode(shifted_stream)

        # Filter out None values (decoding errors) to see if it looks clean
        clean_bits = [b for b in decoded_bits if b is not None]

        if len(clean_bits) > 80:  # If we got a decent amount of data
            print(f"\n--- Decoding Attempt (Offset {offset}) ---")
            packet = parse_hitag2_packet(clean_bits)
            if packet:
                print(f"UID:  {packet['UID']}")
                print(f"BTN:  {packet['BTN']}")
                print(f"LCTR: {packet['LCTR']} (Low Counter)")
                print(f"KS:   {packet['KS']} (Keystream - This is crucial!)")
                print(f"CHK:  {packet['CHK']}")
                print("-" * 30)
