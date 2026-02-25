def hex_to_bin(hex_str):
    '''
    Function converts hex string to a binary string.
    :param hex_str: A string containing hexadecimal characters (can include spaces)
    :return: A string representing the binary equivalent of the hex input
    '''
    # Remove spaces
    clean_hex = hex_str.replace(" ", "")
    num_of_bits = len(clean_hex) * 4
    #convert hex string to int and then to binary string with leading zeros to ensure it has the correct length
    return bin(int(clean_hex, 16))[2:].zfill(num_of_bits)


def manchester_decode(bin_str):
    '''
    Function attempts to decode a binary string using Manchester logic
        Manchester: '01' -> 0, '10' -> 1
    :param bin_str: A string of '0's and '1's representing the binary data
    :return: A list of decoded bits (0s and 1s), with None
    '''
    decoded = []
    # Process in pairs
    for i in range(0, len(bin_str) - 1, 2):
        pair = bin_str[i:i + 2]
        if pair == '01':
            decoded.append(0)
        elif pair == '10':
            decoded.append(1)
        else:
            # '00' or '11' are violations in Manchester, but can happen at borders
            decoded.append(None)
    return decoded

def validate_and_decode(bits):
    """
    Function attempts to find a packet in a bitstream and validates it via checksum.
    :param bits: A list of bits (0s and 1s) representing the decoded data stream
    :return: Returns (True, decoded_data) if valid, (False, None) otherwise.
    """
    sync_pattern = [0, 0, 0, 0, 0, 0, 0, 1]
    
    # Try find the sync pattern in the bitstream and extract the following 88 bits as potential packet data
    #    104 bits (full packet) - 16 bits (for sync) = 88 bits (rest of the packet)
    for i in range(len(bits) - 88): # 88 is the min length of one packet
        if bits[i:i+8] == sync_pattern:
            # Found potential start! Extract the next 88 bits (UID to CHK)
            payload = bits[i+8 : i+8+88]
            
            calc_chk = 0
            # Packet bytes for XOR are the first 80 bits (UID, BTN, LCTR, KS, 10)
            #    j goes from 0 to 72 (inclusive) in steps of 8 to cover the first 80 bits (10 bytes)
            for j in range(0, 73, 8):
                # Turn 8 bit "array" into a byte value
                byte_val = int(''.join(map(str, payload[j:j+8])), 2)
                # XOR the byte value into the checksum calculation
                calc_chk ^= byte_val 
            
            # Extract the checksum from the last 8 bits of the payload
            extracted_chk = int(''.join(map(str, payload[80:88])), 2)
            
            if calc_chk == extracted_chk:
                print(f"[+] Valid packet found at bit index {i} with correct checksum {calc_chk:02X} == {extracted_chk:02X}")
                return True, payload
                
    return False, None


#  Main execution starts here
if __name__ == "__main__":
    files = ["trace_01.sub","trace_02.sub"]

    for file in files:
        # Load Trace recorded with FlipperZero and extract the raw hex payload
        print(f"[*] Processing file: {file}")
        raw_hex_payload = ""
        with open(file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("Data_RAW:"):
                    raw_hex_payload = line.split("Data_RAW:")[1].strip()

        # convert the raw hex payload to a binary string
        binary_stream = hex_to_bin(raw_hex_payload)

        # Check offset: If too many Manchester Decoding errors (None values) occur, 
        #  try shifting the binary stream by 1 bit and decode again.
        for offset in range(2):  # Check both offsets: 0 and 1
            shifted_stream = binary_stream[offset:]
            decoded_bits = manchester_decode(shifted_stream)
            clean_bits = [b for b in decoded_bits if b is not None]
            
            #Validate the decoded bits (Sync pattern + checksum) and extract fields if valid
            is_valid, packet_data = validate_and_decode(clean_bits)

            if is_valid:
                print(f"[+] Success! Correct Offset is {offset}")

                print(f"[*] Full extracted bits: {''.join(str(b) for b in clean_bits)}")
                # Extract fields
                uid_bits = ''.join(str(b) for b in packet_data[0:32])
                btn_bits = ''.join(str(b) for b in packet_data[32:36])
                lctr_bits = ''.join(str(b) for b in packet_data[36:46])
                ks_bits = ''.join(str(b) for b in packet_data[46:78])
                one_null = ''.join(str(b) for b in packet_data[78:80])
                chk_bits = ''.join(str(b) for b in packet_data[80:88])

                print(f"UID:  {uid_bits:32} -> {int(uid_bits, 2):08X}")
                print(f"BTN:  {btn_bits:32} -> {int(btn_bits, 2)}")
                print(f"LCTR: {lctr_bits:32} -> {int(lctr_bits, 2)}")
                print(f"KS:   {ks_bits:32} -> {int(ks_bits, 2):08X}")
                print(f"CHK:  {chk_bits:32} -> {int(chk_bits, 2):02X}")
                
                print("[+] Done ------------------\n")
