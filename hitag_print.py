#!/usr/bin/env python

"""
HITAG2 cipher
Implemented by Aram Verstegen
"""

def i4(x, a, b, c, d):
    return (((x >> a) & 1)*8)+((x >> b) & 1)*4+((x >> c) & 1)*2+((x >> d) & 1)


def f20_4(state):
    return ((0x3c65 >> i4(state,34,43,44,46)) & 1)

def f20_3(state):
    return (( 0xee5 >> i4(state,28,29,31,33)) & 1)

def f20_2(state):
    return (( 0xee5 >> i4(state,17,21,23,26)) & 1)

def f20_1(state):
    return (( 0xee5 >> i4(state, 8,12,14,15)) & 1)

def f20_0(state):
    return ((0x3c65 >> i4(state, 2, 3, 5, 6)) & 1)

def f20_last(s0,s1,s2,s3,s4):
    return (0xdd3929b >> ((s0 * 16)
                        + (s1 *  8)
                        + (s2 *  4)
                        + (s3 *  2)
                        + (s4 *  1))) & 1

def f20(state):
    return f20_last(f20_0(state), f20_1(state), f20_2(state), f20_3(state), f20_4(state))


def hitag2_init(key, uid, nonce):
    state = 0
    # take the top 16 bits of the key and shift them in the register
    print("inserting key:")
    print(f"  key:                        {key:048b}")
    print(f"  part of key to be inserted: {key >> 32:016b}")
    print(f"  part of key reversed:       {f'{key >> 32:016b}'[::-1]}")
    for i in range(32, 48):
        state = (state << 1) | ((key >> i) & 1)
        print(f"   state: {state:048b}")

    print("inserting uid:")
    print(f"  uid to be inserted: {uid:032b}")
    print(f"  uid reversed:       {f'{uid:032b}'[::-1]}")
    for i in range(0, 32):
        state = (state << 1) | ((uid >> i) & 1)
        print(f"   state: {state:048b}")
    print(f"state: {state:048b}")
    
    print("\nInitializing Rounds\n")
    print(f"   nonce:         {nonce:032b}")
    print(f"   key:           {key:048b}")
    print(f"   key part used:                 {key & 0xFFFFFFFF:032b}")

    for i in range(0, 32):
        # 1. Extract the bits
        curr_f20 = f20(state)
        curr_nonce_bit = (nonce >> (31 - i)) & 1
        curr_key_bit = (key >> (31 - i)) & 1

        print(f"state: {state:048b} | f20: {curr_f20}, nonce bit: {curr_nonce_bit} | key bit: {curr_key_bit}")
        
        # 2. First XOR: The filter result meets the random challenge
        final_fb_bit = curr_f20 ^ curr_nonce_bit ^ curr_key_bit

        # 5. Update the state (Shift right and insert the new feedback bit at bit 47)
        state = (state >> 1) | (final_fb_bit << 47)
    print(f"final init state: {state:048b}")
    
    return state


def lfsr_feedback(state):
    return (((state >>  0) ^ (state >>  2) ^ (state >>  3)
            ^ (state >>  6) ^ (state >>  7) ^ (state >>  8)
            ^ (state >> 16) ^ (state >> 22) ^ (state >> 23)
            ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
            ^ (state >> 42) ^ (state >> 43) ^ (state >> 46)
            ^ (state >> 47)) & 1)
def lfsr(state):
    #shift right and insert feedback bit at bit 47
    return (state >>  1) + (lfsr_feedback(state) << 47)

def hitag2(state, length=48):
    # stores all keystream bits filling in new bits in at the lsb
    c = 0 
    for i in range(0, length):
        keystream_bit = f20(state)
        c = (c << 1) | keystream_bit
        print(f"state: {state:048b} -> {keystream_bit} | {c}")
        
        state = lfsr(state)
    return c

if __name__ == "__main__":
    key = 0x123456789ABC
    uid = 0x12345678

    ctr = 0x1234567
    btn = 0x8
    #attach btn to ctr to form 32-bit
    nonce = (ctr << 4) | btn
    print(f"Using nonce: {nonce:032b} | {hex(nonce)} | {int(nonce)}")

    state = hitag2_init(key, uid, nonce)

    print(f"\nkeystream phase\n")

    #print(f"state after Init: {state:048b}")
    keystream = hitag2(state, 32)
    print(f"keystream: {keystream:032b} | {hex(keystream)} | {int(keystream)}")