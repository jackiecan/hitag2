#!/usr/bin/env python

"""
HITAG2 cipher
Implemented by Aram Verstegen

Comments added and some code deleted
"""


def i4(x, a, b, c, d):
    '''
    This function extracts bits a,b,c,d from state x and combines them into a 4-bit number abcd
    '''
    return (((x >> a) & 1)*8)+((x >> b) & 1)*4+((x >> c) & 1)*2+((x >> d) & 1)

def f20_4(state): #f_a
    return ((0x3c65 >> i4(state,34,43,44,46)) & 1)

def f20_3(state): #f_b
    return (( 0xee5 >> i4(state,28,29,31,33)) & 1)

def f20_2(state): #f_b
    return (( 0xee5 >> i4(state,17,21,23,26)) & 1)

def f20_1(state): #f_b
    return (( 0xee5 >> i4(state, 8,12,14,15)) & 1)

def f20_0(state): #f_a
    return ((0x3c65 >> i4(state, 2, 3, 5, 6)) & 1)

def f20_last(s0,s1,s2,s3,s4): #f_c
    return (0xdd3929b >> ((s0 * 16)
                        + (s1 *  8)
                        + (s2 *  4)
                        + (s3 *  2)
                        + (s4 *  1))) & 1

def f20(state):
    '''
    This function implements the filter function f20 as described in the paper.
    
    :param state: 48-bit state of the lfsr
    :return: single bit (output of the filter function f20)
    '''
    return f20_last(f20_0(state), f20_1(state), f20_2(state), f20_3(state), f20_4(state))


def hitag2_init(key, uid, nonce):
    '''
    This function initializes the state of the lfsr based on key, uid and nonce
    
    :param key: 48-bit key
    :param uid: 32-bit uid
    :param nonce: 32-bit nonce
    :return: the initialized state of the lfsr
    '''

    #### Prepare Pre-state ####
    state = 0
    # Take the top 16 bits of the key and shift them in the register
    for i in range(32, 48):
        # Insert first 16 bits (starting with MSB) of key into state
        #    For This the state is shifted left to make one bit of space and the next bit of the key is inserted at that space 
        state = (state << 1) | ((key >> i) & 1)  

    for i in range(0, 32):
        # Insert first 32 bits (starting with MSB) of uid into state (all bits of uid are used)
        #    Also here the bits are shifted in one by one from the "right side"
        state = (state << 1) | ((uid >> i) & 1) 

    #### Initialize Rounds ####
    curr_f20 = 0
    for i in range(0, 32):
        # Evaluate the filter function to get curr_f20 (also named b in the paper)
        curr_f20 = f20(state)
        # Extract the current bits of nonce and key to be used in the XOR operations
        curr_nonce_bit = (nonce >> (31 - i)) & 1
        curr_key_bit = (key >> (31 - i)) & 1
        
        # Now we xor these three bits to get the new feedback bit that will be shifted into the state
        #   from the left (this feedback bits are the bits a_48..a79 from the paper)
        #   To insert this bit in the lfsr we shift is right to make soace and then insert the bit at the leftmost index 47
        final_fb_bit = curr_f20 ^ curr_nonce_bit ^ curr_key_bit
        state = (state >> 1) | (final_fb_bit << 47)
    
    return state # returns state


def lfsr_feedback(state):
    '''
    This function calculates the feedback bit of the lfsr by xoring the bits at the tapped indexes in the current state.
    
    :param state: 48-bit state of the lfsr
    :return: feedback bit (0 or 1)
    '''
    return (((state >>  0) ^ (state >>  2) ^ (state >>  3)
            ^ (state >>  6) ^ (state >>  7) ^ (state >>  8)
            ^ (state >> 16) ^ (state >> 22) ^ (state >> 23)
            ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
            ^ (state >> 42) ^ (state >> 43) ^ (state >> 46)
            ^ (state >> 47)) & 1)

def lfsr(state):
    '''
    This function updates the state of the lfsr by shifting it to the right and inserting the feedback bit at the leftmost index 47.
    
    :param state: 48-bit state of the lfsr
    :return: updated state of the lfsr
    '''
    return (state >>  1) + (lfsr_feedback(state) << 47)

def hitag2(state, length=48):
    '''
    This function generates a keystream of the specified length 
    
    :param state: 48-bit state of the lfsr
    :param length: number of keystream bits to be generated
    :return: generated keystream as an integer (with the first generated bit at the msb)
    '''
    c = 0 # keystream output

    for i in range(0, length):
        # The keystream bit is determined by evaluating the filter function f20 and adding it to the output
        keystream_bit = f20(state)
        c = (c << 1) | keystream_bit
        
        # Then the state is updated by shifting it to the right and inserting the feedback bit at the leftmost index 47
        state = lfsr(state)
    return c

if __name__ == "__main__":
    key = 0x123456789ABC
    uid = 0x12345678

    ctr = 0x1234567
    btn = 0x1
    #attach btn to ctr to form 32-bit
    nonce = (ctr << 4) | btn

    state = hitag2_init(key, uid, nonce)

    #print(f"state after Init: {state:048b}")
    keystream = hitag2(state, 32)