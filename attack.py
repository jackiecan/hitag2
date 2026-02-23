import pickle
import time
import hitag as h2
import os
from hitag import f20

# positions of the 20 taps in the 48-bit LFSR state that are input to the f20 filter function
taps = [2, 3, 5, 6, 8, 12, 14, 15, 17, 21, 23, 26, 28, 29, 31, 33, 34, 43, 44, 46]

def generate_trace(key, uid, iv):
    '''
    This function simulates the generation of a single trace for a given key, uid, and iv.
    It initializes the Hitag2 state and produces a 32-bit keystream output, which represents the observable output for that trace.
    
    :param key: key to be used for the trace generation (48-bit)
    :param uid: uid to be used for the trace generation (32-bit)
    :param iv: IV to be used for the trace generation (32-bit)
    :return: dictionary containing the uid, iv, and keystream output
    '''
    # Initialization procedure of the Hitag2 cipher
    state = h2.hitag2_init(key, uid, iv)
    
    # Generating 32 bits of keystream output
    keystream = h2.hitag2(state, 32)
    
    # Return a trace dictionary containing the uid, iv, and keystream output
    return {
        'uid': uid,
        'iv': iv,
        'ks': keystream
    }

def precalculate_probability_table():
    '''
    This function precomputes a lookup table for the f20 filter function based on the number of 
    known bits in the guessing window. It iterates through all possible combinations of known bits 
    and then checks how many of the possible unknown bit combinations yield an output of 1 from the 
    f20 function. With that we can compute the probability that f20 outputs a 1, given the known input bits. 
    In the attack this is used to score our guesses.

    :return: nested dictionary where: 
        first key: is the number of known bits,
        second key: is the value of those known bits, 
        value: is the probability of f20 outputting 1 for that combination of known bits.
    '''
    print("[*] Precomputation of f20 lookup table...")

    table = {}
    # Iterate through all possible number of known tap bits in our guessing window
    #   Since f20 has 20 input bits we check from 0 known bits (all unknown) to 20 known bits (all known)
    for amount in range(21): # 0..20 inclusive (to make the table semantically complete)
        table[amount] = {}
        #print(f"  Precomputing for {amount} known bits...")

        num_known = amount
        num_unknown = 20 - amount 

        # Iterate over all possible combinations of the known bits
        for known_val in range(1 << num_known):

            count_ones = 0
            
            # Map the known bits to their actual tap positions in a 48-bit state
            state_known = 0
            for i in range(num_known):
                # Extract the bit at position i from the known part of the LFSR and insert them at the correct tap positions in the 48-bit state
                bit = (known_val >> i) & 1  
                state_known |= (bit << taps[i])

            # Iterate over all possible combinations of the unknown bits
            for unknown_val in range(1 << num_unknown):
                
                # Map the unknown bits to their actual tap positions in the 48-bit state
                state_unknown = 0
                for i in range(num_unknown):
                    bit = (unknown_val >> i) & 1
                    # The unknown bits occupy the remaining tap positions
                    state_unknown |= (bit << taps[num_known + i])
                
                # Combine known and unknown parts to form the full 48-bit mock state
                state = state_known | state_unknown
                
                # Directly use the native f20 function!
                if f20(state) == 1:
                    count_ones += 1

            # Aggregate results to get the probability of f20 outputting 1
            prob = float(count_ones) / float(1 << num_unknown)
            table[amount][known_val] = prob

    # Export the table to file
    with open("out/prob_table.txt", "w") as f:
        for amount in range(21): # 0..20 inclusive
            f.write(f"Known bits: {amount}\n")
            for known_val, prob in table[amount].items():
                f.write(f"  Known Val {known_val:0{amount}b}: P(1)={prob:.6f}\n")

    return table

def precalculate_window_table():
    '''
    This function precomputes a lookup table that classifies the 20 filter taps as known or unknown 
    for each possible window size (from 16 to 32) and each possible shift 't' of the window.
    This speeds up the attack by allowing us to quickly determine which taps are known for any given window configuration without needing to compute it on the fly during the attack.

    :return: nested dictionary where:
        first key: is the window size (from 16 to 32)
        second key: is the current shift 't' of the window
        value: is a list of the tap positions that are known for that window configuration. 
            The tap positions are the actual positions in the 48-bit state (e.g. 2,3,5,6,...).
    '''
    print("[*] Precomputation of window lookup table...")
    table = {}
    for window_size in range(16, 33): # window size [16,..,32]
        table[window_size] = {}
        for t in range(window_size):
            
            # Indexes where the corrent window starts and ends in the 48-bit state With respect to the size and the current shift 't'
            window_start = 0
            window_end = (window_size - 1) - t
            
            # Array that saves which taps are in the "known area" for this window configuration in a list.
            guess_indices = []   
            
            # Classify the 20 filter taps
            for i in range(20):
                tap_pos = taps[i]

                # If the tap position is within the current window, it is known and added to the value in the dictionary.
                if window_start <= tap_pos <= window_end:
                    guess_indices.append(tap_pos)
            table[window_size][t] = guess_indices

    # Export dictionary to file
    with open("out/window_table.txt", "w") as f:
        for window_size, t_dict in table.items():
            f.write(f"Window Size: {window_size}\n")
            for t, known_indices in t_dict.items():
                f.write(f"  t={t}: Known Indices: {known_indices}\n")

    return table

def garcia_attack_step1_2_3(traces, prob_table, window_table, secret_key=None):
    '''
    This function implements the first three steps of Garcia's attack on Hitag2. 
    It brute-forces all possible 16-bit guesses for the upper half of the key (the "window") and 
    scores each guess based on how well it matches the observed keystream bits across all traces. 
    The scoring is done using the precomputed probability table for the f20 filter function, 
    which allows us to calculate the likelihood of each guess being correct based on the known 
    bits in the window and the observed keystream output.
    
    :param traces: List of trace dictionaries with 'uid', 'iv', and 'ks' (keystream)
    :param prob_table: precomputed probability table that gives the probability of the f20 function 
                       outputting 1 for any combination of known bits in the window
    :param window_table: precomputed lookup table that gives the list of known tap positions 
                         for each window size and shift value
    :param secret_key: For Debug: The real secret key, to check if the correct key is among the candidates
    '''
    print(f"[*] Starting Step 1: Brute-forcing 16-bit window...")
    start_time = time.time()
    candidates = []

    ##### Step 1 #####
    # Iterate over all possible 16-bit guesses. This corresponds to brute-forcing the upper 16 bits of the key, 
    #    which are part of the initial state of the LFSR.
    for key_prefix in range(2**16):
        print(f"  Testing guess {key_prefix+1}/65536", end='\r')
        
        # Reconstruct the full 48-bit initialization state for the lfsr initialization procedure.
        #   This is done by combining the guessed upper 16 bits of the key (key_prefix) with the known UID bits from the traces.
        key = key_prefix << 32
        init_state = 0
        # Start by shifting in the guessed key bits (the upper 16 bits of the key) into the initial state, like it is done in the
        #   Hitag2 initialization procedure.
        for bit_idx in range(32, 48):
            init_state = (init_state << 1) | ((key >> bit_idx) & 1)  
        # Then the uid bits are shifted in, which are the same for all traces, so we can just use the first trace to extract them.
        for bit_idx in range(0, 32):
            init_state = (init_state << 1) | ((traces[0]['uid'] >> bit_idx) & 1) 

        # We end up with the initial state of the LFSR BEFORE the initialization procedure starts.
        #   This state has to be handed to the next attack step to be able to compute b_i which is needed to update the lfsr state before the 
        #   keystream outputting phase (we need it to compute a_48+i). In this attack step these init_states are still the same for all traces,
        #   but in later steps they will differ due to the different ivs, so we save them in an array for each trace.
        init_states = [init_state] * len(traces)

        ##### Step 2 #####
        # This now simulates step 2 from the paper, which kind of corresponds to the initialization procedure of Hitag2.
        #   We end up in the state of the lfsr where it would start to output the keystream bits though only the bits of the known window are set.
        #   The "unknown part" is resulting from the lookup in the probability table. 
        ks_state_known = init_state >> 32

        ##### Step 3 #####
        # The score for a guess is determined by averaging over the scores per trace.
        trace_scores = []
        for trace in traces:
            # Since the precomputed probability table gives us the probability of f20 outputting a 1 for this combination of known bits, 
            #    we can use it to score our guess: The score - accoring to the papers definition - corresponds to the 
            #    probability deviation which is centered around 1 (not 0.5), that's why the probability is later multiplied by 2
            current_score = 1.0   
            for t in range(16):
                known_indices = window_table[16][t] # lookup which taps are known for this window configuration

                # To be able to score multiple keystream bits for the same guess, we need to shift the state accordingly
                #   Then we can determine the current known bits by extracting the bits at the known tap positions and 
                #   forming the index for the probability table lookup
                shifted_guess = ks_state_known >> t
                table_index = 0
                for idx, pos in enumerate(known_indices):
                    # Extract bit of lfsr at tap position
                    bit = (shifted_guess >> pos) & 1 
                    # Place extracted bit at the index corresponding to the position of the tap in the array of taps, 
                    #    so since the tap at index 2 is the first tap (index: 0), the bit would be placed at index 0 
                    #    in the value table_index to form the lookup-index of the probability)
                    table_index |= (bit << idx)      
                # The score (score) of a guess is determined by multiplying the bit_score for each keystream bit when shifting the window by t.
                prob = prob_table[len(known_indices)][table_index]
                # Get the real keystream bit from the trace for scoring. 
                #   Start with the MSB (k_0) and go down to bit k_16, since we are only scoring the first 16 bits in this step.
                real_bit = (trace['ks'] >> (31 - t)) & 1
                if real_bit == 1:
                    current_score *= (prob * 2.0)
                else:
                    # The probability table was set up to compute the probability of f20 outputting a 1, so we can simply get
                    #   the probability of it outputting a 0 by subtracting from 1.
                    current_score *= (1.0 - prob) * 2.0

            trace_scores.append(current_score)
        
        average_score = sum(trace_scores) / len(trace_scores)
        
        # Save the candidate guess along with its final score and the initial states for each trace.
        #   This is the input for the next attack step.
        candidates.append((key, init_states, average_score))

    candidates.sort(key=lambda x: x[2], reverse=True)

    # For Debug: check position of intermediate key of the real value in the candidates and if it is still present
    #   Determines if the attack works or if if won't work
    found = False
    for i, (key, _, _) in enumerate(candidates):
        intermediate_key = secret_key & 0xFFFF00000000
        if key == intermediate_key:
            found = True
            print(f"    Debug: Real key intermediate (0x{intermediate_key:012x}) found at position {i+1} with score {candidates[i][2]:.10f}!")
            break
    if not found:
        print(f"    Debug: Real key intermediate (0x{intermediate_key:012x}) NOT found among candidates!")

    # save candidates to file
    with open("out/candidates_step1_16_window.txt", "w") as f:
        f.write(f"{'Key (bin)':48} {'Key (hex)':16} {'Score':10} ")
        #for i in range(len(traces)):
        #    f.write(f"{f'trace {i}':48}")
        f.write("\n")
        for key, lfsr_states, score in candidates:
            f.write(f"{key:048b} {key:012x} {score:.10f} ")
            #for i in range(len(traces)):
            #    f.write(f"{lfsr_states[i]:048b} ")
            #f.write("\n")
    print(f"    Step 1 completed in {time.time() - start_time:.2f} seconds.")
    return candidates

def garcia_attack_step4_5(out_candidates, traces, prob_table, window_table, secret_key=None):
    '''
    This function implements the steps 4 and 5 of the attack, which are basically an extension of the first three steps.
    
    :param out_candidates: List of tuples (key, init_states, score) for the top candidates from the previoud step
    :param traces: List of trace dictionaries with 'uid', 'iv', and 'ks' (keystream)
    :param prob_table: precomputed probability table that gives the probability of the f20 function 
                       outputting 1 for any combination of known bits in the window
    :param window_table: precomputed lookup table that gives the list of known tap positions 
                         for each window size and shift value
    :param secret_key: For Debug: The real secret key, to check if the correct key is among the candidates
    '''
    for window_size in range(17, 33):  # window size [17,..,32]
        start_time = time.time()
        print(f"[*] Starting Step 5.{window_size}: Brute-forcing {window_size}-bit window...")

        # The candidates from the previous step are now used as input for the next step.
        #   By extending the window by one bit, we can now include one more key bit in our guessing and scoring procedure.
        #   So we iterate over the candidates and create two new candidates for each old one by simply extending the key guess by one bit (0 or 1).
        in_candidates = []
        for key, init_states, _ in out_candidates: #score is only relevant for sorting the candidates, but not needed in the next attack step
            key_extended = key | (1 << (48-window_size))
            in_candidates.append((key, init_states)) 
            in_candidates.append((key_extended, init_states)) 
        
        # Now we iterate over the new candidates and score them again (with the extended window).
        out_candidates = []
        for candidate_index, (key, init_states) in enumerate(in_candidates):
            print(f"  Testing guess {candidate_index+1}/{len(in_candidates)}", end='\r')
        
            trace_scores = []
            out_init_states = []
            
            for trace_index, trace in enumerate(traces):
                init_state = init_states[trace_index]
                
                ##### Step 5.1 #####
                # We now need to determine the next derived bit in the initialization procedure (a_48+i)
                #   To be able to do so, we need to compute b_i which is the output of the f20 function for the 
                #   current state (handed over from the last step)
                b = f20(init_state)
                # We also need the key bit k_16+i which is the next key bit that is shifted in during the initialization procedure.
                #   This basically corresponds to the bit we just added to the window.
                #   For the first iteration (window_size=17) we want k_16 (at index 31), then k_17 (index 30), ...
                k_16_i = (key >> (48 - window_size)) & 1
                # We also need the IV bit iv_i which is the next bit of the iv that is shifted in during the initialization procedure.
                #   For the first round (window_size=17) we want iv_0 (MSB, at index 31), then iv_1, ...
                iv_i = (trace['iv'] >> (48 - window_size)) & 1 
                # Now we can cumpute the new feedback bit
                a_48_i = k_16_i ^ iv_i ^ b

                # update the lfsr state according to the initialization procedure by shifting in the new feedback bit
                init_state = (init_state >> 1) | (a_48_i << 47)
                out_init_states.append(init_state)

                ##### Step 5.2 #####
                # Like before we shift the state to get the current known bits to the very rightside of the lfsr state.
                #   This marks the state from which the keystream outputting phase would start, where we continue with the scoring.
                ks_state_known = init_state >> (48 - window_size)

                ##### Step 5.3 #####
                # Now we are again scoring the guess (same as step 3 in function garcia_attack_step1_2_3 but with the extended window).
                current_score = 1.0
                for t in range(window_size):
                    known_indices = window_table[window_size][t] #lookup taps of extended window
                    shifted_lfsr = ks_state_known >> t
                    table_index = 0
                    for bit_index, pos in enumerate(known_indices):
                        bit = (shifted_lfsr >> pos) & 1
                        table_index |= (bit << bit_index)
                    
                    # probability lookup and scoring
                    prob = prob_table[len(known_indices)][table_index]
                    real_bit = (trace['ks'] >> (31 - t)) & 1 
                    if real_bit == 1:
                        current_score *= (prob * 2.0)
                    else:
                        current_score *= (1.0 - prob) * 2.0

                trace_scores.append(current_score)
            
            average_score = sum(trace_scores) / len(trace_scores) 
            
            out_candidates.append((key, out_init_states, average_score))

        # Sort candidates according to their score
        out_candidates.sort(key=lambda x: x[2], reverse=True)

        # For Debug: check position of intermediate key of the real value in the candidates and if it is still present
        #   Determines if the attack works or if if won't work
        found = False
        for i, (key, _, _) in enumerate(out_candidates):
            intermediate_key = secret_key & (0xFFFFFFFFFFFF << (48-window_size))
            if key == intermediate_key:
                found = True
                print(f"    Debug: Real key intermediate (0x{intermediate_key:012x}) found at position {i+1} with score {out_candidates[i][2]:.10f}!")
                break
        if not found:
            print(f"    Debug: Real key intermediate (0x{intermediate_key:012x}) NOT found among candidates!")

        # save candidates to file
        with open(f"out/candidates_step5_{window_size}_window.txt", "w") as f:
            f.write(f"{'Key (bin)':48} {'Key (hex)':16} {'Score':10} ")
            #for i in range(len(traces)):
            #    f.write(f"{f'trace {i}':48}")
            f.write("\n")
            for key, lfsr_states, score in out_candidates:
                f.write(f"{key:048b} {key:012x} {score:.10f} ")
                #for i in range(len(traces)):
                #    f.write(f"{lfsr_states[i]:048b} ")
                f.write("\n")
        
        #### Step 4 #####
        # Only take the best 400.000 candidates to keep the runtime of the next iteration manageable
        out_candidates = out_candidates[:400000]

        print(f"    Step 5.{window_size} completed in {time.time() - start_time:.2f} seconds. Candidates: {len(out_candidates)}")
            
    return out_candidates

def read_candidates(filepath):
    '''
    Function reads the candidates from the provided file and returns a suitable data structure, like it is used in the attack
    This can be used to skip the attack and directly start the brutforce attack step 6.
    
    :param filepath: path to the file containing the candidates
    :return: list of tuples, where each tuple contains (key, 0, 0) for a candidate
    '''
    candidates = []
    
    with open(filepath, 'r') as file:
        # Skip headers
        next(file)
        
        # Loop though lines in the file and extract the candidate keys
        for line in file:
            # Clean up leading/trailing whitespace and skip empty lines (should not be the case)
            line = line.strip()
            if not line:
                continue
            
            # Get the columns in an array by splitting the line at whitespaces
            columns = line.split()
            
            # We expect at least 3 columns (key in binary, key in hex, score), we can ignore the rest for this purpose
            if len(columns) >= 3:
                key = int(columns[0],2)  # extract the key cnadidate and convert to integer e.g., '0000000100011110...'
                init_states = 0 # Placeholder (not relevant for step 6)
                score = 0  # Placeholder (not relevant for step 6)
                
                # Append tuple with the candidate key and placeholders to the candidates list that is returned later
                candidates.append((key, init_states, score))
                
    return candidates

def garcia_attack_step6(candidates, traces):
    '''
    This function implements the final brute-force step to find the full 48-bit key from the top candidates obtained.
    
    :param candidates: List of tuples (key, init_states, score) for the top candidates
    :param traces: List of trace dictionaries with 'uid', 'iv', and 'ks' (keystream)
    :return: The full key if found, otherwise None
    '''
    print("\n[*] Starting Step 6: Brute-forcing the remaining 16 bits of the key...")
    start_time = time.time()
    
    # We should only need to check the very top candidates since the correct key should be among them.
    #   Since the attack is not working perfectly, we just set it to 10.000 candidates
    for candidate_idx, (key, _, _) in enumerate(candidates[:10000]):
        print(f"  Testing candidate {candidate_idx+1}/10000...", end='\r')
        
        # The key cnadidates after the last step have bits k_0 (MSB) to k_31 set
        # -> for example we could have the candidate: 111111111111111111111111111111110000000000000000
        # This means the 16 missing bits (0 bits) are still unknown and have to be brute forced.
        # For this we iterate over all 2^16 combinations of these bits, initialize the hitag algorithm with this full key,
        # generate the full key-stream output (32 bits) and compare it with the one in the traces.
        # If the generated keystream match for all traces, we found the correct key!  
        for suffix in range(65536):
            test_key = key | suffix
            
            # Generate the keystream output for the first trace with the current full key guess.
            trace = traces[0]
            state = h2.hitag2_init(test_key, trace['uid'], trace['iv'])
            ks = h2.hitag2(state, 32) # guessed key stream
            
            # Test keystream against the first trace
            # If it matches, verify against the other traces to eliminate false positives
            if ks == trace['ks']:
                valid = True
                for other_trace in traces[1:]:
                    state = h2.hitag2_init(test_key, other_trace['uid'], other_trace['iv'])
                    if h2.hitag2(state, 32) != other_trace['ks']:
                        valid = False
                        break
                if valid:
                    # The key could recreate all keystreams for all traces, so we found the correct key!
                    print(f"\n[+] KEY FOUND! 0x{test_key:012X}")
                    print(f"    Step 6 completed in {time.time() - start_time:.2f} seconds.")
                    return test_key
                    
    print("\n[-] Key not found in top candidates.")
    return None

def experiment_traces(experiment_id):
        '''
        This function defines the parameters for the different experiments that can be run with this code.
        
        :param experiment_id: The ID of the experiment to run (see explanations).
        :return: The traces generated with the parameters of the experiment.

        SECRET_KEY (48-bit): The secret key is not known to us during the attack and is the target of it.
        UID (32-bit): The UID is fixed for all traces and is used in the initialization procedure of Hitag2
        IV: The IV is different for each trace due to the Rolling Code mechanism of Hitag2
            It consists of the concatenation of a counter (28-bit) and a button value (4-bit)
            To simulate the generation of multiple traces we generate multiple IV values 
            by incrementing the Rolling Code (counter) for each trace
        COUNTER (28 bit): Rolling Code counter, can be incremented for each trace to generate different IVs
        BTN (4 bit): Button ID, indicates which button was pressed, can be fixed (assuming the same button is used for all traces)
        '''
        if experiment_id == 0:
            SECRET_KEY = 0x123456789ABC
            UID = 0x01234567
            COUNTER = 0x0000000
            BTN = 0x3
            AMOUNT_TRACES = 10
            DISTANCE_COUNTER = 10
        elif experiment_id == 1:
            SECRET_KEY = 0xABCDEF123456
            UID = 0x89ABCDEF
            COUNTER = 0x0000000
            BTN = 0x1
            AMOUNT_TRACES = 10
            DISTANCE_COUNTER = 10
        elif experiment_id == 2:
            SECRET_KEY = 0x123456789ABC
            UID = 0x01234567
            COUNTER = 0x0000000
            BTN = 0x3
            AMOUNT_TRACES = 20
            DISTANCE_COUNTER = 10
        elif experiment_id == 3:
            SECRET_KEY = 0x123456789ABC
            UID = 0x01234567
            COUNTER = 0x0000000
            BTN = 0x3
            AMOUNT_TRACES = 8
            DISTANCE_COUNTER = 1
        if experiment_id == 4:
            SECRET_KEY = 0x276359283601
            UID = 0x01234567
            COUNTER = 0x0000000
            BTN = 0x3
            AMOUNT_TRACES = 10
            DISTANCE_COUNTER = 10
        elif experiment_id == 5:
            SECRET_KEY = 0xABCDEF123456
            UID = 0x89ABCDEF
            COUNTER = 0x0000000
            BTN = 0x1
            AMOUNT_TRACES = 10
            DISTANCE_COUNTER = 5627726
        elif experiment_id == 6:
            SECRET_KEY = 0xABCDEF123456
            UID = 0x89ABCDEF
            COUNTER = 0xAAAAAAA
            BTN = 0x1
            AMOUNT_TRACES = 10
            DISTANCE_COUNTER = 10

        ivs = []
        for i in range(AMOUNT_TRACES):
            counter = COUNTER + (i*DISTANCE_COUNTER)
            iv = counter << 4 | BTN
            ivs.append(iv)
        all_traces = []
        for i in range(AMOUNT_TRACES):
            all_traces.append(generate_trace(SECRET_KEY, UID, ivs[i]))
        return all_traces, SECRET_KEY

if __name__ == "__main__":

    start = time.time()
    os.system('cls') # clear console output
    # Check if folder out exists, 
    #    if not: create it, 
    #    if it does exist: remove all files in it to have a clean output for each run
    if not os.path.exists("out"):
        os.makedirs("out")
    else:
        for filename in os.listdir("out"):
            file_path = os.path.join("out", filename)
            if os.path.isfile(file_path):
                os.unlink(file_path)


    ###### Generate traces used for scoring the guesses #####
    all_traces, SECRET_KEY = experiment_traces(0)

    # print all traces
    print("[*] Generated traces")
    for i, trace in enumerate(all_traces):
        print(f"  Trace {i}: UID={hex(trace['uid'])}, IV={hex(trace['iv'])}, KS={trace['ks']:032b}")

    ##### Precalculation #####
    # precapculate the probability table for the f20 function and the window table for determining which taps
    #   are known for each window configuration. This allows to speed up the attack.
    window_table = precalculate_window_table()
    prob_table = precalculate_probability_table()
    
    
    ####### Attack ######
    #
    #   garcia_attack_step1_2_3 contains the first round of Steps 1,2 and 3
    #   garcia_attack_step4_5 contains the loop for step 5, where the window is extended and Steps 1,2,3 and 4 are repeated again
    #   garcia_attack_step6 contains the final step to guess the remaining 16 bits of the key for the top candidates (not in the paper)
    #
    candidates = garcia_attack_step1_2_3(all_traces, prob_table, window_table, SECRET_KEY)
    final_candidates = garcia_attack_step4_5(candidates, all_traces, prob_table, window_table, SECRET_KEY)
    #can be used for debugging to read in the candidates from the last step
    #final_candidates = read_candidates("out/candidates_step5_32_window.txt") # if you want to read the candidates from file instead of running the attack steps again
    recovered_key = garcia_attack_step6(final_candidates, all_traces)

    print("[*] done")

    minutes = int((time.time() - start) // 60)
    seconds = int((time.time() - start) % 60)
    print(f"Total execution time: {minutes} minutes and {seconds} seconds")