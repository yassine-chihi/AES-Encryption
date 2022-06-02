rounds_by_key_size = {16:10, 24:12, 32:14}

r_con = ( 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

s_box = (
#    0     1     2     3     4     5     6     7     8     9     A     B     C     D      E    F
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, # 0
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, # 1
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, # 2
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, # 3
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, # 4
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, # 5
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, # 6
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, # 7
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, # 8 
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, # 9
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, # A
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, # B
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, # C
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, # D
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, # E
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16, # F
)

def bytes2matrix(input):
    # using list comprehension to create a list of lists. Each row contains 4 elements.
    return [list(input[i:i+4]) for i in range(0, len(input), 4)]

def matrix2hex(matrix):
    # iterate the matrix and return a hex value without '0x'.
    return ''.join("%02x" % j for i in matrix for j in i)

def xor_bytes(a,b):
    return bytes(i^j for i,j in zip(a,b))

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

# In Galois Field GF(2^8), multiplication by 2 could be implemented as a shift left. 
# And if the result is 8 bit (i.e longer or egal to 128 in decimal), the last bit would be deleted
# by XORing it with 0x11B which is the hexadecimal representation of Rijndeal's GF(2^8)
# reduction polynomial.

def GaloisMul(x,y):
    if y == 1:
        return x
    temp = (x << 1) 
    if y == 2:
        return temp if (x < 128) else temp ^ 0x11b
    if y == 3:
        return GaloisMul(x,2) ^ x

def mix_columns(s):
    for i in range(4):
        temp0,temp1,temp2,temp3 = s[i][0],s[i][1],s[i][2],s[i][3]
        s[i][0] = GaloisMul(temp0,2) ^ GaloisMul(temp1,3) ^ GaloisMul(temp2,1) ^ GaloisMul(temp3,1)
        s[i][1] = GaloisMul(temp0,1) ^ GaloisMul(temp1,2) ^ GaloisMul(temp2,3) ^ GaloisMul(temp3,1)
        s[i][2] = GaloisMul(temp0,1) ^ GaloisMul(temp1,1) ^ GaloisMul(temp2,2) ^ GaloisMul(temp3,3)
        s[i][3] = GaloisMul(temp0,3) ^ GaloisMul(temp1,1) ^ GaloisMul(temp2,1) ^ GaloisMul(temp3,2)

def key_expansion(master_key):
    n_rounds = rounds_by_key_size[len(master_key)]
    # Initialize round keys.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4
    i = 1

    while( len(key_columns) < 4*(n_rounds+1)):
        # Copy previous word.
        word = list(key_columns[-1]) 

        if( len(key_columns) % iteration_size == 0 ):
            # Cyclic left shift(i.e RotWord())
            word.append(word.pop(0))
            word = [s_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i+=1

        elif( len(master_key)==32 and len(key_columns) % iteration_size == 4 ):
            # Run word through S-box in the fourth iteration when using a 256-bit key.
            word = [s_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = xor_bytes( bytes(word) , bytes(key_columns[-iteration_size]) )
        key_columns.append(word)
    
    return [key_columns[ 4*i: 4*(i+1)] for i in range(len(key_columns) // 4 )]

def Encrypt(plaintext,masterkey):
    round_keys = key_expansion(masterkey)
    NbRound=rounds_by_key_size[len(masterkey)]
    
    state = bytes2matrix(plaintext)
    # Initial AddRounKey
    add_round_key(state,round_keys[0])

    for i in range(1,NbRound):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state,round_keys[i])
        
    # The last Round
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state,round_keys[-1])
    return state

def RunTest():
    print("Choose AES key length: ")
    print('1. AES-128')
    print('2. AES-192')
    print('3. AES-256')
    inp = input()
    m = '00112233445566778899aabbccddeeff'
    if inp == '1':
        k = '000102030405060708090A0B0C0D0E0F'
        c = matrix2hex(Encrypt(bytes.fromhex(m),bytes.fromhex(k)))
        print("""\n[Plaintext] = {}\n[Key] = {}\n[Cipher] = {}\n""".format(m,k,c))
    elif inp == '2':
        k = '000102030405060708090A0B0C0D0E0F1011121314151617'
        c = matrix2hex(Encrypt(bytes.fromhex(m),bytes.fromhex(k)))
        print("""\n[Plaintext] = {}\n[Key] = {}\n[Cipher] = {}\n""".format(m,k,c))
    elif inp == '3':
        k = '000102030405060708090A0B0C0D0E0F101112131415161718191a1b1c1d1e1f'
        c = matrix2hex(Encrypt(bytes.fromhex(m),bytes.fromhex(k)))
        print("""\n[Plaintext] = {}\n[Key] = {}\n[Cipher] = {}\n""".format(m,k,c))

if __name__ == "__main__":
    import sys

    banner= """
    ┌───────────────────────────────────────────────┐
    | ┌──(CyberTrace@Advanced)-[~]                  |
    | └─$ ./AesEnc.py [Plaintext] [Key] | RunTest   |
    |                                               |
    |                                               |
    |               By ya$$ine                      |
    └───────────────────────────────────────────────┘
    """
    print(banner)

    if len(sys.argv) == 3:
        print("""\nBoth plaintext and key should be in hexadecimal format without prefixed 0x. Be carful!\n""")
        try:
            msg = bytes.fromhex(sys.argv[1])
            key = bytes.fromhex(sys.argv[2])
            if len(msg) != 16 and (len(key) != 16 or len(key) != 24 or len(key) != 32):
                raise Exception()
            StateBox = Encrypt(msg,key)
            cipher = matrix2hex(StateBox)
            print('[Cipher] : ',cipher)
        except:
            print("[ERROR]: Check your arguments !")

    elif len(sys.argv) == 2 and sys.argv[1] == 'RunTest':
        RunTest()
    else:
        print("""[Usage]: ./AesEnc.py [plaintext] [key] | RunTest""")
    
