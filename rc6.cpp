#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <math.h>
#include <stdint.h>

using namespace std;

/* --- NOTES ---
word size (w) = 32 bits
num. of rounds (r) = 20.
key length in bytes (b) = not specified.
*/

/* --- FUTURE CHANGES ---
do not hardcore (w) value or (r) value
*/

/* --- BASIC OPERATIONS ---
a + b       integer addition modulo 2^w
a - b       integer subtraction modulo 2^w
a XOR b     bitwise exclusive-or of w-bit words
a * b       integer multiplication modulo 2^w
a << b      rotate the w-bit word a to the left by the amount given by the least significant lg w bits of b
a >> b      rotate the w-bit word a to the right by the amount given by the least significant lg w bits of b
*/

void create_hex_vec(string val, vector<uint8_t> &val_to_hex);

void load_registers(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D, vector<uint8_t> text);
void key_schedule(uint32_t *L, uint32_t *S, int L_Len, int S_Len, int r);
void encrypt_vec(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D, int r, uint32_t *S);
void decrypt_vec(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D, int r, uint32_t *S);

// Testing
void print_vec(vector<uint8_t> hex_val);
void print_key_list(uint32_t *key_array, int len);
void print_reg(uint32_t A, uint32_t B, uint32_t C, uint32_t D);

// Results
void print_output(uint32_t A, uint32_t B, uint32_t C, uint32_t D, vector<uint8_t> &text, vector<uint8_t> &key, int enc_dec);
void write_output(uint32_t A, uint32_t B, uint32_t C, uint32_t D, ofstream &output_file, int enc_dec);

// Aux functions
uint32_t rotate_left(uint32_t val, uint32_t offset);
uint32_t rotate_right(uint32_t val, uint32_t offset);

int main(int argc, char const *argv[]) {
    string inputfile  = "", 
           outputfile = "", 
           line       = "";

    // 20 (r) rounds
    int r = 20;
    // 32 (w) = word size
    int w = 32;
    // key len (b) initially not given
    int b = 0;

    // 32 (w) bit registers
    uint32_t A = 0,
             B = 0,
             C = 0,
             D = 0;

    vector<uint8_t> text,
                    userkey;

    int linecount = 0;
    bool encrypt  = 0;
    bool decrypt  = 0;

    if (argc != 3) {
        cout << "Incorrect command line args." << endl;
        return 1;
    }
    
    inputfile  = argv[1];
    outputfile = argv[2];
    inputfile.erase(0,2);
    outputfile.erase(0,2);

    ifstream input;
    ofstream output;
    input.open(inputfile.c_str());
    output.open(outputfile.c_str());
    
    if(!(input.is_open())) {
        cout << "Error opening input file." << endl;
        return 1;
    }

    if(!(output.is_open())) {
        cout << "Error opening output file." << endl;
        return 1;
    }
    while (getline(input, line)) {
        if (linecount == 0) {
            if (line == "Encryption") encrypt = 1;
            else decrypt = 1;
        }
        if (linecount == 1) {
            // remove word 'plaintext:' or 'ciphertext:' that precedes hex values
            if (encrypt) {
                string remove = "plaintext:";
                int index = line.find(remove);
                if (index != string::npos) line.erase(index, remove.length());
                create_hex_vec(line, text);
            } else {
                string remove = "ciphertext:";
                int index = line.find(remove);
                if (index != string::npos) line.erase(index, remove.length());
                create_hex_vec(line, text);
            }
        }
        if (linecount == 2) {
            string remove = "userkey:";
            int index = line.find(remove);
            if (index != string::npos) line.erase(index, remove.length());
            create_hex_vec(line, userkey);
        }
        // userkey is longer than 1 line. Must add these hex values to userkey vector
        if (linecount > 2) {
            create_hex_vec(line, userkey);
        }
        linecount++;
    }

    // number of bytes in key
    b = userkey.size();

    // create key list. Each element is size  32 (w) bits.
    int L_len = b / 4;    
    uint32_t *L = new uint32_t[L_len]();
    
    int S_len = 2 * r + 4;
    uint32_t *S = new uint32_t[S_len]();
    
    // fill in key list. First byte of key stored in LSB of L[0]...
    int key_index = 0;
    int byte_index = 0;
    for (int i = 0, j = 0; i < userkey.size(); i++, j++) {
        if (j > 3) {
            j = 0;
            key_index++;
        }
        uint32_t key  = L[key_index];
        uint32_t byte = userkey.at(i);
        uint32_t mask = 0xFFFFFFFF;
        byte = byte << (8*j);
        uint32_t temp = (mask &= byte);
        key |= temp;
        L[key_index]  = key;
    }

    // create S list. Stores the number of w-bit words that will be generated for the additive round keys.
    key_schedule(L, S, L_len, S_len, r);

    load_registers(A, B, C, D, text);

    if (encrypt) encrypt_vec(A, B, C, D, r, S);
    else decrypt_vec(A, B, C, D, r, S);

    // print_output(A, B, C, D, text, userkey, encrypt);
    write_output(A, B, C, D, output, encrypt);
    
    // test if input was read correctly
    // print_reg(A, B, C, D);
    // print_vec(text);
    // print_vec(userkey);
    // print_key_list(L, L_len);

    delete[] L;
    delete[] S;

    input.close();
    output.close();

    return 0;
}

void create_hex_vec(string line, vector<uint8_t> &val_to_hex) {
    uint32_t temp = 0;
    istringstream ss(line);
    while (ss >> std::hex >> temp) {
        val_to_hex.push_back(int(temp));
    };
};

// first byte of plaintext or ciphertext goes into LSB of A ...
void load_registers(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D, vector<uint8_t> text) {
    uint32_t reg[4] = {A,B,C,D};
    int reg_index = 0;
    int byte_index = 0;
    for (int i = 0, j = 0; i < text.size(); i++, j++) {
        if (j > 3) {
            j = 0;
            reg_index++;
        }
        uint32_t key   = reg[reg_index];
        uint32_t byte  = text.at(i);
        uint32_t mask  = 0xFFFFFFFF;
        byte = byte << (8*j);
        uint32_t temp  = (mask &= byte);
        key |= temp;
        reg[reg_index] = key;
    }
    A = reg[0];
    B = reg[1];
    C = reg[2];
    D = reg[3];
};

void key_schedule(uint32_t *L, uint32_t *S, int L_Len, int S_Len, int r) {
    uint32_t P32 = 0xB7E15163;
    uint32_t Q32 = 0x9E3779B9;
    S[0] = P32;

    for (int i = 1; i < S_Len; i++) {
        S[i] = S[i - 1] + Q32 % (int64_t)pow((double)2, 32);
    }

    uint32_t A = 0,
             B = 0,
             j = 0,
             i = 0;
    int v = 3 * max(L_Len, S_Len);

    for (int s = 1; s <= v; s++) {
        uint32_t temp1 = S[i] + A + B % (int64_t)pow((double)2, 32);;
        S[i] = rotate_left(temp1, 3);
        A = S[i];
        uint32_t temp2 = L[j] + A + B % (int64_t)pow((double)2, 32);;
        L[j] = rotate_left(temp2, A + B);
        B = L[j];
        i = (i + 1) % (S_Len);
        j = (j + 1) % (L_Len);
    }
};

void encrypt_vec(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D, int r, uint32_t *S) {
    B = B + S[0];
    D = D + S[1];
    for (int i = 1; i <= r; i++) {
        uint32_t temp1 = (B * (2 * B + 1) % (int64_t)pow((double)2, 32));
        uint32_t temp2 = (D * (2 * D + 1) % (int64_t)pow((double)2, 32));
        uint32_t offset = (uint32_t)log2(32);
        uint32_t t = rotate_left(temp1, offset);
        uint32_t u = rotate_left(temp2, offset);
        uint32_t temp3 = A^t;
        uint32_t temp4 = C^u;
        A = rotate_left(temp3, u) + S[2 * i];
        C = rotate_left(temp4, t) + S[2 * i + 1];
        uint32_t temp = A;
        A = B;
        B = C;
        C = D; 
        D = temp;
    }
    A = A + S[2 * r + 2];
    C = C + S[2 * r + 3];
};

void decrypt_vec(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D, int r, uint32_t *S) {
    C = C - S[2 * r + 3];
    A = A - S[2 * r + 2];
    for (int i = r; i >= 1; i--) {
        uint32_t tempA = A;
        uint32_t tempB = B;
        uint32_t tempC = C;
        uint32_t tempD = D;
        A = tempD;
        B = tempA;
        C = tempB;
        D = tempC;
        uint32_t temp1 = (D * (2 * D + 1)) % (int64_t)pow((double)2, 32);
        uint32_t temp2 = (B * (2 * B + 1)) % (int64_t)pow((double)2, 32);
        uint32_t offset = log2(32);
        uint32_t u = rotate_left(temp1, offset);
        uint32_t t = rotate_left(temp2, offset);
        uint32_t temp3 = (C - S[2 * i + 1]) % (int64_t)pow((double)2, 32);
        uint32_t temp4 = (A - S[2 * i]) % (int64_t)pow((double)2, 32);
        C = (rotate_right(temp3, t)) ^ u;
        A = (rotate_right(temp4, u)) ^ t;       
    }
    D = D - S[1];
    B = B - S[0];
};


// (w) = 32 is hardcoded here
uint32_t rotate_left(uint32_t val, uint32_t offset){
    uint32_t lsb = log2(32);
    uint32_t mask = 0xFFFFFFFF >> (32 - lsb);
    offset &= mask;
    val = (val << offset) | (val >> (32 - offset));
    return val;
};

// (w) = 32 is hardcoded here
uint32_t rotate_right(uint32_t val, uint32_t offset){
    uint32_t lsb = log2(32);
    uint32_t mask = 0xFFFFFFFF >> (32 - lsb);
    offset &= mask;
    val = (val >> offset) | (val << (32 - offset));
    return val;
};

void print_vec(vector<uint8_t> hex_val) {
    for (vector<uint8_t>::iterator i = hex_val.begin(); i != hex_val.end(); i++){
       cout << setw(2) << setfill('0') << hex << (int)*i << " ";
    };
    cout << endl;
};

void print_key_list(uint32_t* L, int len) {
    for (int i = 0; i < len; i++) {
        cout << "L[" << i << "] " << hex << L[i] << endl;
    }
}

void print_reg(uint32_t A, uint32_t B, uint32_t C, uint32_t D) {
    cout << hex << "A: " << setw(8) << setfill('0') << A << endl;
    cout << hex << "B: " << setw(8) << setfill('0') << B << endl;
    cout << hex << "C: " << setw(8) << setfill('0') << C << endl;
    cout << hex << "D: " << setw(8) << setfill('0') << D << endl;
}

void print_output(uint32_t A, uint32_t B, uint32_t C, uint32_t D, vector<uint8_t> &text, vector<uint8_t> &key, int enc_dec) {
    if (enc_dec == 1) cout << "Encryption" << endl << "plaintext: ";
    else cout << "Decryption" << endl << "ciphertext: ";
    for (vector<uint8_t>::iterator i = text.begin(); i != text.end(); i++){
       cout << setw(2) << setfill('0') << hex << (int)*i << " ";
    };
    cout << endl;
    cout << "userkey: ";
    for (vector<uint8_t>::iterator i = key.begin(); i != key.end(); i++){
       cout << setw(2) << setfill('0') << hex << (int)*i << " ";
    };

    cout << endl;
    if (enc_dec == 1) cout << "ciphertext: ";
    else cout << "plaintext: ";
    cout << hex << setw(2) << setfill('0') << (A & 0xFF) << " " << setw(2) << setfill('0') << ((A >> 8) & 0xFF) << " " << setw(2) << setfill('0') << ((A >> 16) & 0xFF) << " " << setw(2) << setfill('0') << ((A >> 24) & 0xFF) << " "
         << setw(2) << setfill('0') << (B & 0xFF) << " " << setw(2) << setfill('0') << ((B >> 8) & 0xFF) << " " << setw(2) << setfill('0') << ((B >> 16) & 0xFF) << " " << setw(2) << setfill('0') << ((B >> 24) & 0xFF) << " "
         << setw(2) << setfill('0') << (C & 0xFF) << " " << setw(2) << setfill('0') << ((C >> 8) & 0xFF) << " " << setw(2) << setfill('0') << ((C >> 16) & 0xFF) << " " << setw(2) << setfill('0') << ((C >> 24) & 0xFF) << " "
         << setw(2) << setfill('0') << (D & 0xFF) << " " << setw(2) << setfill('0') << ((D >> 8) & 0xFF) << " " << setw(2) << setfill('0') << ((D >> 16) & 0xFF) << " " << setw(2) << setfill('0') << ((D >> 24) & 0xFF) << " " << endl;
};

void write_output(uint32_t A, uint32_t B, uint32_t C, uint32_t D, ofstream &output_file, int enc_dec) {
    if (enc_dec != 1) output_file << "plaintext: ";
    else output_file << "ciphertext: ";
    output_file << hex << setw(2) << setfill('0') << (A & 0xFF) << " " << setw(2) << setfill('0') << ((A >> 8) & 0xFF) << " " << setw(2) << setfill('0') << ((A >> 16) & 0xFF) << " " << setw(2) << setfill('0') << ((A >> 24) & 0xFF) << " "
         << setw(2) << setfill('0') << (B & 0xFF) << " " << setw(2) << setfill('0') << ((B >> 8) & 0xFF) << " " << setw(2) << setfill('0') << ((B >> 16) & 0xFF) << " " << setw(2) << setfill('0') << ((B >> 24) & 0xFF) << " "
         << setw(2) << setfill('0') << (C & 0xFF) << " " << setw(2) << setfill('0') << ((C >> 8) & 0xFF) << " " << setw(2) << setfill('0') << ((C >> 16) & 0xFF) << " " << setw(2) << setfill('0') << ((C >> 24) & 0xFF) << " "
         << setw(2) << setfill('0') << (D & 0xFF) << " " << setw(2) << setfill('0') << ((D >> 8) & 0xFF) << " " << setw(2) << setfill('0') << ((D >> 16) & 0xFF) << " " << setw(2) << setfill('0') << ((D >> 24) & 0xFF) << " " << endl;
};