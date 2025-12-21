from flask import Flask, render_template, request
import hashlib

app = Flask(__name__)

# Vocabulary Mapping
BITS_TO_WORD = {0: "tamjeed", 1: "biri", 2: "tala", 3: "khai"}
WORD_TO_BITS = {v: k for k, v in BITS_TO_WORD.items()}

def get_subkeys(main_key):
    """Generates 8 unique subkeys from a master passphrase."""
    subkeys = []
    seed = int(hashlib.sha256(str(main_key).encode()).hexdigest(), 16)
    for _ in range(8):
        seed = (1103515245 * seed + 12345) % (2**31)
        subkeys.append(seed % 16)
    return subkeys

def round_function(right_half, subkey):
    mix = ((right_half + subkey) ** 2)
    return (mix ^ (mix >> 4)) & 0xF

def process_byte(byte_val, subkeys, decrypt=False):
    left, right = (byte_val >> 4) & 0xF, byte_val & 0xF
    active_keys = subkeys[::-1] if decrypt else subkeys
    for key in active_keys:
        left, right = right, left ^ round_function(right, key)
    return (right << 4) | left

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    action_type = ""
    
    if request.method == 'POST':
        text = request.form.get('text', '')
        password = request.form.get('password', 'default')
        action = request.form.get('action')
        
        main_key = sum(ord(c) for c in password)
        subkeys = get_subkeys(main_key)
        
        if action == 'encrypt':
            encoded_words = []
            for char in text:
                enc_byte = process_byte(ord(char), subkeys)
                for i in range(3, -1, -1):
                    encoded_words.append(BITS_TO_WORD[(enc_byte >> (i * 2)) & 0b11])
            result = " ".join(encoded_words)
            action_type = "Encrypted Message"
            
        elif action == 'decrypt':
            try:
                words = text.strip().split()
                chars = []
                for i in range(0, len(words), 4):
                    byte_val = 0
                    for j, word in enumerate(words[i:i+4]):
                        byte_val |= (WORD_TO_BITS[word.lower()] << ((3 - j) * 2))
                    chars.append(chr(process_byte(byte_val, subkeys, decrypt=True)))
                result = "".join(chars)
                action_type = "Decrypted Message"
            except Exception:
                result = "Error: Invalid cipher text or incorrect password."

    return render_template('index.html', result=result, action_type=action_type)

if __name__ == '__main__':
    app.run(debug=True)
