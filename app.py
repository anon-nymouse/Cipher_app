from flask import Flask, render_template, request
import hashlib
import secrets

app = Flask(__name__)

# Vocabulary Mapping
BITS_TO_WORD = {0: "fadilah", 1: "bigaad", 2: "giya", 3: "haiii"}
WORD_TO_BITS = {v: k for k, v in BITS_TO_WORD.items()}

def get_subkeys(hex_key):
    """Generates 8 unique subkeys from the 1024-bit hex key."""
    subkeys = []
    # Hash the long key to create a starting seed
    seed = int(hashlib.sha256(hex_key.encode()).hexdigest(), 16)
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
    generated_key = ""
    action_type = ""

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'encrypt':
            text = request.form.get('text', '')
            # Generate a 1024-bit key (128 bytes = 256 hex chars)
            generated_key = secrets.token_hex(128)
            subkeys = get_subkeys(generated_key)

            encoded_words = []
            for char in text:
                enc_byte = process_byte(ord(char), subkeys)
                for i in range(3, -1, -1):
                    encoded_words.append(BITS_TO_WORD[(enc_byte >> (i * 2)) & 0b11])

            result = " ".join(encoded_words)
            action_type = "Encrypted Message"

        elif action == 'decrypt':
            text = request.form.get('text', '')
            provided_key = request.form.get('passkey', '').strip()

            if not provided_key:
                result = "Error: You must provide the 1024-bit key to decrypt."
            else:
                try:
                    subkeys = get_subkeys(provided_key)
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
                    result = "Error: Decryption failed. Check your key and word sequence."

    return render_template('index.html', result=result, action_type=action_type, key_out=generated_key)

if __name__ == '__main__':
    app.run(debug=True)
