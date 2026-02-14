from cryptography.fernet import Fernet
import base64
import hashlib
from flask import Flask, render_template, request, send_file
import os
from PIL import Image
import numpy as np

app = Flask(__name__, static_folder='statics', static_url_path='/statics')
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def render_response(content):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #eef2f7; color: #333; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }}
            h2 {{ color: #005a9c; margin-bottom: 20px; }}
            a {{ color: #007bff; text-decoration: none; font-size: 1.1rem; margin-top: 15px; display: inline-block; }}
            img {{ max-width: 100%; height: auto; margin-bottom: 15px; }}
            p {{ word-break: break-word; white-space: pre-wrap; background: #f8f9fa; padding: 10px; border-radius: 5px; text-align: left; }}
            .container {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); text-align: center; width: 100%; max-width: 450px; }}
        </style>
    </head>
    <body>
        <div class="container">
            {content}
        </div>
    </body>
    </html>
    """

# Generate key from password
def generate_key(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

# Encrypt (supports bytes or string)
def encrypt_message(data, password):
    key = generate_key(password)
    f = Fernet(key)
    if isinstance(data, str):
        data = data.encode()
    return f.encrypt(data)

# Decrypt (returns bytes)
def decrypt_message(encrypted_data, password):
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted_data)

# Hide data in image using LSB
def hide_data(image_path, secret_data, output_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    arr = np.array(img)

    # Convert bytes to string for LSB
    if isinstance(secret_data, bytes):
        secret_data = ''.join(format(byte, '08b') for byte in secret_data)
    else:
        secret_data = ''.join(format(ord(i), '08b') for i in secret_data)

    data_index = 0
    total_bits = len(secret_data)

    for row in arr:
        for pixel in row:
            for i in range(3):  # R,G,B
                if data_index < total_bits:
                    pixel[i] = (pixel[i] & 254) | int(secret_data[data_index])
                    data_index += 1

    new_img = Image.fromarray(arr)
    new_img.save(output_path)

# Extract LSB data from image
def extract_data(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    arr = np.array(img)

    binary_data = ""
    decoded_data = ""

    for row in arr:
        for pixel in row:
            for i in range(3):
                binary_data += str(pixel[i] & 1)
                if len(binary_data) >= 8:
                    byte = binary_data[:8]
                    binary_data = binary_data[8:]
                    decoded_data += chr(int(byte, 2))
                    if decoded_data.endswith("#####"):
                        return decoded_data[:-5]
    return decoded_data

# ----------------- Flask Routes -----------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    image = request.files.get('image')
    message = request.form.get('message')
    document = request.files.get('document')
    password = request.form.get('password')

    if not image or image.filename == '' or not password or password.strip() == '':
        return render_response("<h3>Missing input.</h3><a href='/'>Go Back</a>")

    # Prepare data
    if document and document.filename != '':
        file_bytes = document.read()
        file_name = document.filename
        data_to_hide = file_name.encode() + b"::FILE::" + file_bytes
    elif message and message.strip() != '':
        data_to_hide = message.encode()
    else:
        return render_response("<h3>No message or document provided.</h3><a href='/'>Go Back</a>")

    # Encrypt
    encrypted_data = encrypt_message(data_to_hide, password)

    # Save uploaded image
    image_path = os.path.join(UPLOAD_FOLDER, image.filename)
    image.save(image_path)

    output_path = os.path.join(UPLOAD_FOLDER, "pixeltomb_encoded.png")
    hide_data(image_path, encrypted_data, output_path)

    return render_response("""
    <h2>Message Hidden Successfully!</h2>
    <a href="/download">Download Encoded Image</a>
    """)


@app.route('/decode', methods=['GET', 'POST'])
def decode():
    if request.method == 'GET':
        return render_template('decode.html')

    image = request.files.get('image')
    password = request.form.get('password')

    if not image or image.filename == '' or not password or password.strip() == '':
        return render_response("<h3>Missing input.</h3><a href='/decode'>Go Back</a>")

    image_path = os.path.join(UPLOAD_FOLDER, image.filename)
    image.save(image_path)

    try:
        extracted_data = extract_data(image_path)
        decrypted_data = decrypt_message(extracted_data.encode(), password)
    except Exception:
        return render_response("<h3>Wrong password or corrupted image.</h3><a href='/decode'>Try Again</a>")

    # Check if file or text
    if b"::FILE::" in decrypted_data:
        filename, filecontent = decrypted_data.split(b"::FILE::")
        output_file_path = os.path.join(UPLOAD_FOLDER, filename.decode())
        with open(output_file_path, "wb") as f:
            f.write(filecontent)
        return render_response(f"""
        <img src="/statics/pixeltomb.png" alt="PIXEL-TOMB Logo" width="100" height="100">
        <h2>File Extracted Successfully!</h2>
        <a href="/download_file/{filename.decode()}">Download File</a>
        """)
    else:
        return render_response(f"""
        <img src="/statics/pixeltomb.png" alt="PIXEL-TOMB Logo" width="100" height="100">
        <h2>Decoded Message:</h2>
        <p>{decrypted_data.decode()}</p>
        <a href="/">Go Back</a>
        """)

@app.route('/download')
def download():
    return send_file(os.path.join(UPLOAD_FOLDER, "pixeltomb_encoded.png"), as_attachment=True)

@app.route('/download_file/<filename>')
def download_file(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

if __name__ == '__main__':
    #app.run(debug=True)
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
