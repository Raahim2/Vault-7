from flask import Flask, render_template, request, jsonify
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    return render_template('docs.html')

@app.route('/check_health', methods=['GET'])
def check_health():
    client_ip = request.remote_addr
    response_data = {
        "status": "Server is running OK",
        "client_ip": client_ip
    }
    return jsonify(response_data), 200

@app.route('/get_token', methods=['POST'])
def get_token():
    data = request.get_json()
    if 'device_guid' not in data:
        return jsonify({"error": "Missing device_guid"}), 400  # Fixed error message
    
    client_ip = request.remote_addr
    device_guid = data.get('device_guid')
    key = hashlib.sha256(client_ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    
    try:
        encrypted_ip = base64.b64decode(device_guid)
        decrypted_ip = unpad(cipher.decrypt(encrypted_ip), AES.block_size).decode('utf-8')
        
        if decrypted_ip == client_ip:
            return jsonify({"message": "Valid attempt to get token detected"}), 200
        else:
            return jsonify({"message": "Failed attempt to get token detected"}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
