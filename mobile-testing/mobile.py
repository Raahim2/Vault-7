import requests
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json

device_ip = ''
device_guid = ''

# Function to generate device GUID using AES encryption
def generate_device_guid(ip):
    key = hashlib.sha256(ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded_ip = pad(ip.encode(), AES.block_size)
    encrypted_ip = cipher.encrypt(padded_ip)
    encoded_ip = base64.b64encode(encrypted_ip).decode('utf-8')
    print(f"Generated GUID for {ip}: {encoded_ip}")
    return encoded_ip

# Function to decrypt the GUID and verify it matches the IP
def decrypt_device_guid(guid, ip):
    key = hashlib.sha256(ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_ip = base64.b64decode(guid)
    decrypted_ip = unpad(cipher.decrypt(encrypted_ip), AES.block_size).decode('utf-8')
    print(f"Decrypted GUID: {decrypted_ip}")
    if decrypted_ip == ip:
        print("Decrypted IP matches the original IP")
    else:
        print("Decrypted IP does NOT match the original IP")
    return decrypted_ip

# Function to simulate getting the token
def simulate_getting_token(check_health_url, get_token_url):
    global device_ip
    global device_guid
    response_from_check_health = requests.get(check_health_url)
    if response_from_check_health.status_code == 200:
        response_json = response_from_check_health.json()
        client_ip = response_json.get("client_ip", "IP not found")
        print(f"Client IP detected by server: {client_ip}")
        device_ip = client_ip
        device_guid = generate_device_guid(client_ip)
        decrypt_device_guid(device_guid, client_ip)

        headers = {'Content-Type': 'application/json'}
        json_data = json.dumps({"device_guid": device_guid})
        
        response_from_get_token = requests.post(get_token_url, headers=headers, data=json_data)
        if response_from_get_token.status_code == 200:
            print(f"Successfully sent device GUID to {get_token_url}")
            print(f"Got Response : {response_from_get_token.json()}")
        else:
            print(f"Failed to send device GUID to {get_token_url}. Status code: {response_from_get_token.status_code}")

        # Send a fake GUID to see how the server reacts
        fake_guid = generate_device_guid("1.2.3.4")  # Using a fake IP
        print(f"Generated fake GUID: {fake_guid}")
        fake_json_data = json.dumps({"device_guid": fake_guid})
        
        response_from_fake_attempt = requests.post(get_token_url, headers=headers, data=fake_json_data)
        if response_from_fake_attempt.status_code == 200:
            print(f"Server accepted fake GUID! Response: {response_from_fake_attempt.json()}")
        else:
            print(f"Server rejected fake GUID. Status code: {response_from_fake_attempt.status_code}")
    else:
        print(f"Failed to fetch health check data. Status code: {response_from_check_health.status_code}")

# Main function to run the client
def main():
    url = input("Enter the Vercel website: ")
    check_health_url = url + '/check_health'
    get_token_url = url + '/get_token'
    simulate_getting_token(check_health_url, get_token_url)

if __name__ == "__main__":
    main()
