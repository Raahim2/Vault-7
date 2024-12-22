import requests
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json

def fetch_health_data(url):
    """Fetches the health check data from the given URL."""
    print("\n[Fetching Health Check Data]")
    try:
        response = requests.get(url)
        response.raise_for_status()
        # Check if the response is valid JSON
        try:
            response_json = response.json()
            client_ip = response_json.get("client_ip", "IP not found")
            print(f"Server Detected IP: {client_ip}")
            return client_ip
        except ValueError:
            print("Response is not in valid JSON format.")
            return None
    except requests.RequestException as e:
        print(f"Error fetching health check data: {e}")
        return None

def generate_device_guid(ip):
    """Generates a GUID from the device's IP using AES encryption."""
    key = hashlib.sha256(ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded_ip = pad(ip.encode(), AES.block_size)
    encrypted_ip = cipher.encrypt(padded_ip)
    encoded_ip = base64.b64encode(encrypted_ip).decode('utf-8')
    print(f"\n[GUID Generation]\nIP Address: {ip}\nGenerated GUID: {encoded_ip}")
    return encoded_ip

def send_guid(url, guid):
    """Sends a POST request to the given URL with the device GUID."""
    print("\n[Sending Device GUID]")
    headers = {'Content-Type': 'application/json'}
    json_data = json.dumps({"device_guid": guid})
    try:
        response = requests.post(url, headers=headers, data=json_data)
        response.raise_for_status()
        # Handle response JSON properly
        try:
            print(f"Response: {response.json()}")
        except ValueError:
            print(f"Response is not in valid JSON format.")
    except requests.RequestException as e:
        print(f"Error sending GUID: {e}")

def simulate_getting_token(check_health_url, get_token_url):
    """Simulates the process of getting a token based on the detected IP and GUID."""
    device_ip = fetch_health_data(check_health_url)
    if device_ip:
        device_guid = generate_device_guid(device_ip)
        send_guid(get_token_url, device_guid)

def simulate_getting_token_with_custom_guid(check_health_url, get_token_url):
    """Simulates getting a token with a custom GUID (user provides IP)."""
    ip = input("Enter a custom IP address to generate GUID: ")
    print(f"\n[Generating Custom GUID for IP: {ip}]")
    custom_guid = generate_device_guid(ip)
    send_guid(get_token_url, custom_guid)

def simulate_getting_token_for_files(check_health_url, get_token_url):
    """Simulates the process of getting a token for file detection."""
    device_ip = fetch_health_data(check_health_url)
    if device_ip:
        device_guid = generate_device_guid(device_ip)
        send_guid(get_token_url, device_guid)

def send_message_to_detect(url, token):
    """Sends a POST request with a user-defined message to be detected along with the token."""
    print("\n[Sending Message to Detect]")
    message = input("Enter your message: ")
    
    headers = {'Content-Type': 'application/json'}
    message_data = {"message": message, "token": token}
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(message_data))
        response.raise_for_status()
        # Handle response JSON properly
        try:
            print(f"Response: {response.json()}")
        except ValueError:
            print(f"Response is not in valid JSON format.")
    except requests.RequestException as e:
        print(f"Error sending message: {e}")

def send_signatures_to_detect(url, token):
    """Sends a POST request with signatures to be detected along with the token."""
    print("\n[Sending Signatures to Detect]")
    
    # Input: Expecting a comma-separated list of signatures
    signatures_input = input("Enter your signatures (separated by commas): ")
    
    # Split the input into a list of signatures
    signatures_list = [sig.strip() for sig in signatures_input.split(",")]

    # Create the JSON payload
    message_data = {"signatures": signatures_list, "token": token}

    # Set headers for the request
    headers = {'Content-Type': 'application/json'}
    
    try:
        # Make the POST request
        response = requests.post(url, headers=headers, data=json.dumps(message_data))
        response.raise_for_status()  # Raise an exception for HTTP errors
        # Handle response JSON properly
        try:
            print(f"Response: {response.json()}")
        except ValueError:
            print(f"Response is not in valid JSON format.")
    except requests.RequestException as e:
        print(f"Error sending signatures: {e}")

def main():
    """Main loop for the interactive program."""
    while True:
        print("\n[Menu]")
        print("1. Simulate Getting Token for Message (Use server-detected IP)")
        print("2. Simulate Getting Token with Custom GUID (Enter your own IP)")
        print("3. Simulate Getting Token for File Detection (Use server-detected IP)")
        print("4. Simulate Sending Message to Detect")
        print("5. Simulate Sending Signatures to Detect")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            url = input("Enter the base URL (e.g., https://yourvercelwebsite.com): ")
            check_health_url = url + '/check_health'
            get_token_url = url + '/get_token_for_message'
            simulate_getting_token(check_health_url, get_token_url)
        elif choice == '2':
            url = input("Enter the base URL (e.g., https://yourvercelwebsite.com): ")
            check_health_url = url + '/check_health'
            get_token_url = url + '/get_token_for_message'
            simulate_getting_token_with_custom_guid(check_health_url, get_token_url)
        elif choice == '3':
            url = input("Enter the base URL (e.g., https://yourvercelwebsite.com): ")
            check_health_url = url + '/check_health'
            get_token_url = url + '/get_token_for_files'
            simulate_getting_token_for_files(check_health_url, get_token_url)
        elif choice == '4':
            token = input("Enter the token for your request: ")
            url = input("Enter the base URL (e.g., https://yourvercelwebsite.com): ")
            message_detection_url = url + '/message_detection' 
            send_message_to_detect(message_detection_url, token)
        elif choice == '5':
            token = input("Enter the token for your request: ")
            url = input("Enter the base URL (e.g., https://yourvercelwebsite.com): ")
            signature_detection_url = url + '/malware_detection' 
            send_signatures_to_detect(signature_detection_url, token)
        elif choice == '6':
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
