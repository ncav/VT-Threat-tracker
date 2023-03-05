import requests
import time

api_key = ""

# List of ransomware groups to track
ransomware_groups = ["Hive", "Conti", "DarkSide", "Play", "Royal"]

# Dictionary to store the latest hash of each ransomware group
latest_hashes = {group: "" for group in ransomware_groups}

def search_samples(api_key, query):
    url = f"https://www.virustotal.com/api/v3/intelligence/search?query={query}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_sample_details(api_key, hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def update_latest_hashes(api_key):
    for group in ransomware_groups:
        query = f"comment:\"{group}\""
        results = search_samples(api_key, query)
        if results is not None:
            latest_hash = results["data"][0]["id"]
            if latest_hash != latest_hashes[group]:
                latest_hashes[group] = latest_hash
                sample_details = get_sample_details(api_key, latest_hash)
                # Save the sample details to a database or file
                # Example: save_sample_details_to_database(sample_details)
                print(f"New sample found for {group}: {latest_hash}")
        else:
            print(f"Error searching for samples for {group}")

while True:
    # Update the latest hashes every hour
    update_latest_hashes(api_key)
    time.sleep(3600)
