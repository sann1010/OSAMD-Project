from pymisp import PyMISP
from opensearchpy import OpenSearch
import time
import json
from datetime import datetime

# MISP Configuration
misp_url = 'https://192.168.64.3'
misp_key = 'eUyROKNWX7gFmPnyDjxqvFs8GCQ5zLVmC7fvRzmG'
misp_verifycert = False

# OpenSearch Configuration
opensearch_host = 'https://192.168.64.5:9200'
opensearch_auth = ('admin', 'Strongpassword@1234')
log_indexes = ['windows-logs*', 'linux-logs*', 'firewall-logs*']  
threat_index = 'misp-threat-matches' 
output_file = 'threat_matches.log'  

# Initialize MISP and OpenSearch clients
misp = PyMISP(misp_url, misp_key, misp_verifycert)
client = OpenSearch(
    [opensearch_host],
    http_auth=opensearch_auth,
    use_ssl=True,
    verify_certs=False
)

# Function to fetch IoCs from MISP
def fetch_misp_iocs():
    iocs = {}
    events = misp.search(controller='events', return_format='json')
    for event in events:
        event_data = event.get("Event", {})
        if "Attribute" in event_data:
            for attr in event_data["Attribute"]:
                attr_type = attr.get("type", "unknown")
                attr_value = attr.get("value", "")
                if attr_value:  # Only add non-empty values
                    iocs[attr_value] = {
                        "type": attr_type,
                        "category": attr.get("category", ""),
                        "event_id": event_data.get("id", ""),
                        "event_description": event_data.get("info", "")
                    }
    return iocs

# Function to search logs from the last 5 minutes and match IoCs
def search_and_match_logs(iocs, indexes):
    # Query logs from the last 5 minutes
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "now-1m/m",  
                    "lte": "now"        
                }
            }
        }
    }
    
    # Use a multi-index search with index patterns
    response = client.search(
        index=",".join(indexes),  
        body=query,
        scroll='2m',  
        size=1000     
    )
    
    scroll_id = response['_scroll_id']
    matched_logs = []

    while True:
        # Process each batch of logs
        hits = response['hits']['hits']
        if not hits:
            break

        for hit in hits:
            log = hit['_source']
            log_id = hit['_id']
            log_index = hit['_index']  

            # Define fields to check based on index pattern
            fields_to_check = []
            if log_index.startswith('windows-logs'):
                fields_to_check = [
                    log.get('winlog.event_data.SourceIp', ''),
                    log.get('winlog.event_data.DestinationIp', ''),
                    log.get('winlog.event_data.TargetFilename', ''),
                    log.get('winlog.event_data.HashSHA256', '')
                ]
            elif log_index.startswith('linux-logs'):
                fields_to_check = [
                    log.get('source.ip', ''),
                    log.get('destination.ip', ''),
                    log.get('file.name', ''),
                    log.get('file.hash.sha256', '')
                ]
            elif log_index.startswith('firewall-logs'):
                fields_to_check = [
                    log.get('src_ip', ''),         
                    log.get('dst_ip', ''),         
                    log.get('file.hash.sha256', '')                 ]

            # Check specific fields for IoC matches
            for field_value in fields_to_check:
                if isinstance(field_value, str) and field_value in iocs:
                    # Enrich log with IoC details
                    log['ioc_match'] = {
                        "value": field_value,
                        "type": iocs[field_value]["type"],
                        "category": iocs[field_value]["category"],
                        "misp_event_id": iocs[field_value]["event_id"],
                        "misp_event_description": iocs[field_value]["event_description"],
                        "source_index": log_index   
                    }
                    matched_logs.append((log_id, log))
                    break  

        # Fetch the next batch using scroll
        response = client.scroll(scroll_id=scroll_id, scroll='2m')
    
    # Clear the scroll context
    client.clear_scroll(scroll_id=scroll_id)
    return matched_logs

# Function to index matched logs into OpenSearch and write to file
def index_matched_logs(matched_logs, target_index, output_file):
    indexed_count = 0
    with open(output_file, 'a') as f:  
        for log_id, log in matched_logs:
            # Index into OpenSearch
            client.index(
                index=target_index,
                body=log,
                id=log_id  
            )
            indexed_count += 1
            
            # Write to file with timestamp
            timestamp = datetime.now().isoformat()
            log_entry = {
                "timestamp": timestamp,
                "log_id": log_id,
                "log_data": log
            }
            f.write(json.dumps(log_entry) + '\n')  
    return indexed_count

# Main loop to continuously monitor logs
def main():
    print("Starting IoC monitoring from MISP and OpenSearch logs (last 5 minutes)...")
    while True:
        try:
            # Step 1: Fetch IoCs from MISP
            print("Fetching IoCs from MISP...")
            iocs = fetch_misp_iocs()
            print(f"Loaded {len(iocs)} IoCs from MISP.")

            # Step 2: Search logs from the last 5 minutes and match IoCs
            print(f"Searching logs from the last 5 minutes in indexes: {log_indexes}")
            matched_logs = search_and_match_logs(iocs, log_indexes)
            print(f"Found {len(matched_logs)} logs with IoC matches.")

            # Step 3: Index matched logs and write to file
            if matched_logs:
                indexed_count = index_matched_logs(matched_logs, threat_index, output_file)
                print(f"Indexed {indexed_count} matched logs into '{threat_index}' and wrote to '{output_file}'.")
            else:
                print("No IoC matches found in this cycle.")

            # Wait before the next cycle (e.g., 1 minute)
            time.sleep(60)

        except Exception as e:
            print(f"Error in monitoring loop: {e}")
            time.sleep(60)  # Wait before retrying on error

if __name__ == "__main__":
    main()