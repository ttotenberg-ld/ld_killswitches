import requests
import json
import os
import logging
from dotenv import load_dotenv
import csv
from datetime import datetime, timedelta
from collections import defaultdict
import time
import re
import copy # Needed for deep copying headers for safe logging

# Configuration constants
PROJECT = "*"  # The project to search for audit log entries. Use "*" to search all projects
SEARCH_DATE = 1743551530000  # Earliest date to search for audit log entries, in epoch milliseconds. You can find a converter here: https://www.epochconverter.com/

# Set up logging for better debugging and monitoring
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file for secure configuration
load_dotenv()
logging.info("Environment variables loaded")

# Define LaunchDarkly API endpoints
base_url = "https://app.launchdarkly.com"
api_url_auditlog = "/api/v2/auditlog"
url = base_url + api_url_auditlog

# Retrieve API key from environment variable for security
api_key = os.getenv('LAUNCHDARKLY_API_KEY')
if not api_key:
    logging.error("LAUNCHDARKLY_API_KEY not found in environment variables")
    exit(1)
logging.info("API key retrieved from environment variables")

# Set up headers for API requests
headers = {
  'Authorization': f'{api_key}',
  'Content-Type': 'application/json'
}

# Initial payload for finding "turned off" events
initial_payload = json.dumps([
  {
    "resources": [
      f"proj/{PROJECT}:env/production:flag/*"
    ],
    "effect": "allow",
    "actions": [
      "updateOn"  # This action covers both turning on and off
    ]
  }
])

# API and processing configuration
limit = 20  # Number of items per page in API response for the initial scan
batch_size = 50 # Number of "turned off" items to collect before processing and writing

def extract_project_key(site_href):
    """
    Extract the project key from the site href, trying various known patterns.

    Args:
    site_href (str): The site href from the API response (_links.parent.href or _links.site.href)

    Returns:
    str: The extracted project key or an empty string if not found
    """
    if not site_href:
        return ''
        
    # Define patterns, from more specific/common to less specific
    # Order matters!
    patterns = [
        # Pattern 1: Matches site hrefs like /proj-key/production/features/flag-key
        r'^/([^/]+)/[^/]+/features/', 
        # Pattern 2: Matches site hrefs like /projects/proj-key/flags/flag-key
        r'/projects/([^/]+)/flags/',  
         # Pattern 3: Matches parent hrefs like /api/v2/flags/proj-key/flag-key
        r'/flags/([^/]+)/',          
        # Pattern 4: Fallback for general /projects/proj-key/... links
        r'/projects/([^/]+)/'       
    ]

    for pattern in patterns:
        match = re.search(pattern, site_href)
        if match:
            extracted_key = match.group(1)
            # Basic sanity check to avoid matching common API path segments
            if extracted_key not in ["api", "members", "settings", "account", "auditlog", "flags"]:
                logging.debug(f"Extracted project key '{extracted_key}' using pattern '{pattern}' from href: {site_href}")
                return extracted_key
            else:
                logging.debug(f"Pattern '{pattern}' matched non-project key '{extracted_key}' in href: {site_href}. Trying next pattern.")
        # else: Keep trying other patterns

    logging.warning(f"Could not extract project key using any known pattern from href: {site_href}")
    return ''

def extract_flag_key_from_href(href):
    """
    Extract the flag key from a LaunchDarkly API href.
    Assumes format like /api/v2/flags/{project_key}/{flag_key}
    
    Args:
    href (str): The href string.
    
    Returns:
    str: The extracted flag key or an empty string if not found or format mismatch.
    """
    if not href:
        return ''
    # Match the last segment after /flags/{project_key}/
    match = re.search(r'/flags/[^/]+/([^/?]+)', href)
    if match:
        return match.group(1)
    else:
        # Changed to debug level to reduce noise for expected non-matching parent_href like /api/v2/auditlog
        logging.debug(f"Could not extract flag key from href (expected '/flags/project/key...'): {href}") 
        return ''

def extract_flag_key_from_site_href(site_href):
    """
    Extract the flag key from a LaunchDarkly UI site href.
    Assumes format like .../features/{flag_key}...
    
    Args:
    site_href (str): The site href string.
    
    Returns:
    str: The extracted flag key or an empty string if not found or format mismatch.
    """
    if not site_href:
        return ''
    # Updated regex to match the segment after /features/
    match = re.search(r'/features/([^/?]+)', site_href)
    if match:
        flag_key = match.group(1)
        logging.debug(f"Extracted flag key '{flag_key}' from site_href: {site_href}")
        return flag_key
    else:
        logging.debug(f"Could not extract flag key from site_href format (expected '/features/...'): {site_href}")
        return ''

def get_turn_on_details(flag_key, project_key, turn_off_timestamp_ms):
    """
    Find the single most recent 'turned on' event for a specific flag before a given timestamp.
    Relies on the API returning the correct event with limit=1 based on payload filter.
    
    Args:
    flag_key (str): The key of the flag.
    project_key (str): The key of the project.
    turn_off_timestamp_ms (int): The timestamp (in ms) when the flag was turned off.

    Returns:
    int: The timestamp (in ms) when the flag was turned on, or None if not found.
    """
    logging.debug(f"Searching for SINGLE most recent 'turn on' event for flag '{flag_key}' before {turn_off_timestamp_ms}")
    
    if not flag_key or not project_key:
        logging.warning(f"Missing flag_key ('{flag_key}') or project_key ('{project_key}') for 'turn on' search. Skipping.")
        return None

    target_url = base_url + api_url_auditlog

    try:
        resource_string = f"proj/{project_key}:env/production:flag/{flag_key}"
        payload = json.dumps([
            {
                "resources": [resource_string],
                "effect": "allow",
                "actions": ["updateOn"]
            }
        ])
    except Exception as e:
        logging.error(f"Error constructing payload for flag '{flag_key}', project '{project_key}': {e}")
        return None
    
    params = {
        'limit': 1,
        'before': turn_off_timestamp_ms
    }

    # --- Detailed Request Logging --- 
    # Mask API key for safety
    logged_headers = copy.deepcopy(headers)
    if 'Authorization' in logged_headers:
        logged_headers['Authorization'] = 'api-key-masked' 
    logging.debug(f"--- Turn On Details Request --- F:{flag_key}")
    logging.debug(f"URL: {target_url}")
    logging.debug(f"PARAMS: {params}")
    logging.debug(f"HEADERS: {logged_headers}")
    logging.debug(f"PAYLOAD: {payload}")
    # --- End Detailed Request Logging ---

    try:
        response = requests.post(target_url, headers=headers, params=params, data=payload)
        
        # --- Detailed Response Logging --- 
        logging.debug(f"--- Turn On Details Response --- F:{flag_key}")
        logging.debug(f"STATUS CODE: {response.status_code}")
        # Limit response text logging length in case it's huge
        response_text_snippet = response.text[:1000] + ('...' if len(response.text) > 1000 else '')
        logging.debug(f"RESPONSE TEXT: {response_text_snippet}")
        # --- End Detailed Response Logging ---

        if response.status_code == 400:
            # Error already logged above, just return None
            # Log full text again here specifically for 400 error context if needed
            # logging.error(f"400 Bad Request full response text: {response.text}") 
            return None 
        else:
            response.raise_for_status()

        data = response.json()
        items = data.get('items', [])

        if items:
            first_item = items[0]
            if first_item.get('titleVerb') == 'turned on the flag':
                turn_on_timestamp_ms_found = first_item.get('date')
                if turn_on_timestamp_ms_found:
                     logging.debug(f"Found 'turn on' event for '{flag_key}' at {turn_on_timestamp_ms_found}")
                     return turn_on_timestamp_ms_found
                else:
                    logging.warning(f"'Turned on' event found for '{flag_key}', but it lacked a date.")
                    return None 
            else:
                found_verb = first_item.get('titleVerb', 'N/A')
                found_date = first_item.get('date', 'N/A')
                logging.info(f"Most recent event matching payload for '{flag_key}' before {turn_off_timestamp_ms} was not 'turned on'. Found verb: '{found_verb}' at date: {found_date}.")
                return None
        else:
            logging.info(f"No event found matching payload criteria for '{flag_key}' before {turn_off_timestamp_ms}.")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching 'turn on' details for flag '{flag_key}': {e}")
        return None
    except json.JSONDecodeError as e:
        # Log the problematic text that couldn't be decoded
        logging.error(f"Error decoding JSON response for flag '{flag_key}': {e}. Response text snippet: {response_text_snippet}")
        return None


def process_batch(batch, csv_writer):
    """
    Process a batch of audit log entries, find corresponding 'turn on' events,
    calculate durations, and write to CSV.

    Args:
    batch (list): List of audit log entries to process (expecting 'turned off' events)
    csv_writer (csv.DictWriter): CSV writer object to write results

    Returns:
    int: Number of 'turned off' entries processed and written to CSV
    """
    processed_count = 0
    for entry in batch:
        if entry.get('titleVerb') == 'turned off the flag':
            flag_name = entry.get('name', '')
            links = entry.get('_links', {})
            parent_href = links.get('parent', {}).get('href', '')
            site_href_raw = links.get('site', {}).get('href', '')
            
            # --- Flag Key Extraction (Existing Logic - Seems OK) ---
            flag_key = extract_flag_key_from_href(parent_href)
            if not flag_key:
                logging.debug(f"Flag key not found in parent_href ('{parent_href}'), trying site_href ('{site_href_raw}') for flag '{flag_name}'")
                flag_key = extract_flag_key_from_site_href(site_href_raw)
            if not flag_key:
                logging.warning(f"Could not determine flag key for entry with name '{flag_name}' from parent_href ('{parent_href}') or site_href ('{site_href_raw}'). Skipping.")
                continue
            
            # --- Project Key Extraction (Revised Logic) ---
            project_key = ''
            # Try parent_href ONLY if it looks like it contains the flag key structure
            if parent_href and '/flags/' in parent_href: 
                logging.debug(f"Attempting project key extraction from parent_href: {parent_href}")
                project_key = extract_project_key(parent_href)
                if project_key:
                    logging.debug(f"Successfully extracted project key '{project_key}' from parent_href.")
                else:
                    logging.debug(f"Failed to extract project key from parent_href ('{parent_href}'), will try site_href.")
            else:
                 logging.debug(f"Parent_href ('{parent_href}') does not contain '/flags/', skipping direct project key extraction from it.")

            # If project_key wasn't found via parent_href, try site_href_raw
            if not project_key:
                logging.debug(f"Attempting project key extraction from site_href_raw: {site_href_raw}")
                project_key = extract_project_key(site_href_raw) 
                if project_key:
                     logging.debug(f"Successfully extracted project key '{project_key}' from site_href_raw.")
                else:
                    # This is the final failure point for project key
                    logging.warning(f"Could not determine project key for entry with name '{flag_name}' from parent_href ('{parent_href}') or site_href ('{site_href_raw}'). Using fallback 'unknown'.")
                    project_key = 'unknown' # Assign a placeholder if absolutely needed, or handle differently

            # --- End Project Key Extraction --- 
                
            turn_off_timestamp_ms = entry.get('date')
            turn_off_date_str = datetime.fromtimestamp(turn_off_timestamp_ms / 1000).strftime('%Y-%m-%d %H:%M:%S') if turn_off_timestamp_ms else ''

            member = entry.get('member', {})
            first_name = member.get('firstName', '')
            last_name = member.get('lastName', '')
            email = member.get('email', '')
            comment = entry.get('comment', '')
            
            site_href = f"https://app.launchdarkly.com/projects/{project_key}/flags/{flag_key}/targeting/production" if project_key != 'unknown' and flag_key else site_href_raw

            turn_on_timestamp_ms = None
            turn_on_date_str = 'N/A'
            duration_seconds = 'N/A'

            if flag_key and project_key != 'unknown' and turn_off_timestamp_ms:
                 turn_on_timestamp_ms = get_turn_on_details(flag_key, project_key, turn_off_timestamp_ms)
                 if turn_on_timestamp_ms:
                     turn_on_date_str = datetime.fromtimestamp(turn_on_timestamp_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')
                     duration_seconds = (turn_off_timestamp_ms - turn_on_timestamp_ms) / 1000
                     logging.info(f"Flag '{flag_name}' (key: '{flag_key}'): Off at {turn_off_date_str}, On at {turn_on_date_str}, Duration: {duration_seconds:.2f}s")
                 else:
                     logging.info(f"Could not find 'turn on' details for flag '{flag_name}' (key: '{flag_key}')")
            
            result = {
                'flag_key': flag_key,
                'flag_name': flag_name,
                'site_href': site_href,
                'turn_off_date': turn_off_date_str,
                'turn_on_date': turn_on_date_str,
                'duration_seconds': f"{duration_seconds:.2f}" if isinstance(duration_seconds, (int, float)) else duration_seconds,
                'turned_off_by_first_name': first_name,
                'turned_off_by_last_name': last_name,
                'turned_off_by_email': email,
                'project_key': project_key,
                'comment': comment
            }
            csv_writer.writerow(result)
            processed_count += 1

    return processed_count

# Define CSV fieldnames including new fields
fieldnames = [
    'flag_key', 'flag_name', 'site_href', 'turn_off_date', 'turn_on_date', 'duration_seconds',
    'turned_off_by_first_name', 'turned_off_by_last_name', 'turned_off_by_email',
    'project_key', 'comment'
]

# Clear the CSV file and write the header
output_filename = 'flag_off_durations.csv'
try:
    with open(output_filename, 'w', newline='') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        csv_writer.writeheader()
    logging.info(f"Initialized CSV file: {output_filename}")
except IOError as e:
    logging.error(f"Error opening or writing header to CSV file {output_filename}: {e}")
    exit(1)


# Set initial date to current timestamp (in milliseconds)
current_scan_timestamp_ms = round(time.time() * 1000)
total_processed = 0
current_batch = []
current_url = url # Use a different variable for the pagination URL

# Fetch audit log entries until reaching the SEARCH_DATE or end of data
try:
    with open(output_filename, 'a', newline='') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        while current_scan_timestamp_ms > SEARCH_DATE:
            params = {
                'limit': limit,
                # Use 'before' parameter for pagination based on timestamp
                'before': current_scan_timestamp_ms
            }

            logging.info(f"Requesting audit logs before {datetime.fromtimestamp(current_scan_timestamp_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')}")
            try:
                # Make POST request to LaunchDarkly API using the initial payload
                response = requests.post(current_url, headers=headers, params=params, data=initial_payload)
                response.raise_for_status()

                data = response.json()
                items = data.get('items', [])
                logging.info(f"Received {len(items)} audit log items")

                if not items:
                    logging.info("No more items found in the specified date range.")
                    break

                # Filter for 'turned off' events and add to batch
                turned_off_items = [item for item in items if item.get('titleVerb') == 'turned off the flag']
                current_batch.extend(turned_off_items)
                logging.info(f"Added {len(turned_off_items)} 'turned off' items to batch. Batch size: {len(current_batch)}")

                # Process batch if it reaches the specified size
                if len(current_batch) >= batch_size:
                    processed = process_batch(current_batch, csv_writer)
                    total_processed += processed
                    logging.info(f"Processed and wrote {processed} entries to CSV. Total processed: {total_processed}")
                    current_batch = [] # Clear the batch

                # Update the timestamp for the next request to the timestamp of the last item received
                last_item_date = items[-1].get('date')
                if last_item_date:
                     # Subtract 1ms to avoid refetching the last item
                    current_scan_timestamp_ms = last_item_date - 1
                else:
                    # Should not happen if items exist, but break defensively
                    logging.warning("Last item had no date, stopping pagination.")
                    break

                # Check if the oldest item received is older than our search date
                if last_item_date <= SEARCH_DATE:
                    logging.info(f"Oldest item timestamp ({last_item_date}) reached SEARCH_DATE ({SEARCH_DATE}). Stopping.")
                    break

                # Optional: Add a small delay to avoid rate limiting
                # time.sleep(0.1)

            except requests.exceptions.RequestException as e:
                logging.error(f"Error making request: {e}")
                # Optionally implement retries or stop
                break
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON response: {e}. Response text: {response.text}")
                break # Stop processing if response is invalid

        # Process any remaining items in the batch after the loop finishes
        if current_batch:
            processed = process_batch(current_batch, csv_writer)
            total_processed += processed
            logging.info(f"Processed and wrote final {processed} entries to CSV. Total processed: {total_processed}")

except IOError as e:
    logging.error(f"Error opening or writing to CSV file {output_filename} during processing: {e}")


print(f"Extracted and processed {total_processed} 'flag turned off' events and saved to {output_filename}")
