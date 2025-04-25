import requests
import json
import os
import logging
from dotenv import load_dotenv
import csv
from datetime import datetime, timedelta
from collections import defaultdict, deque
import time
import re
import copy # Needed for deep copying headers for safe logging

# Configuration constants
PROJECT = "*"  # The project to search for audit log entries. Use "*" to search all projects
SEARCH_DATE = 1743551530000  # Earliest date to search for audit log entries, in epoch milliseconds. You can find a converter here: https://www.epochconverter.com/

# Define rollout actions and description substrings
# Start Actions
ACTION_START_ROLLOUT_FALLTHROUGH = "updateFallthroughWithMeasuredRollout"
ACTION_START_ROLLOUT_RULE = "updateRulesWithMeasuredRollout"
SUBSTR_START_ROLLOUT_FALLTHROUGH = "Set a guarded rollout on the default rule"
# For rules, check for either of these substrings based on samples
SUBSTR_START_ROLLOUT_RULE_1 = "Updated a rule with a guarded rollout"
SUBSTR_START_ROLLOUT_RULE_2 = "Started guarded rollout on rule"

# Automatic Stop Actions
ACTION_AUTO_STOP_FALLTHROUGH = "updateFallthrough"
ACTION_AUTO_STOP_RULE = "updateRules"
SUBSTR_AUTO_STOP_FALLTHROUGH = "Reverted the guarded rollout on the default rule"
SUBSTR_AUTO_STOP_RULE = "Reverted the guarded rollout for the rule"

# Manual Stop Actions
ACTION_MANUAL_STOP_FALLTHROUGH = "stopMeasuredRolloutOnFlagFallthrough"
ACTION_MANUAL_STOP_RULE = "stopMeasuredRolloutOnFlagRule"
SUBSTR_MANUAL_STOP_FALLTHROUGH = "Guarded rollout on the default rule was manually reverted"
# No reliable description substring for manual rule stop based on samples - rely on action only

# Define output filenames
OUTPUT_FLAG_DURATION_CSV = 'flag_on_durations.csv'
OUTPUT_ROLLOUT_AUTO_CSV = 'measured_rollout_automatic_rollback.csv'
OUTPUT_ROLLOUT_MANUAL_CSV = 'measured_rollout_manual_rollback.csv'

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
load_dotenv()
logging.info("Environment variables loaded")

# Define LaunchDarkly API endpoints
base_url = "https://app.launchdarkly.com"
api_url_auditlog = "/api/v2/auditlog"
url = base_url + api_url_auditlog

# Retrieve API key
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

# Define actions to filter in the API request
ALL_RELEVANT_ACTIONS = [
    "updateOn", # For flag on/off
    ACTION_START_ROLLOUT_FALLTHROUGH,
    ACTION_START_ROLLOUT_RULE,
    ACTION_AUTO_STOP_FALLTHROUGH,
    ACTION_AUTO_STOP_RULE,
    ACTION_MANUAL_STOP_FALLTHROUGH,
    ACTION_MANUAL_STOP_RULE
]

# Define the initial payload for the POST request
initial_payload = json.dumps([
  {
    "resources": [
      f"proj/{PROJECT}:env/production:flag/*" # Focus on production flags
    ],
    "effect": "allow",
    "actions": ALL_RELEVANT_ACTIONS # Fetch all action types we might need
  }
])

# API and processing configuration
limit = 20  # Number of items per page

# --- Helper Functions ---
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
    patterns = [
        # Matches site hrefs like /proj-key/production/features/flag-key
        r'^/([^/]+)/[^/]+/features/', 
        # Matches site hrefs like /projects/proj-key/flags/flag-key
        r'/projects/([^/]+)/flags/',  
         # Matches parent hrefs like /api/v2/flags/proj-key/flag-key
        r'/flags/([^/]+)/',          
        # Fallback for general /projects/proj-key/... links
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
    match = re.search(r'/features/([^/?]+)', site_href)
    if match:
        flag_key = match.group(1)
        logging.debug(f"Extracted flag key '{flag_key}' from site_href: {site_href}")
        return flag_key
    else:
        logging.debug(f"Could not extract flag key from site_href format (expected '/features/...'): {site_href}")
        return ''

def get_event_details(entry):
    """Extracts common and relevant details from an audit log entry."""
    details = {
        'timestamp': entry.get('date'),
        'flag_name': entry.get('name', ''),
        'description': entry.get('description', ''),
        'comment': entry.get('comment', ''),
        'action': None,
        'member_email': entry.get('member', {}).get('email'), # May be None for API actions
        'project_key': 'unknown',
        'flag_key': 'unknown',
        'site_href_raw': entry.get('_links', {}).get('site', {}).get('href', ''),
        'parent_href': entry.get('_links', {}).get('parent', {}).get('href', ''),
        'titleVerb': entry.get('titleVerb', '')
    }

    # Extract action from the accesses array
    accesses = entry.get('accesses', [])
    if accesses and isinstance(accesses, list) and len(accesses) > 0:
        details['action'] = accesses[0].get('action')

    # Extract flag key (usually works on parent_href or site_href)
    flag_key = extract_flag_key_from_href(details['parent_href'])
    if not flag_key:
        flag_key = extract_flag_key_from_site_href(details['site_href_raw'])
    if flag_key:
        details['flag_key'] = flag_key
    else:
        logging.debug(f"Could not determine flag key for entry at {details['timestamp']}")

    # Extract Project Key
    project_key = ''
    parent_href = details['parent_href']
    site_href_raw = details['site_href_raw']
    
    # Only attempt project key extraction from parent_href if it seems relevant
    if parent_href and ('/flags/' in parent_href or '/projects/' in parent_href):
        logging.debug(f"Attempting project key extraction from relevant parent_href: {parent_href}")
        project_key = extract_project_key(parent_href)
        if project_key:
            logging.debug(f"Successfully extracted project key '{project_key}' from parent_href.")
        else:
            logging.debug(f"Failed to extract project key from relevant parent_href, will try site_href.")
    else:
         logging.debug(f"Skipping project key extraction from non-specific parent_href: {parent_href}")

    # If project_key wasn't found via parent_href, try site_href_raw
    if not project_key:
        logging.debug(f"Attempting project key extraction from site_href_raw: {site_href_raw}")
        project_key = extract_project_key(site_href_raw)
        if project_key:
             logging.debug(f"Successfully extracted project key '{project_key}' from site_href_raw.")
        else:
            logging.debug(f"Could not determine project key from site_href_raw either for entry at {details['timestamp']}")
            
    details['project_key'] = project_key if project_key else 'unknown'

    # Construct a more useful site href if possible
    if details['project_key'] != 'unknown' and details['flag_key'] != 'unknown':
        details['site_href'] = f"https://app.launchdarkly.com/projects/{details['project_key']}/flags/{details['flag_key']}/targeting/production"
    else:
        details['site_href'] = details['site_href_raw']

    # Basic validation
    if not details['timestamp']:
        logging.warning(f"Audit entry missing timestamp: {entry}")
        return None
        
    return details

def check_description_contains(description, substring):
    """Checks if the description contains the given substring, ignoring case and leading/trailing whitespace."""
    if not description or not substring:
        return False
    return substring.lower() in description.lower()

def classify_event(details):
    """Classifies the event based on action and description content."""
    action = details['action'] 
    desc = details['description']

    # Flag On/Off (using titleVerb is primary identifier)
    if details.get('titleVerb') == 'turned on the flag':
        return 'flag_on'
    if details.get('titleVerb') == 'turned off the flag':
        return 'flag_off'
        
    # If action is missing, cannot classify further
    if not action: 
        return 'other'

    # Rollout Start
    if action == ACTION_START_ROLLOUT_FALLTHROUGH and check_description_contains(desc, SUBSTR_START_ROLLOUT_FALLTHROUGH):
        return 'rollout_start_fallthrough'
    if action == ACTION_START_ROLLOUT_RULE and (check_description_contains(desc, SUBSTR_START_ROLLOUT_RULE_1) or check_description_contains(desc, SUBSTR_START_ROLLOUT_RULE_2)):
        return 'rollout_start_rule'

    # Automatic Rollback
    if action == ACTION_AUTO_STOP_FALLTHROUGH and check_description_contains(desc, SUBSTR_AUTO_STOP_FALLTHROUGH):
        return 'rollout_stop_auto_fallthrough'
    if action == ACTION_AUTO_STOP_RULE and check_description_contains(desc, SUBSTR_AUTO_STOP_RULE):
        return 'rollout_stop_auto_rule'

    # Manual Rollback
    if action == ACTION_MANUAL_STOP_FALLTHROUGH and check_description_contains(desc, SUBSTR_MANUAL_STOP_FALLTHROUGH):
        return 'rollout_stop_manual_fallthrough'
    if action == ACTION_MANUAL_STOP_RULE: # Relies only on action for manual rule stop
        return 'rollout_stop_manual_rule'

    return 'other' # Not an event we are tracking

# --- Define CSV fieldnames ---
fieldnames_flag_duration = [
    'flag_key', 'flag_name', 'site_href', 'turn_off_date', 'turn_on_date', 'duration_seconds',
    'turned_off_by_first_name', 'turned_off_by_last_name', 'turned_off_by_email',
    'project_key', 'comment'
]

fieldnames_rollout = [
    'flag_key', 'flag_name', 'site_href', 'rollout_type', # 'fallthrough' or 'rule'
    'rollback_type', # 'automatic' or 'manual'
    'start_date', 'end_date', 'duration_seconds',
    'started_by_email', 'ended_by_email', # Capture who started and ended
    'project_key', 'start_comment', 'end_comment'
]

# --- Initialize CSV files ---
def initialize_csv(filename, fieldnames):
    """Creates a CSV file and writes the header row."""
    try:
        with open(filename, 'w', newline='') as csv_file:
            csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            csv_writer.writeheader()
        logging.info(f"Initialized CSV file: {filename}")
    except IOError as e:
        logging.error(f"Error opening or writing header to CSV file {filename}: {e}")
        exit(1)

initialize_csv(OUTPUT_FLAG_DURATION_CSV, fieldnames_flag_duration)
initialize_csv(OUTPUT_ROLLOUT_AUTO_CSV, fieldnames_rollout)
initialize_csv(OUTPUT_ROLLOUT_MANUAL_CSV, fieldnames_rollout)

# --- Fetch Audit Log Data ---
all_audit_items = [] # List to hold all fetched items

# Start with the base URL for the first request
current_request_url = url

logging.info("Starting fetch of all relevant audit log entries using POST...")
logging.info(f"Filtering actions: {ALL_RELEVANT_ACTIONS}")
fetch_count = 0
page_count = 0

# Fetch pages until the 'next' link is null or we encounter entries older than SEARCH_DATE
while current_request_url:
    page_count += 1
    logging.info(f"Requesting page {page_count} from URL: {current_request_url}")
    
    try:
        # Add limit parameter only to the first request
        request_params = {'limit': limit} if page_count == 1 else None
        
        # Make POST request. Use params only for the first request.
        # Send payload data on all requests for POST pagination.
        response = requests.post(current_request_url, headers=headers, data=initial_payload, params=request_params)

        response.raise_for_status() # Check for HTTP errors

        data = response.json()
        items = data.get('items', [])
        fetch_count += len(items)
        logging.info(f"Received {len(items)} audit log items this page (Total fetched so far: {fetch_count})")

        if not items and not data.get('_links', {}).get('next'):
            logging.info("No items on this page and no next link.")
            break # Exit loop if no items and no next link

        all_audit_items.extend(items)
        
        # Stop fetching if the oldest item on the page is older than our search date
        should_stop_fetching = False
        if items:
            oldest_item_date = items[-1].get('date')
            if oldest_item_date and oldest_item_date < SEARCH_DATE:
                logging.info(f"Oldest item on page {page_count} ({oldest_item_date}) is older than SEARCH_DATE ({SEARCH_DATE}). Stopping pagination.")
                should_stop_fetching = True
            elif not oldest_item_date:
                 logging.warning(f"Could not get date from oldest item on page {page_count}. Stopping pagination as a precaution.")
                 should_stop_fetching = True # Stop if data seems inconsistent
        
        # Get the URL for the next page from _links
        next_link = data.get('_links', {}).get('next', {}).get('href')
        
        # Decide whether to continue
        if should_stop_fetching or not next_link:
            if not next_link and not should_stop_fetching:
                 logging.info("No next link found. Reached end of audit log results for the query.")
            current_request_url = None # Stop the loop
        else:
            # Prepend base_url if href is relative
            if next_link.startswith('/'):
                current_request_url = base_url + next_link
            else:
                current_request_url = next_link
            logging.debug(f"Next page URL: {current_request_url}")
            
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP Error making API request to {response.url}: {e}")
        # Log specific errors
        if response.status_code == 401 or response.status_code == 403:
             logging.error("Received 401/403 Unauthorized/Forbidden. Check API Key permissions.")
        elif response.status_code == 429:
             logging.error("Received 429 Too Many Requests. Consider adding a delay (time.sleep).")
        # Log response text for debugging other errors
        logging.error(f"Response Text: {response.text[:500]}...")
        break # Stop on error
    except requests.exceptions.RequestException as e:
        logging.error(f"Network or Request Error making API request: {e}")
        break
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response: {e}. Response text: {response.text[:500]}...")
        break

logging.info(f"Finished fetching audit log pages. Total items collected before date filtering: {len(all_audit_items)}")

# Filter fetched items by date in memory
original_count = len(all_audit_items)
all_audit_items = [item for item in all_audit_items if item.get('date', 0) >= SEARCH_DATE]
filtered_count = len(all_audit_items)
logging.info(f"Filtered items by date (>= {SEARCH_DATE}). Kept {filtered_count} out of {original_count}.")

# --- Process Audit Log Data ---
# Reverse the list to process oldest first
all_audit_items.reverse()
logging.info(f"Reversed item list for chronological processing.")

# Dictionaries to store state during processing
# Key: (project_key, flag_key)
flag_on_times = {} # Value: {timestamp: ms, member_email: str, comment: str}

# Key: (project_key, flag_key, rollout_type)
active_rollouts = {} # Value: {timestamp: ms, member_email: str, comment: str}

# Lists to store results before writing to CSV
flag_duration_results = []
rollout_auto_results = []
rollout_manual_results = []

logging.info("Starting chronological processing of audit items...")
processed_count = 0

for entry in all_audit_items:
    processed_count += 1
    if processed_count % 500 == 0:
         logging.info(f"Processing item {processed_count}/{len(all_audit_items)}...")

    details = get_event_details(entry)
    if not details:
        continue # Skip entries missing essential info
        
    pk = details['project_key']
    fk = details['flag_key']
    
    # Skip if we couldn't identify the flag or project
    if pk == 'unknown' or fk == 'unknown':
        logging.debug(f"Skipping entry due to unknown project/flag key at {details['timestamp']}")
        continue
        
    state_key_flag = (pk, fk)
    state_key_rollout_fallthrough = (pk, fk, 'fallthrough')
    state_key_rollout_rule = (pk, fk, 'rule')

    event_type = classify_event(details)

    current_time = details['timestamp']
    current_member = details['member_email']
    current_comment = details['comment']

    if event_type == 'flag_on':
        flag_on_times[state_key_flag] = {
            'timestamp': current_time,
            'member_email': current_member,
            'comment': current_comment
        }
        logging.debug(f"Flag ON: {state_key_flag} at {current_time}")

    elif event_type == 'flag_off':
        if state_key_flag in flag_on_times:
            start_info = flag_on_times[state_key_flag]
            start_time = start_info['timestamp']
            duration_seconds = (current_time - start_time) / 1000

            # Format dates
            start_date_str = datetime.fromtimestamp(start_time / 1000).strftime('%Y-%m-%d %H:%M:%S')
            end_date_str = datetime.fromtimestamp(current_time / 1000).strftime('%Y-%m-%d %H:%M:%S')
            
            # Get end user info from the current event (who turned it off)
            end_member_info = entry.get('member', {})
            end_first_name = end_member_info.get('firstName', '')
            end_last_name = end_member_info.get('lastName', '')
            end_email = end_member_info.get('email', 'API/System') # Use placeholder if no member

            result = {
                'flag_key': fk,
                'flag_name': details['flag_name'],
                'site_href': details['site_href'],
                'turn_off_date': end_date_str,
                'turn_on_date': start_date_str,
                'duration_seconds': f"{duration_seconds:.2f}" if duration_seconds >= 0 else 'Error (<0s)',
                'turned_off_by_first_name': end_first_name,
                'turned_off_by_last_name': end_last_name,
                'turned_off_by_email': end_email,
                'project_key': pk,
                'comment': current_comment # Comment from the 'off' event
            }
            flag_duration_results.append(result)
            logging.debug(f"Flag OFF: Matched {state_key_flag}. Duration: {duration_seconds:.2f}s")
            # Remove the 'on' time state once matched
            del flag_on_times[state_key_flag]
        else:
            logging.debug(f"Flag OFF: No matching ON found for {state_key_flag} at {current_time}")

    elif event_type == 'rollout_start_fallthrough':
        if state_key_rollout_fallthrough in active_rollouts:
             logging.warning(f"Rollout START (Fallthrough): Already active for {state_key_rollout_fallthrough} at {current_time}. Overwriting previous start.")
        active_rollouts[state_key_rollout_fallthrough] = {
            'timestamp': current_time,
            'member_email': current_member,
            'comment': current_comment
        }
        logging.debug(f"Rollout START (Fallthrough): {state_key_rollout_fallthrough} at {current_time}")

    elif event_type == 'rollout_start_rule':
        if state_key_rollout_rule in active_rollouts:
             logging.warning(f"Rollout START (Rule): Already active for {state_key_rollout_rule} at {current_time}. Overwriting previous start.")
        active_rollouts[state_key_rollout_rule] = {
            'timestamp': current_time,
            'member_email': current_member,
            'comment': current_comment
        }
        logging.debug(f"Rollout START (Rule): {state_key_rollout_rule} at {current_time}")

    elif event_type == 'rollout_stop_auto_fallthrough':
        if state_key_rollout_fallthrough in active_rollouts:
            start_info = active_rollouts[state_key_rollout_fallthrough]
            start_time = start_info['timestamp']
            duration_seconds = (current_time - start_time) / 1000
            start_date_str = datetime.fromtimestamp(start_time / 1000).strftime('%Y-%m-%d %H:%M:%S')
            end_date_str = datetime.fromtimestamp(current_time / 1000).strftime('%Y-%m-%d %H:%M:%S')

            result = {
                'flag_key': fk,
                'flag_name': details['flag_name'],
                'site_href': details['site_href'],
                'rollout_type': 'fallthrough',
                'rollback_type': 'automatic',
                'start_date': start_date_str,
                'end_date': end_date_str,
                'duration_seconds': f"{duration_seconds:.2f}" if duration_seconds >= 0 else 'Error (<0s)',
                'started_by_email': start_info['member_email'] or 'Unknown/API',
                'ended_by_email': current_member or 'API/System', # End event member
                'project_key': pk,
                'start_comment': start_info['comment'],
                'end_comment': current_comment
            }
            rollout_auto_results.append(result)
            logging.debug(f"Rollout STOP (Auto Fallthrough): Matched {state_key_rollout_fallthrough}. Duration: {duration_seconds:.2f}s")
            del active_rollouts[state_key_rollout_fallthrough]
        else:
             logging.debug(f"Rollout STOP (Auto Fallthrough): No matching START found for {state_key_rollout_fallthrough} at {current_time}")
             
    elif event_type == 'rollout_stop_auto_rule':
        if state_key_rollout_rule in active_rollouts:
            start_info = active_rollouts[state_key_rollout_rule]
            start_time = start_info['timestamp']
            duration_seconds = (current_time - start_time) / 1000
            start_date_str = datetime.fromtimestamp(start_time / 1000).strftime('%Y-%m-%d %H:%M:%S')
            end_date_str = datetime.fromtimestamp(current_time / 1000).strftime('%Y-%m-%d %H:%M:%S')

            result = {
                'flag_key': fk,
                'flag_name': details['flag_name'],
                'site_href': details['site_href'],
                'rollout_type': 'rule',
                'rollback_type': 'automatic',
                'start_date': start_date_str,
                'end_date': end_date_str,
                'duration_seconds': f"{duration_seconds:.2f}" if duration_seconds >= 0 else 'Error (<0s)',
                'started_by_email': start_info['member_email'] or 'Unknown/API',
                'ended_by_email': current_member or 'API/System', # End event member
                'project_key': pk,
                'start_comment': start_info['comment'],
                'end_comment': current_comment
            }
            rollout_auto_results.append(result)
            logging.debug(f"Rollout STOP (Auto Rule): Matched {state_key_rollout_rule}. Duration: {duration_seconds:.2f}s")
            del active_rollouts[state_key_rollout_rule]
        else:
             logging.debug(f"Rollout STOP (Auto Rule): No matching START found for {state_key_rollout_rule} at {current_time}")

    elif event_type == 'rollout_stop_manual_fallthrough':
        if state_key_rollout_fallthrough in active_rollouts:
            start_info = active_rollouts[state_key_rollout_fallthrough]
            start_time = start_info['timestamp']
            duration_seconds = (current_time - start_time) / 1000
            start_date_str = datetime.fromtimestamp(start_time / 1000).strftime('%Y-%m-%d %H:%M:%S')
            end_date_str = datetime.fromtimestamp(current_time / 1000).strftime('%Y-%m-%d %H:%M:%S')

            result = {
                'flag_key': fk,
                'flag_name': details['flag_name'],
                'site_href': details['site_href'],
                'rollout_type': 'fallthrough',
                'rollback_type': 'manual',
                'start_date': start_date_str,
                'end_date': end_date_str,
                'duration_seconds': f"{duration_seconds:.2f}" if duration_seconds >= 0 else 'Error (<0s)',
                'started_by_email': start_info['member_email'] or 'Unknown/API',
                'ended_by_email': current_member or 'API/System', # End event member
                'project_key': pk,
                'start_comment': start_info['comment'],
                'end_comment': current_comment
            }
            rollout_manual_results.append(result)
            logging.debug(f"Rollout STOP (Manual Fallthrough): Matched {state_key_rollout_fallthrough}. Duration: {duration_seconds:.2f}s")
            del active_rollouts[state_key_rollout_fallthrough]
        else:
             logging.debug(f"Rollout STOP (Manual Fallthrough): No matching START found for {state_key_rollout_fallthrough} at {current_time}")

    elif event_type == 'rollout_stop_manual_rule':
        if state_key_rollout_rule in active_rollouts:
            start_info = active_rollouts[state_key_rollout_rule]
            start_time = start_info['timestamp']
            duration_seconds = (current_time - start_time) / 1000
            start_date_str = datetime.fromtimestamp(start_time / 1000).strftime('%Y-%m-%d %H:%M:%S')
            end_date_str = datetime.fromtimestamp(current_time / 1000).strftime('%Y-%m-%d %H:%M:%S')

            result = {
                'flag_key': fk,
                'flag_name': details['flag_name'],
                'site_href': details['site_href'],
                'rollout_type': 'rule',
                'rollback_type': 'manual',
                'start_date': start_date_str,
                'end_date': end_date_str,
                'duration_seconds': f"{duration_seconds:.2f}" if duration_seconds >= 0 else 'Error (<0s)',
                'started_by_email': start_info['member_email'] or 'Unknown/API',
                'ended_by_email': current_member or 'API/System', # End event member
                'project_key': pk,
                'start_comment': start_info['comment'],
                'end_comment': current_comment
            }
            rollout_manual_results.append(result)
            logging.debug(f"Rollout STOP (Manual Rule): Matched {state_key_rollout_rule}. Duration: {duration_seconds:.2f}s")
            del active_rollouts[state_key_rollout_rule]
        else:
             logging.debug(f"Rollout STOP (Manual Rule): No matching START found for {state_key_rollout_rule} at {current_time}")

logging.info(f"Finished processing {processed_count} items.")

# --- Write Results to CSV ---

def write_results_to_csv(filename, fieldnames, results):
    """Writes the collected results to the specified CSV file."""
    try:
        # Use 'a' append mode as the header is written during initialization
        with open(filename, 'a', newline='', encoding='utf-8') as csv_file: 
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writerows(results)
        logging.info(f"Successfully wrote {len(results)} records to {filename}")
    except IOError as e:
        logging.error(f"Error writing results to CSV file {filename}: {e}")
    except Exception as e:
         logging.error(f"Unexpected error writing to {filename}: {e}")

logging.info(f"Writing results to CSV files...")
write_results_to_csv(OUTPUT_FLAG_DURATION_CSV, fieldnames_flag_duration, flag_duration_results)
write_results_to_csv(OUTPUT_ROLLOUT_AUTO_CSV, fieldnames_rollout, rollout_auto_results)
write_results_to_csv(OUTPUT_ROLLOUT_MANUAL_CSV, fieldnames_rollout, rollout_manual_results)

# Final summary message
print("-"*30)
print("Processing Summary:")
print(f"  - Found {len(flag_duration_results)} flag on/off durations.")
print(f"  - Found {len(rollout_auto_results)} automatically rolled back measured rollouts.")
print(f"  - Found {len(rollout_manual_results)} manually rolled back measured rollouts.")
print(f"Results saved to:")
print(f"  - {OUTPUT_FLAG_DURATION_CSV}")
print(f"  - {OUTPUT_ROLLOUT_AUTO_CSV}")
print(f"  - {OUTPUT_ROLLOUT_MANUAL_CSV}")
print("-"*30)
