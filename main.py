import requests
import json
import os
import logging
from dotenv import load_dotenv
import csv
from datetime import datetime
from collections import defaultdict
import time
import re

# Configuration constants
PROJECT = "*"  # The project to search for audit log entries. Use "*" to search all projects
SEARCH_DATE = 1729451496000  # Cutoff date for audit log entries, in epoch milliseconds

# Set up logging for better debugging and monitoring
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file for secure configuration
load_dotenv()
logging.info("Environment variables loaded")

# Define LaunchDarkly API endpoints
base_url = "https://app.launchdarkly.com"
api_url = "/api/v2/auditlog"
url = base_url + api_url

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

# Define payload for filtering audit log entries
# This payload filters for flag updates in the production environment of the specified project
payload = json.dumps([
  {
    "resources": [
      f"proj/{PROJECT}:env/production:flag/*"
    ],
    "effect": "allow",
    "actions": [
      "updateOn"
    ]
  }
])

# API and processing configuration
limit = 20  # Number of items per page in API response
batch_size = 100  # Number of items to process before writing to CSV

def extract_project_key(site_href):
    """
    Extract the project key from the site href.
    
    Args:
    site_href (str): The site href from the API response
    
    Returns:
    str: The extracted project key or an empty string if not found
    """
    # Try different patterns to extract the project key
    patterns = [
        r'/([^/]+)/~/features/',  # Original pattern
        r'/projects/([^/]+)/',    # New pattern for updated URL structure
        r'^/([^/]+)/'             # Fallback pattern for other possible formats
    ]
    
    for pattern in patterns:
        match = re.search(pattern, site_href)
        if match:
            return match.group(1)
    
    logging.warning(f"Could not extract project key from site_href: {site_href}")
    return ''

def process_batch(batch, csv_writer):
    """
    Process a batch of audit log entries, consolidate results, and write to CSV.
    
    Args:
    batch (list): List of audit log entries to process
    csv_writer (csv.DictWriter): CSV writer object to write results
    
    Returns:
    int: Number of unique entries processed and written to CSV
    """
    results = defaultdict(list)
    # Filter and extract required information from the audit log entries
    for entry in batch:
        if entry.get('titleVerb') == 'turned off the flag':
            name = entry.get('name', '')
            site_href = entry.get('_links', {}).get('site', {}).get('href', '')
            date = entry.get('date', '')
            
            # Extract member information
            member = entry.get('member', {})
            first_name = member.get('firstName', '')
            last_name = member.get('lastName', '')
            email = member.get('email', '')
            
            # Extract project key
            project_key = extract_project_key(site_href)
            
            # Log the extracted project key for debugging
            logging.debug(f"Extracted project key '{project_key}' from site_href: {site_href}")
            
            # Convert timestamp to human-readable format
            if date:
                date = datetime.fromtimestamp(date / 1000).strftime('%Y-%m-%d %H:%M:%S')
            
            results[name].append({
                'site_href': site_href,
                'date': date,
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'project_key': project_key
            })

    # Consolidate results, removing duplicates
    consolidated_results = set()
    for name, entries in results.items():
        # Update site_href to point to the flags page
        site_href = entries[0]['site_href'].replace("/production/features/", "/flags/")
        site_href = f"https://app.launchdarkly.com/projects{site_href}"
        for entry in entries:
            consolidated_results.add((
                name, site_href, entry['date'],
                entry['first_name'], entry['last_name'], entry['email'],
                entry['project_key']
            ))

    # Convert set to list of dictionaries for easier handling
    consolidated_results_list = [
        {
            'name': name,
            'site_href': site_href,
            'date': date,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'project_key': project_key
        }
        for name, site_href, date, first_name, last_name, email, project_key in consolidated_results
    ]

    # Sort the results by date (most recent first) and then by name
    consolidated_results_list.sort(key=lambda x: (-datetime.strptime(x['date'], '%Y-%m-%d %H:%M:%S').timestamp(), x['name']))

    # Write sorted results to CSV
    for result in consolidated_results_list:
        csv_writer.writerow(result)

    return len(consolidated_results_list)

# Clear the CSV file and write the header
with open('consolidated_results.csv', 'w', newline='') as csv_file:
    fieldnames = ['name', 'site_href', 'date', 'first_name', 'last_name', 'email', 'project_key']
    csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    csv_writer.writeheader()

# Set initial date to current timestamp (in milliseconds)
date = round(time.time() * 1000)
total_processed = 0
batch = []

# Fetch audit log entries until reaching a specific date or end of data
with open('consolidated_results.csv', 'a', newline='') as csv_file:
    fieldnames = ['name', 'site_href', 'date', 'first_name', 'last_name', 'email', 'project_key']
    csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    while date > SEARCH_DATE:
        params = {
            'limit': limit
        }
        
        try:
            # Make POST request to LaunchDarkly API
            response = requests.post(url, headers=headers, params=params, data=payload)
            response.raise_for_status()
            
            data = response.json()
            next_url = data.get('_links', {}).get('next', {}).get('href', '')
            items = data.get('items', [])
            item_date = items[0].get('date', '') if items else None
            logging.info(f"Received {len(items)} items")
            
            batch.extend(items)
            
            # Process batch if it reaches the specified size
            if len(batch) >= batch_size:
                processed = process_batch(batch, csv_writer)
                total_processed += processed
                logging.info(f"Processed and wrote {processed} entries to CSV. Total processed: {total_processed}")
                batch = []
            
            # Break the loop if we've reached the end of the data
            if len(items) < limit:
                logging.info("Reached end of data")
                break

            # Update URL and date for next iteration
            url = base_url + next_url
            date = item_date
            print(f"Retrieved date: {datetime.fromtimestamp(date / 1000).strftime('%Y-%m-%d %H:%M:%S')}")
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Error making request: {e}")
            break

    # Process any remaining items in the batch
    if batch:
        processed = process_batch(batch, csv_writer)
        total_processed += processed
        logging.info(f"Processed and wrote final {processed} entries to CSV. Total processed: {total_processed}")

print(f"Extracted and consolidated {total_processed} unique entries and saved to consolidated_results.csv")
