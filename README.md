# LaunchDarkly Audit Log Extractor

This script extracts and consolidates audit log entries from LaunchDarkly, focusing on flags that have been turned off in the production environment.


## Installation

1. Clone this repository:
   ```
   git clone https://github.com/your-username/launchdarkly-audit-log-extractor.git
   cd launchdarkly-audit-log-extractor
   ```

2. Install the required packages:
   ```
   pip3 install -r requirements.txt
   ```

3. Change the `.env` file in the project root and add your LaunchDarkly API key:
   ```
   LAUNCHDARKLY_API_KEY=your_api_key_here
   ```

## Usage

1. Adjust the `PROJECT` and `SEARCH_DATE` constants in `main.py` if needed:
   - `PROJECT`: The project to search for audit log entries. Use "*" to search all projects.
   - `SEARCH_DATE`: The cutoff date for audit log entries, in epoch milliseconds.

2. Run the script:
   ```
   python main.py
   ```

3. The script will output progress information and save the results to `consolidated_results.csv`.

## Output

The script generates a CSV file named `consolidated_results.csv` with the following columns:

- name: The name of the flag
- site_href: The URL to the flag in LaunchDarkly
- date: The date and time when the flag was turned off
- first_name: First name of the member who turned off the flag
- last_name: Last name of the member who turned off the flag
- email: Email of the member who turned off the flag
- project_key: The key of the project the flag belongs to
