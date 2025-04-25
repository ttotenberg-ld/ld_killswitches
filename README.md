# LaunchDarkly Audit Log Extractor

This script extracts and consolidates audit log entries from LaunchDarkly, focusing on flags that have been turned off in the production environment.


## Installation

1. Clone this repository:
   ```
   git clone https://github.com/ttotenberg-ld/ld_killswitches.git
   cd ld_killswitches
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

1. Adjust the `PROJECT` and `SEARCH_DATE` in `main.py` if needed:
   - `PROJECT`: The project to search for audit log entries. Use "*" to search all projects.
   - `SEARCH_DATE`: The cutoff date for audit log entries, in epoch milliseconds. The script will search for events occurring *after* this date.

2. Run the script:
   ```bash
   python3 main.py
   ```

3. The script will output progress information and save the results to three CSV files:
   - `flag_on_durations.csv`: Tracks how long flags were turned on before being turned off.
   - `measured_rollout_automatic_rollback.csv`: Tracks measured rollouts that were automatically rolled back.
   - `measured_rollout_manual_rollback.csv`: Tracks measured rollouts that were manually rolled back.

## Output

- The script generates three CSV files (detailed below).

### `flag_on_durations.csv`

This file tracks the duration for which flags were turned on in the production environment before being turned off.

- `flag_key`: The unique key of the flag.
- `flag_name`: The human-readable name of the flag.
- `site_href`: A direct URL to the flag's targeting settings in the LaunchDarkly UI.
- `turn_off_date`: The timestamp (YYYY-MM-DD HH:MM:SS) when the flag was turned off.
- `turn_on_date`: The timestamp (YYYY-MM-DD HH:MM:SS) when the flag was turned on.
- `duration_seconds`: The calculated duration (in seconds) the flag was on.
- `turned_off_by_first_name`: First name of the member who turned off the flag.
- `turned_off_by_last_name`: Last name of the member who turned off the flag.
- `turned_off_by_email`: Email of the member who turned off the flag (or 'API/System').
- `project_key`: The key of the project the flag belongs to.
- `comment`: Any comment associated with the action of turning off the flag.

### `measured_rollout_automatic_rollback.csv`

This file tracks measured rollouts (gradual percentage rollouts) that were automatically rolled back (likely due to an associated experiment or metric configuration).

- `flag_key`: The unique key of the flag.
- `flag_name`: The human-readable name of the flag.
- `site_href`: A direct URL to the flag's targeting settings in the LaunchDarkly UI.
- `rollout_type`: Indicates if the rollout was on the 'fallthrough' (default rule) or a specific 'rule'.
- `rollback_type`: Will always be 'automatic' for this file.
- `start_date`: The timestamp (YYYY-MM-DD HH:MM:SS) when the measured rollout started.
- `end_date`: The timestamp (YYYY-MM-DD HH:MM:SS) when the measured rollout was automatically rolled back.
- `duration_seconds`: The calculated duration (in seconds) of the measured rollout.
- `started_by_email`: Email of the member who started the rollout (or 'Unknown/API').
- `ended_by_email`: Email of the member/system associated with the rollback (or 'API/System').
- `project_key`: The key of the project the flag belongs to.
- `start_comment`: Any comment associated with starting the rollout.
- `end_comment`: Any comment associated with the automatic rollback action.

### `measured_rollout_manual_rollback.csv`

This file tracks measured rollouts that were manually stopped or reverted by a user.

- `flag_key`: The unique key of the flag.
- `flag_name`: The human-readable name of the flag.
- `site_href`: A direct URL to the flag's targeting settings in the LaunchDarkly UI.
- `rollout_type`: Indicates if the rollout was on the 'fallthrough' (default rule) or a specific 'rule'.
- `rollback_type`: Will always be 'manual' for this file.
- `start_date`: The timestamp (YYYY-MM-DD HH:MM:SS) when the measured rollout started.
- `end_date`: The timestamp (YYYY-MM-DD HH:MM:SS) when the measured rollout was manually stopped.
- `duration_seconds`: The calculated duration (in seconds) of the measured rollout.
- `started_by_email`: Email of the member who started the rollout (or 'Unknown/API').
- `ended_by_email`: Email of the member who manually stopped the rollout (or 'API/System').
- `project_key`: The key of the project the flag belongs to.
- `start_comment`: Any comment associated with starting the rollout.
- `end_comment`: Any comment associated with manually stopping the rollout.
