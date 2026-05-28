import os
import json
import datetime

def get_latest_stacks_version():
    return "3.3.0", "2026-05-01"

def main():
    latest_ver, release_date = get_latest_stacks_version()
    release_dt = datetime.datetime.strptime(release_date, "%Y-%m-%d")
    now = datetime.datetime.now()

    buffer_days = 30
    ready_date = release_dt + datetime.timedelta(days=buffer_days)

    if now >= ready_date:
        if 'GITHUB_ENV' in os.environ:
            with open(os.environ['GITHUB_ENV'], 'a') as f:
                f.write("SYNC_REQUIRED=true\n")
    else:
        if 'GITHUB_ENV' in os.environ:
            with open(os.environ['GITHUB_ENV'], 'a') as f:
                f.write("SYNC_REQUIRED=false\n")

if __name__ == "__main__":
    main()
