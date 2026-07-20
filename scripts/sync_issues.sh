#!/bin/bash
# Sync issues and PRs from GitHub to local tracking
# Usage: ./scripts/sync_issues.sh

set -euo pipefail

REPO="Conxian/conxius-enclave-sdk"
ISSUES_DIR="issues"
PRS_DIR="prs"
GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
export GITHUB_TOKEN

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN or GH_TOKEN environment variable not set"
    exit 1
fi

echo "Fetching issues and PRs from GitHub..."

# Fetch every page so the indexes represent the complete GitHub history.
python3 << 'FETCH_SCRIPT'
import json
import os
from urllib.request import Request, urlopen

repo = "Conxian/conxius-enclave-sdk"
headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
    "X-GitHub-Api-Version": "2022-11-28",
}

for endpoint, output in (("issues", "/tmp/sdk_issues.json"), ("pulls", "/tmp/sdk_prs.json")):
    records = []
    page = 1
    while True:
        url = (
            f"https://api.github.com/repos/{repo}/{endpoint}"
            f"?state=all&per_page=100&page={page}"
        )
        request = Request(url, headers=headers)
        with urlopen(request) as response:
            batch = json.load(response)
        if not batch:
            break
        records.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    with open(output, "w") as handle:
        json.dump(records, handle)
FETCH_SCRIPT

# Run Python script to process
python3 << 'PYTHON_SCRIPT'
import json
import os
from datetime import datetime, timezone

# Create directories
os.makedirs('issues', exist_ok=True)
os.makedirs('prs', exist_ok=True)

snapshot_note = (
    "> **Snapshot semantics:** Closed and merged entries are point-in-time GitHub "
    "outcomes from this sync. They do not establish implementation completeness, "
    "production readiness, security review, release acceptance, or support. See "
    "[PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md).\n"
)
now = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def normalize_body(value):
    return '\n'.join(line.rstrip() for line in (value or '').splitlines()).strip()

# Process Issues
with open('/tmp/sdk_issues.json', 'r') as f:
    issues = json.load(f)
issues = [i for i in issues if i.get('pull_request') is None]
index_data = []

for issue in issues:
    number = issue['number']
    title = issue['title']
    state = issue['state']
    labels = [l['name'] for l in issue.get('labels', [])]
    assignee = issue.get('assignee', {})
    assignee_login = assignee.get('login', 'unassigned') if assignee else 'unassigned'
    created_at = issue['created_at'][:10]
    updated_at = issue['updated_at'][:10]
    url = issue['html_url']
    body = normalize_body(issue.get('body', ''))

    filename = f"issues/{number:04d}.md"
    with open(filename, 'w') as f:
        f.write(f"""---
number: {number}
title: "{title}"
state: {state}
labels: {', '.join(labels) if labels else 'none'}
assignee: {assignee_login}
created: {created_at}
updated: {updated_at}
url: {url}
source: github
---

# {title}

**Issue #{number}** | {state.upper()} | Created: {created_at} | Updated: {updated_at}

{body}
""".rstrip() + "\n")

    index_data.append({
        'number': number, 'title': title, 'state': state,
        'labels': labels, 'assignee': assignee_login,
        'created': created_at, 'url': url
    })

index_data.sort(key=lambda x: x['number'], reverse=True)
open_issues = [i for i in index_data if i['state'] == 'open']
closed_issues = [i for i in index_data if i['state'] == 'closed']

with open('ISSUES_INDEX.md', 'w') as f:
    f.write(f"""# Conclave SDK Issues Index

> Auto-generated from GitHub. Last sync: {now}

{snapshot_note}

## Summary
- **Total Issues**: {len(index_data)}
- **Open Issues**: {len(open_issues)}
- **Closed Issues**: {len(closed_issues)}

## Open Issues
""")
    if open_issues:
        for issue in open_issues:
            f.write(f"- [ ] [**#{issue['number']}**]({issue['url']}): {issue['title']}\n")
            if issue['labels']:
                f.write(f"  - Labels: {', '.join(issue['labels'])}\n")
            f.write(f"  - Assigned: {issue['assignee']}\n\n")
    else:
        f.write("*None returned by GitHub in this snapshot.*\n")
    f.write("\n## Closed Issues\n")
    for issue in closed_issues:
        f.write(f"- [x] [**#{issue['number']}**]({issue['url']}): {issue['title']}\n")
        if issue['labels']:
            f.write(f"  - Labels: {', '.join(issue['labels'])}\n\n")

print(f"Synced {len(issues)} issues")

# Process PRs
with open('/tmp/sdk_prs.json', 'r') as f:
    prs = json.load(f)
pr_index = []

for pr in prs:
    number = pr['number']
    title = pr['title']
    state = pr['state']
    labels = [l['name'] for l in pr.get('labels', [])]
    author = pr['user']['login']
    assignee = pr.get('assignee', {})
    assignee_login = assignee.get('login', 'unassigned') if assignee else 'unassigned'
    created_at = pr['created_at'][:10]
    updated_at = pr['updated_at'][:10]
    merged_at = pr.get('merged_at', '')[:10] if pr.get('merged_at') else 'never'
    url = pr['html_url']
    head_ref = pr['head']['ref']
    base_ref = pr['base']['ref']
    body = normalize_body(pr.get('body', ''))

    filename = f"prs/{number:04d}.md"
    with open(filename, 'w') as f:
        f.write(f"""---
number: {number}
title: "{title}"
state: {state}
labels: {', '.join(labels) if labels else 'none'}
author: {author}
assignee: {assignee_login}
created: {created_at}
updated: {updated_at}
merged: {merged_at}
url: {url}
source: github
branch: {head_ref} -> {base_ref}
---

# {title}

**PR #{number}** | {state.upper()} | Author: {author} | Created: {created_at} | Merged: {merged_at}

Branch: `{head_ref}` → `{base_ref}`

{body}
""".rstrip() + "\n")

    pr_index.append({
        'number': number, 'title': title, 'state': state,
        'labels': labels, 'author': author, 'merged': merged_at,
        'created': created_at, 'url': url
    })

pr_index.sort(key=lambda x: x['number'], reverse=True)
open_prs = [i for i in pr_index if i['state'] == 'open']
merged_prs = [i for i in pr_index if i['merged'] != 'never']
closed_unmerged_prs = [
    i for i in pr_index if i['state'] == 'closed' and i['merged'] == 'never'
]

with open('PRS_INDEX.md', 'w') as f:
    f.write(f"""# Conclave SDK Pull Requests Index

> Auto-generated from GitHub. Last sync: {now}

{snapshot_note}

## Summary
- **Total PRs**: {len(pr_index)}
- **Open PRs**: {len(open_prs)}
- **Merged PRs**: {len(merged_prs)}
- **Closed PRs**: {len(closed_unmerged_prs)}

## Open PRs
""")
    if open_prs:
        for pr in open_prs:
            f.write(f"- [ ] [**#{pr['number']}**]({pr['url']}): {pr['title']}\n")
            f.write(f"  - Author: {pr['author']}\n\n")
    else:
        f.write("*None returned by GitHub in this snapshot.*\n")
    f.write("\n## Recently Merged PRs\n")
    for pr in merged_prs[:20]:
        f.write(f"- [x] [**#{pr['number']}**]({pr['url']}): {pr['title']}\n")
        f.write(f"  - Author: {pr['author']} | Merged: {pr['merged']}\n\n")
    f.write("\n## Closed (Not Merged) PRs\n")
    for pr in closed_unmerged_prs:
        f.write(f"- [ ] [**#{pr['number']}**]({pr['url']}): {pr['title']}\n")
        f.write(f"  - Author: {pr['author']}\n\n")

print(f"Synced {len(prs)} pull requests")
print("Done!")
PYTHON_SCRIPT
