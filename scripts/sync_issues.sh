#!/bin/bash
# Sync issues and PRs from GitHub to local tracking
# Usage: ./scripts/sync_issues.sh

set -e

REPO="Conxian/conxius-enclave-sdk"
ISSUES_DIR="issues"
PRS_DIR="prs"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

if [ -z "$GITHUB_TOKEN" ]; then
    echo "Error: GITHUB_TOKEN environment variable not set"
    exit 1
fi

echo "Fetching issues and PRs from GitHub..."

# Fetch issues
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/repos/$REPO/issues?state=all&per_page=100" \
    > /tmp/sdk_issues.json

# Fetch PRs
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/repos/$REPO/pulls?state=all&per_page=100" \
    > /tmp/sdk_prs.json

# Run Python script to process
python3 << 'PYTHON_SCRIPT'
import json
import os
from datetime import datetime

# Create directories
os.makedirs('issues', exist_ok=True)
os.makedirs('prs', exist_ok=True)

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
    body = issue.get('body', '') or ''
    
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
""")
    
    index_data.append({
        'number': number, 'title': title, 'state': state,
        'labels': labels, 'assignee': assignee_login,
        'created': created_at, 'url': url
    })

index_data.sort(key=lambda x: x['number'], reverse=True)
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

with open('ISSUES_INDEX.md', 'w') as f:
    f.write(f"""# Conclave SDK Issues Index

> Auto-generated from GitHub. Last sync: {now}

## Summary
- **Total Issues**: {len(index_data)}
- **Open Issues**: {len([i for i in index_data if i['state'] == 'open'])}
- **Closed Issues**: {len([i for i in index_data if i['state'] == 'closed'])}

## Open Issues
""")
    for issue in [i for i in index_data if i['state'] == 'open']:
        f.write(f"- [ ] **#{issue['number']}**: {issue['title']}\n")
        if issue['labels']:
            f.write(f"  - Labels: {', '.join(issue['labels'])}\n")
        f.write(f"  - Assigned: {issue['assignee']}\n\n")
    f.write("\n## Closed Issues\n")
    for issue in [i for i in index_data if i['state'] == 'closed']:
        f.write(f"- [x] **#{issue['number']}**: {issue['title']}\n")
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
    body = pr.get('body', '') or ''
    
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
""")
    
    pr_index.append({
        'number': number, 'title': title, 'state': state,
        'labels': labels, 'author': author, 'merged': merged_at,
        'created': created_at, 'url': url
    })

pr_index.sort(key=lambda x: x['number'], reverse=True)

with open('PRS_INDEX.md', 'w') as f:
    f.write(f"""# Conclave SDK Pull Requests Index

> Auto-generated from GitHub. Last sync: {now}

## Summary
- **Total PRs**: {len(pr_index)}
- **Open PRs**: {len([i for i in pr_index if i['state'] == 'open'])}
- **Merged PRs**: {len([i for i in pr_index if i['merged'] != 'never'])}
- **Closed PRs**: {len([i for i in pr_index if i['state'] == 'closed' and i['merged'] == 'never'])}

## Open PRs
""")
    for pr in [i for i in pr_index if i['state'] == 'open']:
        f.write(f"- [ ] **#{pr['number']}**: {pr['title']}\n")
        f.write(f"  - Author: {pr['author']}\n\n")
    f.write("\n## Recently Merged PRs\n")
    for pr in [i for i in pr_index if i['merged'] != 'never'][:20]:
        f.write(f"- [x] **#{pr['number']}**: {pr['title']}\n")
        f.write(f"  - Author: {pr['author']} | Merged: {pr['merged']}\n\n")
    f.write("\n## Closed (Not Merged) PRs\n")
    for pr in [i for i in pr_index if i['state'] == 'closed' and i['merged'] == 'never']:
        f.write(f"- [ ] **#{pr['number']}**: {pr['title']}\n")
        f.write(f"  - Author: {pr['author']}\n\n")

print(f"Synced {len(prs)} pull requests")
print("Done!")
PYTHON_SCRIPT
