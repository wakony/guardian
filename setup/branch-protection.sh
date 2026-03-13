#!/usr/bin/env bash
# branch-protection.sh — Set up GitHub branch protection rules
# Requires: gh CLI (https://cli.github.com/) authenticated
#
# Usage:
#   ./branch-protection.sh owner/repo-name          Set up protection
#   ./branch-protection.sh owner/repo-name --status  Check current status
#   ./branch-protection.sh --list                    List all repos
set -euo pipefail

if ! command -v gh &>/dev/null; then
  echo "Error: gh CLI not found. Install from https://cli.github.com/"
  exit 1
fi

if [ "${1:-}" = "--list" ]; then
  echo "Repositories you have access to:"
  gh repo list --limit 100 --json nameWithOwner,defaultBranchRef --template '{{range .}}{{.nameWithOwner}} ({{.defaultBranchRef.name}}){{"\n"}}{{end}}'
  exit 0
fi

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <owner/repo> [--status]"
  echo "       $0 --list"
  exit 1
fi

REPO="$1"

# Get default branch
DEFAULT_BRANCH=$(gh api "repos/$REPO" --jq '.default_branch' 2>/dev/null || echo "main")
echo "Repository: $REPO"
echo "Default branch: $DEFAULT_BRANCH"

if [ "${2:-}" = "--status" ]; then
  echo ""
  echo "Current branch protection:"
  gh api "repos/$REPO/branches/$DEFAULT_BRANCH/protection" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  No branch protection rules set."
  exit 0
fi

echo ""
echo "Setting up branch protection on $DEFAULT_BRANCH..."

# Apply branch protection rules
gh api -X PUT "repos/$REPO/branches/$DEFAULT_BRANCH/protection" \
  --input - << 'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": []
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true
}
EOF

echo ""
echo "Branch protection applied:"
echo "  - Require pull request review (1 reviewer)"
echo "  - Dismiss stale reviews on new commits"
echo "  - Block force pushes"
echo "  - Block branch deletion"
echo "  - Require conversation resolution"
echo ""
echo "To also require signed commits, run:"
echo "  gh api -X POST repos/$REPO/branches/$DEFAULT_BRANCH/protection/required_signatures"
echo ""
echo "Done."
