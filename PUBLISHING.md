# Publish to GitHub

Repository name suggestion: `phishing-website-risk-analyzer` under your GitHub account.

1. Create an **empty** GitHub repository at https://github.com/new. Use the suggested name and public visibility if you want this portfolio piece to be visible. Do **not** initialize GitHub README or .gitignore (those files already exist here).
2. From the extracted project folder, run the following commands in PowerShell (requires Git):

```powershell
git init
git branch -M main
git add .
git commit -m "Initial release: phishing URL risk analyzer"
git remote add origin https://github.com/Yaserdrd/phishing-website-risk-analyzer.git
git push -u origin main
```

GitHub may request browser authentication when pushing. Never paste your account password or personal access token into a chat.

Alternatively, if GitHub CLI (`gh`) is installed and authenticated:

```powershell
gh repo create phishing-website-risk-analyzer --public --source . --remote origin --push
```

**Before public deployment:** train the model, review metrics and security notes, ensure all code is committed, and add provider-specific egress restrictions and rate limiting for the optional active checks.
