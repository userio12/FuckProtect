# Push FuckProtect to GitHub via Termux (GitHub CLI)

A complete step-by-step guide to pushing the project to GitHub using the GitHub CLI (`gh`) from Termux on Android.

---

## Table of Contents

1. [Install Termux Dependencies](#1-install-termux-dependencies)
2. [Install & Authenticate GitHub CLI](#2-install--authenticate-github-cli)
3. [Initialize Local Git Repository](#3-initialize-local-git-repository)
4. [Create GitHub Repository](#4-create-github-repository)
5. [Create `.gitignore`](#5-creategitignore)
6. [Add, Commit & Push](#6-add-commit--push)
7. [Verify on GitHub](#7-verify-on-github)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Install Termux Dependencies

Open Termux and run:

```bash
# Update package lists
pkg update && pkg upgrade -y

# Install Git, GitHub CLI, and essential tools
pkg install -y git gh proot-distro

# Verify installations
git --version
# Expected: git 2.x.x

gh --version
# Expected: gh version 2.x.x
```

---

## 2. Install & Authenticate GitHub CLI

### Step 1: Authenticate with GitHub

```bash
# Start the authentication flow
gh auth login
```

### Step 2: Choose Options

When prompted, select these options:

```
? What account do you want to log into?
  → GitHub.com

? What is your preferred protocol for Git operations?
  → HTTPS   (easier on Termux)
  # OR SSH if you have SSH keys set up

? Authenticate Git with your GitHub credentials?
  → Yes

? How would you like to authenticate GitHub CLI?
  → Login with a web browser    (recommended)
  # OR
  → Paste an authentication token
```

### Step 3: Complete Authentication

If you chose **web browser**:
1. A URL will be displayed — copy it
2. Open it in your phone's browser (Chrome/Firefox)
3. Log in to GitHub and authorize the CLI
4. You'll get a code — paste it back in Termux

If you chose **token**:
1. Go to https://github.com/settings/tokens/new
2. Create a token with these scopes: `repo`, `workflow`
3. Copy the token
4. Paste it in Termux when prompted

### Step 4: Verify Authentication

```bash
gh auth status

# Expected output:
# github.com
#   ✓ Logged in to github.com as YOUR_USERNAME
#   ✓ Git operations for github.com configured to use HTTPS protocol.
#   ✓ Token: gho_****
```

---

## 3. Initialize Local Git Repository

Before creating anything on GitHub, initialize the local git repo first.

```bash
cd /storage/emulated/0/AndroidCSProjects/FuckProtect

# Initialize a local git repository
git init

# Configure git user (matches your GitHub account)
git config user.name "YOUR_GITHUB_USERNAME"
git config user.email "your_email@example.com"

# Set default branch name
git branch -M main

# Verify the repo is initialized
git status
# Expected: "No commits yet" with lots of untracked files
```

---

## 4. Create GitHub Repository

Now create the **empty** repository on GitHub. **Do not** initialize it with a README, .gitignore, or license — you already have those locally.

### Option A: Create via GitHub CLI (Recommended)

```bash
# Create an EMPTY public repository on GitHub
gh repo create FuckProtect \
  --public \
  --description "Android APK protection tool — prevents reverse engineering like JiGu 360, DexProtector" \
  --remote origin

# This does three things:
#   1. Creates the empty repo on github.com/YOUR_USERNAME/FuckProtect
#   2. Adds 'origin' as a remote pointing to it
#   3. Sets the default branch to track origin/main
```

Or create a **private** repository:

```bash
gh repo create FuckProtect \
  --private \
  --description "Android APK protection tool" \
  --remote origin
```

### Option B: Create via GitHub Website

If `gh repo create` fails, use the browser:

1. Open https://github.com/new
2. Repository name: `FuckProtect`
3. Description: `Android APK protection tool — prevents reverse engineering`
4. **⚠️ IMPORTANT: Leave all three checkboxes UNCHECKED:**
   - ☐ Add a README file
   - ☐ Add .gitignore
   - ☐ Choose a license
5. Click **Create repository**
6. Copy the repository URL:
   ```
   https://github.com/YOUR_USERNAME/FuckProtect.git
   ```
7. Back in Termux, connect the remote:
   ```bash
   cd /storage/emulated/0/AndroidCSProjects/FuckProtect
   git remote add origin https://github.com/YOUR_USERNAME/FuckProtect.git
   ```

### Verify Remote Connection

```bash
git remote -v
# Expected:
# origin  https://github.com/YOUR_USERNAME/FuckProtect.git (fetch)
# origin  https://github.com/YOUR_USERNAME/FuckProtect.git (push)

# Test connection
git ls-remote origin
# Expected: lists refs (should be empty since no commits yet)
```

---

## 5. Create `.gitignore`

Create a `.gitignore` file in the project root to exclude build artifacts and sensitive files:

```bash
cat > .gitignore << 'EOF'
# ─── Gradle ──────────────────────────────────────────
.gradle/
local.properties
build/
*/build/

# ─── IDE ─────────────────────────────────────────────
.idea/
*.iml
*.ipr
*.iws
.vscode/
*.swp
*.swo
*~

# ─── C/C++ Build Artifacts ──────────────────────────
.cxx/
*.o
*.so.debug
*/obj/

# ─── OS Files ───────────────────────────────────────
.DS_Store
Thumbs.db

# ─── Secrets & Keys ─────────────────────────────────
*.jks
*.keystore
*.pem
**/secrets/
**/keys/

# ─── APK Build Outputs (keep source, not binaries) ──
*.apk
*.aab
*-release-unsigned.apk

# ─── Termux ─────────────────────────────────────────
termux.properties

# ─── Misc ───────────────────────────────────────────
*.log
captures/
.externalNativeBuild/
EOF
```

Verify the `.gitignore` is in place:

```bash
cat .gitignore | head -10
```

---

## 6. Add, Commit & Push

### Step 1: Check Status

```bash
git status
```

This shows all untracked, modified, and staged files. You should see lots of new files.

### Step 2: Review What Will Be Committed

```bash
# See what will be added (dry run)
git add --dry-run .

# Count files that will be tracked
git ls-files --others --exclude-standard | wc -l
```

### Step 3: Add All Files

```bash
git add .
```

### Step 4: Verify Staged Files

```bash
# See staged files
git status

# Count staged files
git diff --cached --name-only | wc -l
# Expected: 60+ files
```

### Step 5: Commit

```bash
git commit -m "chore: initial commit — FuckProtect APK protection tool

- Protector CLI: DEX encryption, APK repackaging, manifest hijacking
- Shell Runtime: AES-256-CBC decryption, class loader injection
- Native C++: anti-debugging, anti-hooking, integrity checks, O-LLVM
- Gradle plugin: drop-in protection for any Android project
- 76/76 tasks complete across 4 phases (13 sprints)
- 50 source files, 11 tests, 7 documentation files
"
```

### Step 6: Push to GitHub

```bash
# Push the main branch
git push -u origin main
```

If you get a size warning (large build artifacts), see the troubleshooting section below.

### Expected Output

```
Enumerating objects: 150, done.
Counting objects: 100% (150/150), done.
Delta compression using up to 8 threads
Compressing objects: 100% (130/130), done.
Writing objects: 100% (150/150), 245.67 KiB | 2.34 MiB/s, done.
Total 150 (delta 20), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (20/20), done.
To https://github.com/YOUR_USERNAME/FuckProtect.git
 * [new branch]      main -> main
branch 'main' set up to track 'origin/main'.
```

---

## 7. Verify on GitHub

### Check Repository via CLI

```bash
# View repo info
gh repo view YOUR_USERNAME/FuckProtect

# List workflow runs (CI/CD)
gh run list --repo YOUR_USERNAME/FuckProtect

# View the latest CI run
gh run view --repo YOUR_USERNAME/FuckProtect
```

### Check Repository in Browser

Open in your phone's browser:
```
https://github.com/YOUR_USERNAME/FuckProtect
```

Verify:
- ✅ All source files are present
- ✅ `doc/` folder with all documentation
- ✅ `.github/workflows/build.yml` exists
- ✅ `gradlew` is executable
- ✅ No build artifacts (`.gradle/`, `build/`, `.cxx/`)

---

## 8. Troubleshooting

### Problem: "Permission denied" or "Authentication failed"

```bash
# Re-authenticate
gh auth logout
gh auth login

# Or use a personal access token instead
gh auth login --with-token <<< "ghp_YOUR_TOKEN_HERE"
```

### Problem: Push rejected — remote already has commits

```bash
# Force push (ONLY if this is your first push and you're sure)
git push -f origin main

# OR pull first then push
git pull origin main --allow-unrelated-histories
git push origin main
```

### Problem: Repository too large (>100MB)

Large build artifacts are being tracked. Clean them up:

```bash
# Remove build directories
rm -rf .gradle/ */build/ .cxx/

# Remove from git index if accidentally committed
git rm -r --cached .gradle/ */build/ .cxx/

# Commit the cleanup
git add -u
git commit -m "chore: remove build artifacts from tracking"

# Push
git push origin main
```

### Problem: `.gitignore` not working for already-tracked files

```bash
# Remove cached files that should be ignored
git rm -r --cached .gradle/ build/ */build/ .cxx/
git commit -m "chore: clean up tracked files that should be gitignored"
git push origin main
```

### Problem: `gh: command not found`

```bash
# Make sure gh is installed
pkg install gh

# If still not found, check PATH
echo $PATH

# Add Termux bin to PATH if needed
export PATH=$PATH:$PREFIX/bin
```

### Problem: Out of storage space on Termux

```bash
# Check storage
df -h /storage/emulated/0

# Clean up old builds
./gradlew clean
rm -rf app/build/ app/.cxx/

# Check large files
du -sh * | sort -rh | head -10
```

### Problem: Slow push on mobile data

```bash
# Compress more aggressively
git config core.compression 9

# Push with thin pack
git push --thin origin main

# Or use SSH instead of HTTPS (faster)
git remote set-url origin git@github.com:YOUR_USERNAME/FuckProtect.git
git push origin main
```

---

## Quick Reference — All Commands

```bash
# ─── Setup ───────────────────────────────────────────
pkg install git gh
cd /storage/emulated/0/AndroidCSProjects/FuckProtect
git init
git branch -M main
git config user.name "YOUR_USERNAME"
git config user.email "your@email.com"

# ─── Authenticate ────────────────────────────────────
gh auth login
gh auth status

# ─── Create Empty GitHub Repo ────────────────────────
gh repo create FuckProtect --public --description "Android APK protection tool" --remote origin

# ─── Add & Commit ────────────────────────────────────
git add .
git commit -m "initial commit"

# ─── Push ────────────────────────────────────────────
git push -u origin main

# ─── Verify ──────────────────────────────────────────
gh repo view YOUR_USERNAME/FuckProtect
gh run list --repo YOUR_USERNAME/FuckProtect
```

---

## Post-Push Checklist

After pushing, verify these items:

- [ ] Repository is visible at `https://github.com/YOUR_USERNAME/FuckProtect`
- [ ] All 60+ source files are present
- [ ] `.gitignore` is committed
- [ ] No build artifacts (`.gradle/`, `build/`, `.cxx/`) in the repo
- [ ] `gradlew` has execute permission (`-rwxr-xr-x`)
- [ ] `.github/workflows/build.yml` exists
- [ ] GitHub Actions workflow starts automatically (check the Actions tab)
- [ ] Repository description and topics are set

```bash
# Add topics to your repo
gh repo edit YOUR_USERNAME/FuckProtect \
  --description "Android APK protection tool — AES-256 DEX encryption, anti-debugging, anti-hooking, O-LLVM" \
  --add-topic android \
  --add-topic security \
  --add-topic apk \
  --add-topic anti-reverse-engineering \
  --add-topic dex-encryption \
  --add-topic native-code
```
