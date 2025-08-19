# 📤 GitHub Setup Guide for PhishGuard

Follow these steps to push your PhishGuard project to GitHub:

## 1. 🔒 Security Check (IMPORTANT!)

Before uploading to GitHub, ensure sensitive files are protected:

### ✅ Verify .gitignore is working:
```bash
# Check what files will be committed
git status

# These files should NOT appear in the list:
# ❌ .env (contains MongoDB credentials)
# ❌ backend/screenshots/ (contains website images)  
# ❌ .venv/ (virtual environment)
# ❌ __pycache__/ (Python cache)
```

### ⚠️ If you see sensitive files in `git status`:
```bash
# Remove from tracking
git rm --cached .env
git rm -r --cached backend/screenshots/
git rm -r --cached .venv/
git rm -r --cached __pycache__/

# Commit the .gitignore
git add .gitignore
git commit -m "Add .gitignore to protect sensitive files"
```

## 2. 🚀 Initial Git Setup

```bash
# Navigate to project directory
cd c:\Users\adity\OneDrive\Desktop\cyber\phishguard-mvp

# Initialize git repository
git init

# Add .gitignore first (most important!)
git add .gitignore
git commit -m "Add .gitignore for security"

# Add all project files
git add .
git commit -m "Initial commit: PhishGuard MVP with 100% accuracy on legitimate sites"
```

## 3. 🌐 Create GitHub Repository

1. Go to [GitHub](https://github.com)
2. Click "+" in top right → "New repository"
3. Repository name: `phishguard-mvp`
4. Description: `AI-powered phishing detection system with 100% accuracy on legitimate websites`
5. Choose "Public" or "Private"
6. **DO NOT** check "Initialize with README" (you already have one)
7. Click "Create repository"

## 4. 📤 Push to GitHub

```bash
# Add GitHub remote (replace 'yourusername' with your GitHub username)
git remote add origin https://github.com/yourusername/phishguard-mvp.git

# Push to GitHub
git branch -M main
git push -u origin main
```

## 5. ✅ Verify Upload

Check your GitHub repository to ensure:
- ✅ README.md displays properly
- ✅ All source code files are present
- ❌ NO .env file (should be missing - this is good!)
- ❌ NO screenshots/ folder (should be missing - this is good!)
- ❌ NO .venv/ folder (should be missing - this is good!)

## 6. 📝 Setup Instructions for Others

Update the README.md clone URL:
1. Go to your GitHub repository
2. Click the green "Code" button
3. Copy the HTTPS URL
4. Replace the clone URL in README.md

## 🔐 Security Reminder

**NEVER commit these files to GitHub:**
- `.env` - Contains MongoDB credentials
- `backend/screenshots/` - Contains website images
- `.venv/` - Large virtual environment
- `__pycache__/` - Python cache files
- Any API keys or passwords

## 📋 Pre-Push Checklist

- [ ] `.gitignore` file created and committed first
- [ ] `.env.example` template provided for users
- [ ] No sensitive credentials in any committed files
- [ ] README.md updated with correct clone URL
- [ ] All test files removed
- [ ] License file added
- [ ] Repository description set

Your PhishGuard project is now ready for GitHub! 🚀
