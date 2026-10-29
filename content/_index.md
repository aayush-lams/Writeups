---
title: Writeups
date: 2026-10-28
category: Overview
---

# Writeups

A collection of technical write-ups, notes, and practical guides as I learn Linux system administration and cybersecurity.

## Getting Started

This is the source-ready Hugo site. To deploy:

```bash
# Clone repo
git clone <url> writeups
cd writeups

# Install Hugo
brew install hugo   # macOS / Homebrew
# or download from https://gohugo.io/getting-started/installation/

# Build the site
hugo --themes-dir=themes

# Push the built site to GitHub Pages
cd public
git init && git add . && git commit -m "Deploy to GitHub Pages"
git remote add origin https://github.com/<user>/Writeups.git
git push -f origin main
```

Then in repo Settings → Pages, set Source = `main`, Folder = `/public`.

Visit at: `https://aayush-lamsal.github.io/Writeups/`