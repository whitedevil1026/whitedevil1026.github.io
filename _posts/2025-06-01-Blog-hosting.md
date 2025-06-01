---
title: "How to Host a Website Using GitHub and Chirpy Starter"
date: 2025-06-01
categories: [web]
tags: [jekyll, ruby, vs-code]
---

## 🚀 How to Host a Website Using GitHub and Chirpy Starter

If you're looking to host a static blog website using GitHub Pages and Jekyll (specifically the **Chirpy Starter** template), follow these easy steps:


### **1. Use the Chirpy Starter Template**

* Visit the Chirpy Starter repo: [https://github.com/cotes2020/chirpy-starter](https://github.com/cotes2020/chirpy-starter)
* Click **"Use this template"**, then select **"Create a new repository"**.
* Name the repository as:
  `your-github-username.github.io`
  (This will become your website’s URL).

---

### **2. Configure Repository Settings**

* Once the repo is created, open the `config.yml` file.
* Update the `url` field to your GitHub Pages link, like:
  `https://your-github-username.github.io`
* Commit the changes.

---

### **3. Clone the Repository Locally**

* Copy the **HTTPS clone URL** of your new repository.
* Open **File Explorer**, choose a folder, and **Git Bash** into it:

  ```bash
  git clone https://github.com/your-username/your-repo-name.git
  cd your-repo-name
  ```
```bash
MINGW64 /d/B10g
git clone https ://gi thub.io.git
loning into 'whitedevi11026.gi thub.io'. .
remote: Enumerating objects: 40, done.
remote: Counting objects: 100% (40/40), done.
remote: Compressing objects: 100% (32/32), done.
remote: Total 40 (delta 2), reused 28 (delta 0), pack-reused O (from 0)Receiving
receiving objects :
(15/40)
rceiving objects: 100% (40/40), 13.22 KiB | 1.89 MiB/s, done.
solving deltas: 100% (2/2), done.
```
---

### **4. Open in VS Code**

* Launch the project in **Visual Studio Code** for local edits.

---

### **5. Install Ruby and Jekyll**

To build and run the site locally, you'll need Ruby and Jekyll:

* Follow the [official installation guide for Windows](https://jekyllrb.com/docs/installation/windows/)
* Ensure your system version (x32 or x64) matches the installer.
* Install **MSYS2** and the **MINGW development toolchain** for Ruby.
* Then, run the following in your terminal:

```bash
gem install jekyll bundler
jekyll -v   # To verify installation
```

---

### **6. Install Dependencies & Run the Site Locally**

* Inside VS Code, open the terminal and run:

```bash
bundle    # Installs required dependencies
bundle exec jekyll s   # Builds and serves your blog locally
```

Example output:

```bash
PS D:\Blog> cd your-repo-name
PS D:\Blog\your-repo-name> bundle
Bundle complete! 5 Gemfile dependencies, 66 gems now installed.
PS D:\Blog\your-repo-name> bundle exec jekyll s
```

Your site should now be accessible locally at `http://127.0.0.1:4000`.

---

### **7. Customize Your Blog**

* Edit the `config.yml` file to update:

  * Blog name
  * Social media handles
  * Author avatar and description

---

### **8. Optional: Auto-Refresh Plugin (Optional)**

To enable auto-refresh during development, add this code to your plugin file:

```ruby
# frozen_string_literal: true

require 'jekyll-watch'

module Jekyll
  module Watcher
    extend self

    alias_method :original_listen_ignore_paths, :listen_ignore_paths

    def listen_ignore_paths(options)
        original_listen_ignore_paths(options) + [%r!.*\.TMP!i]
    end
  end
end
```

---

### **9. Create Blog Posts**

* Navigate to the `_posts` folder.
* Create a Markdown file with the format:
  `YYYY-MM-DD-title.md`
  Example: `2025-06-01-hello-world.md`
* After editing, **commit and push** your changes to GitHub:

```bash
git add .
git commit -m "Add new post"
git push
```

Your website will automatically update on [https://your-github-username.github.io](https://your-github-username.github.io).

---

### ✅ You're Done!

You’ve successfully hosted a blog website using GitHub Pages, Jekyll, and the Chirpy Starter template. Now start writing and sharing your thoughts with the world!

---
