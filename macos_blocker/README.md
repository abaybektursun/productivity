# blocker — System-Level Website Blocker

blocker is a simple macOS script that blocks (or unblocks) specified domains at the **system level** by editing your `/etc/hosts` file. It’s especially useful for productivity, parental controls, or just limiting distractions.

---

## Features

- **Block or unblock** any domain, including subdomains.  
- Automatically **flushes DNS cache** to apply changes immediately.  
- Creates **rotating backups** of your `/etc/hosts`.  
- Offers **health checks** and a **cleanup** function to remove duplicates.  
- **Optional** auto-block of `www.` subdomains alongside your main domain.

---

## Quick Start

1. **Clone or Download** this repository:

   ```bash
   git clone https://github.com/yourusername/blocker.git
   cd blocker
   ```

2. **Make it executable**:

   ```bash
   chmod +x blocker.sh
   ```

3. **Run with `sudo`:**

   ```bash
   sudo ./blocker.sh block example.com
   ```

   > **Note:** Always run with `sudo`, otherwise it can’t edit `/etc/hosts`.

---

## Basic Usage

```bash
sudo ./blocker.sh [command] [domains...]
```

- **block** `[domain ...]` — Block the specified domain(s).  
- **unblock** `[domain ...]` — Unblock the specified domain(s).  
- **status** — Show all currently blocked domains.  
- **enable** — Re-block every domain listed in `domains.txt`.  
- **disable** — Unblock every domain in `domains.txt`.  
- **backup** — Create a timestamped backup of `/etc/hosts`.  
- **restore** — Restore `/etc/hosts` from the original backup.  
- **cleanup** — Remove duplicates and empty lines in `/etc/hosts`.  
- **health** — Check for common `/etc/hosts` issues.  
- **help** — Show usage information.

---

## Tips & Reminders

- **Close and reopen** your browsers after blocking or unblocking. Browsers cache DNS aggressively.  
- If you want to automatically block `www.example.com` when blocking `example.com`, set `ALSO_BLOCK_WWW=true` inside `blocker.sh`.  
- Check if **DNS over HTTPS** (DoH) or a **VPN** might bypass local DNS.  
- To verify blocking quickly, run `ping example.com`. If it returns `127.0.0.1`, blocking is working.

---

## License

This project is provided under the [MIT License](LICENSE). Feel free to fork and modify for personal or commercial use.

---

