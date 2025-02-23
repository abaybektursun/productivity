# System-Level Website Blocker

**SystemBlock** is a pair of Bash scripts that help you block (or unblock) websites at the system level by editing the `/etc/hosts` file. One version is tailored for **macOS** (`macos_blocker.sh`), and the other is tailored for **Ubuntu** (`ubuntu_blocker.sh`). They’re perfect for productivity boosts, parental controls, or simply minimizing distractions.

---

## Scripts Overview

1. **macos_blocker.sh**  
   - Designed specifically for macOS (e.g., macOS Ventura or later).  
   - Uses macOS-specific DNS flushing commands (`dscacheutil` and `killall -HUP mDNSResponder`).  
   - References Safari/Chrome/Firefox in logs for best results.

2. **ubuntu_blocker.sh**  
   - Created for Ubuntu 20.04–24.04+ (or other systemd-resolved distros).  
   - Uses `systemd-resolve --flush-caches` to flush DNS.  
   - Removes macOS-specific operations and references.

Each script includes rotating backups, domain listing, a DNS flush, and convenience features like optional blocking of `www.` subdomains.

---

## Quick Start

1. **Clone or Download** this repository:
   ```bash
   git clone https://github.com/username/SystemBlock.git
   cd SystemBlock
   ```

2. **Pick Your Script**  
   - **macOS** users: `macos_blocker.sh`  
   - **Ubuntu** users: `ubuntu_blocker.sh`

3. **Make the script executable**:
   ```bash
   chmod +x macos_blocker.sh  # or ubuntu_blocker.sh
   ```

4. **Run with `sudo`:**
   ```bash
   sudo ./macos_blocker.sh block example.com
   ```
   or
   ```bash
   sudo ./ubuntu_blocker.sh block example.com
   ```

> **Note:** Always run with **sudo** or as **root**. The script modifies `/etc/hosts`, which requires elevated privileges.

---

## Common Commands

Replace `[script_name]` with either `macos_blocker.sh` or `ubuntu_blocker.sh`, depending on your system.

```bash
sudo ./[script_name] block example.com
sudo ./[script_name] unblock example.com
sudo ./[script_name] status
sudo ./[script_name] enable
sudo ./[script_name] disable
sudo ./[script_name] backup
sudo ./[script_name] restore
sudo ./[script_name] cleanup
sudo ./[script_name] health
sudo ./[script_name] help
```

### Examples

- **Block** multiple domains at once:  
  ```bash
  sudo ./[script_name] block example.com *.example.org badsite.com
  ```
- **Unblock** a domain:  
  ```bash
  sudo ./[script_name] unblock example.com
  ```
- **Show** blocked domains:  
  ```bash
  sudo ./[script_name] status
  ```

---

## Tips & Reminders

1. **Browser Caching**:  
   - Most browsers (Chrome, Firefox, Safari) aggressively cache DNS.  
   - After blocking or unblocking, **close** all browser windows/tabs.  
   - Wait a few seconds, then **reopen** your browser.

2. **Wildcard** (`*.example.com`):  
   - `/etc/hosts` does not truly support wildcard domains.  
   - The scripts will remove the `*.` but **you must manually block** each subdomain if needed.

3. **Check via `ping`**:
   ```bash
   ping example.com
   ```
   - If blocking is working, you should see `127.0.0.1` or get an error.  
   - If you see a real IP address, the domain may not be blocked (check for typos or DNS-over-HTTPS).

4. **DNS over HTTPS (DoH) / VPN**:
   - If you use DoH or a corporate VPN, local `/etc/hosts` changes may be bypassed.

5. **Auto-block `www.`**:
   - In the scripts, `ALSO_BLOCK_WWW=true` means blocking `example.com` also attempts to block `www.example.com`.

---

## License

Provided under the [MIT License](LICENSE). Fork, modify, or distribute freely for personal or commercial use.

**Enjoy simpler, distraction-free computing!**
