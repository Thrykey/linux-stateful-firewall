# Stateful Linux Firewall Script

A Bash implementation of a stateful Linux firewall utilizing `iptables` and system hardening kernel options (`sysctl`). Developed during Operating System Security lab exercises at university to enforce strict service isolation and dynamic traffic filtering.

## Key Technical Features
* **Stateful Inspection:** Uses connection tracking (`conntrack` / `state`) with default `DROP` policies on all incoming and outgoing chains.
* **Kernel Hardening:** Disables IPv4 packet forwarding and completely turns off IPv6 stack via `sysctl`.
* **DoS Protection:** Rate-limits HTTP incoming connections using the `connlimit` module (rejects resets beyond threshold).
* **Service Control & Access Restrictions:**
  * Strict SSH access limited to designated administrator IP with kernel-level logging (`LOG` target) for unauthorized attempts.
  * Passive FTP dynamic port tracking enabled via `nf_conntrack_ftp`.
  * Explicit outbound UDP/TCP DNS filtering.
* **Obfuscation & Bogon Drops:** Modifies outgoing packet TTL values in the `mangle` table and drops unroutable bogon IP ranges.

## Usage
```bash
# Make executable
chmod +x firewall.sh

# Start firewall with strict ruleset
sudo ./firewall.sh start

# Stop firewall and restore default ACCEPT policy
sudo ./firewall.sh stop
