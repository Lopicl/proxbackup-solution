# Network and firewall

## Ports

PCs only connect out; nothing connects to them. Open these from the PC VLANs:

| From | To | Port | Used for |
| --- | --- | --- | --- |
| PCs | ProxBackup Console | TCP 8077 (`PROXBACKUP_LISTEN`), or the agent port if split (below) | Enrollment, config long-poll (mTLS), run reports, agent updates |
| PCs | PBS | TCP 8007 (`PROXBACKUP_PBS_PUBLIC_HOST`), or the proxy port (below) | Backup and restore data |
| Admins | ProxBackup Console | TCP 8077 | Web UI |

The console itself sends outbound SMTP/webhooks for notifications and HTTPS to GitHub for updates.

## Keep the console UI away from the PCs

Serve the agent API on its own listener and only allow the UI port from the admin network.
In `/etc/proxbackup/proxbackup.env`:

```sh
PROXBACKUP_LISTEN=10.0.4.10:8077          # web UI
PROXBACKUP_AGENT_ADDR=10.0.4.10:8078      # agent API only (enrollment, mTLS)
PROXBACKUP_PUBLIC_URL=https://10.0.4.10:8078
```

Then `systemctl restart proxbackup-server`.

- The public URL's host must be listed in `PROXBACKUP_HOSTNAMES`. Changing that list reissues the
  console certificate: reload open browser tabs and accept the new certificate.
- Agents learn a changed `PROXBACKUP_PUBLIC_URL` with their next poll and switch once the new
  address answers; the old one is kept as a fallback. Until every PC has switched (Clients →
  *Last seen*), keep the old address listening as well: both variables take a comma separated
  list, e.g. `PROXBACKUP_AGENT_ADDR=10.0.4.10:8078,10.0.9.10:8077`.
- The tray's *Restore files…* opens the web UI on the UI port. If PCs can't reach it, self-service
  restore doesn't work for them.

## Hide the PBS web UI from the PCs (optional)

PBS serves its GUI and the API on the same port (8007), so a firewall can't allow one and block the
other. Agents only use `/api2/json/...` with an API token, so a reverse proxy can pass exactly that
and refuse the GUI and password logins. Example nginx site on the PBS host
(`/etc/nginx/sites-enabled/pbs-agents.conf`):

```nginx
server {
    listen 10.0.4.10:8443 ssl;
    # Must be PBS's own certificate: agents pin its fingerprint
    ssl_certificate     /etc/proxmox-backup/proxy.pem;
    ssl_certificate_key /etc/proxmox-backup/proxy.key;

    client_max_body_size 0;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;

    # No password/ticket logins from the PC VLANs
    location /api2/json/access/ticket { return 403; }

    # API only, token-authenticated
    location /api2/json/ {
        if ($http_authorization !~ "^PBSAPIToken ") { return 403; }
        proxy_pass https://127.0.0.1:8007;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;     # backup/restore protocol upgrade
        proxy_set_header Connection "upgrade";
    }

    # GUI, static files, everything else
    location / { return 403; }
}
```

1. `apt install nginx`, remove `/etc/nginx/sites-enabled/default`, add the site, then
   `nginx -t && systemctl reload nginx`. Check with `ss -tlnp | grep 8443`.
2. Set `PROXBACKUP_PBS_PUBLIC_HOST=10.0.4.10:8443` and restart the console. Agents get the new
   address with their next config sync.
3. Firewall: PCs → 8443 and the agent port; block 8007 and 8077 from the PCs.

Notes:

- Tested against PBS 4.2: the `pkg/pbs` E2E suite and a 2 GiB agent backup and restore pass
  through the proxy; `/`, the GUI scripts, token-less API calls and ticket logins return 403.
- The console's own PBS calls (retention, snapshot listing) also use `PROXBACKUP_PBS_PUBLIC_HOST`,
  so the proxy must be up for them too.
- After PBS renews its certificate (ACME), `systemctl reload nginx`, e.g. from a renewal hook or a
  daily timer. The console picks up the new fingerprint by itself.

## Hosts with several interfaces

If the PBS/console host has interfaces in several networks, PCs must connect to an address whose
replies leave through the same interface. Otherwise the reply takes the default route, a stateful
firewall sees half a TCP session and drops it, and agents time out after about 60 s.

- Check with `ip route get <pc-ip>`: the interface shown must be the one owning the address the
  PCs use.
- Simplest fix: give agents the address on the default-route interface (`PROXBACKUP_PUBLIC_URL`,
  `PROXBACKUP_PBS_PUBLIC_HOST`).
- Otherwise add policy routing for the other address, in `/etc/network/interfaces` under that
  interface:

  ```
  post-up   ip route add default via <gateway-of-iface> dev <iface> table 100
  post-up   ip rule add from <address-on-iface> table 100
  pre-down  ip rule del from <address-on-iface> table 100
  ```
