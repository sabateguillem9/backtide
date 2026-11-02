# The web behind a reverse proxy

By default you reach backtide's web through an SSH tunnel or a private network, and that is still what we recommend: the network is a layer of protection that asks nothing of backtide. This guide is for when you want it on a domain of your own, reachable from anywhere.

A **reverse proxy** is a server that receives the visitors' connections and passes them on to a program behind it. Here it holds the HTTPS certificate, and the web stays on the server's loopback address, where nothing from outside can reach it directly.

You need a server where backtide is installed, a **subdomain of its own** (`backtide.example.org`, never a path under another site) and nginx 1.25.1 or newer.

## Set it up

1. **Get a certificate for the name**, with `certbot` or whatever you use, and [plan its renewal](#renewing-the-certificate). The example file expects Let's Encrypt's paths.
2. **Copy the example** `deploy/reverse-proxy/backtide.nginx.conf` to `/etc/nginx/conf.d/backtide.conf` and change `backtide.example.org`, everywhere it appears, to your name. Its first `server` block closes every other name on this nginx: if the same nginx serves other sites, leave that block out. Without IPv6 on the server, remove the `listen [::]` lines.
3. **Check it and load it:** `sudo nginx -t && sudo systemctl reload nginx`. On Fedora or RHEL with SELinux, let nginx reach the web first: `sudo setsebool -P httpd_can_network_connect 1`. Without it, every page is a 502.
4. **Tell backtide its name.** Add this to both `/etc/backtide/backtide.toml` and `/etc/backtide/web.toml`, and restart with `sudo systemctl restart backtide backtide-web`:

   ```toml
   [web]
   public_origin = "https://backtide.example.org"
   ```

   [Configuration](configuration.md#web-public_origin-the-web-on-a-domain) has what this changes. The important part: **the SSH tunnel stops working** while it is set, and the way in is a passkey, with no password.
5. **Register your first key.** `sudo backtide enlace` prints a one-time link on your domain. Open it, register a passkey, then register a second one on another device. Once there is a key, the link stops working.

## Who does what

**backtide does this by itself**, with or without a proxy in front:

- It answers one `Host` and one `Origin`, your domain's, and refuses the rest. `127.0.0.1` too, so a proxy that passes any name on does not make a request "local".
- It listens only on loopback, and it believes no `X-Forwarded-*` header.
- It wants a session on every page and order, and a recently touched passkey for what outlasts the session. Its cookie is `__Host-backtide_web`: `Secure`, `HttpOnly`, `SameSite=Strict`.
- It accepts signatures made for your domain only, checked by the service, not by the web.
- It caps sign-ins, wrong links and made-up cookies, for the whole web. It sends the security headers (CSP and the rest) on every answer, and tells nginx not to buffer its live pages.

**The proxy has to do this**, and the example file does it. Each of these is run in a real nginx by the [attack battery](attack-battery.md) (`web-tras-el-proxy`, `tope-por-direccion`):

| What | Why | In the file |
|---|---|---|
| HTTPS, and only for this name | A passkey only works over HTTPS, and nothing should answer to other names | `ssl_certificate`, the `default_server` block |
| Port 80 goes to HTTPS, with HSTS | HSTS tells the browser to never try plain HTTP again, so nobody can read or change the first request | `return 301`, `Strict-Transport-Security` |
| Pass `Host` as the browser sent it | Otherwise every request gets a 400 | `proxy_set_header Host $http_host` |
| A cap per address on `/entrar/llave/` | See [below](#what-happens-without-the-cap) | `limit_req zone=backtide_sign_in` |
| Timeouts, and hold the body until it is all in | So that slow connections wait in nginx and do not hold the web's 64 connections | `client_body_timeout`, `client_header_timeout`, `proxy_request_buffering` |
| Do not log the query string or the `Referer` | The one-time link's token travels in `/?t=...` | `log_format backtide`, `error_log ... crit` |

Two of these are easy to get wrong if you write your own configuration:

- **Logs.** nginx's usual `combined` format has the whole request line and the `Referer`, so the token goes in. So does any line of the error log at `error` level, which is why the file sets `crit`: a failed upstream still shows in the access log, as its 502. The token works once and for 15 minutes, and only until your first key exists, but a token in a log is still a way in for that long. `crit` covers the usual failures, not all of them: SELinux refusing the connection is logged at `crit`, request included. If your first link gives a 502, fix that and ask for another link: `sudo backtide enlace`.
- **`client_header_timeout`** has to be outside the site's `server` block. nginx has not chosen a `server` by name while it reads the head, so there it is ignored and half-sent heads wait the default 60 seconds.

## Renewing the certificate

With HSTS for a year, a browser will not let you click past an expired certificate: you stay out of the web until it is renewed, and only SSH is left. So try the renewal before you rely on it, with `sudo certbot renew --dry-run`.

The example answers everything on port 80 with its redirect, so the HTTP challenge cannot get through it (`certbot --webroot` fails). Renew with the DNS challenge, or with `--standalone` and hooks that free the port: `--pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"`. With the DNS challenge, add `--deploy-hook "systemctl reload nginx"`, or nginx keeps the old certificate.

## What happens without the cap

backtide does not believe `X-Forwarded-For`, because anyone can send that header, so **its own caps cannot go by address**: there is one bucket of sign-in attempts for the whole web. Anyone with a `curl` can empty it, with no key and no account, by asking for sign-in challenges in a loop:

```bash
while true; do curl -s -X POST -H 'Origin: https://backtide.example.org' \
  -H 'Content-Type: application/x-www-form-urlencoded' -d '' \
  https://backtide.example.org/entrar/llave/empezar; done
```

While that lasts, **you cannot sign in with your own key**. They get no further than you do (nothing opens without a signature), but you stay out for as long as they keep at it. Sessions already open are not affected, since they do not spend that bucket.

With the cap, one address gets six requests at once and then one every ten seconds, which is less than the service gives back, so it can never empty the bucket on its own. You get a `429` if you sign in and fail several times in a row.

**The cap has a limit.** It stops one address. A few of them can still empty the bucket, since the service gives back ten answers a minute and each address may spend six. An IPv6 address counts by its `/64`, so one customer of a hosting company usually counts as one, but someone with several addresses does not. If it happens, **the way back is SSH**, which is not behind any of this:

- The command line still works: `sudo backtide rebobinar`, `sudo backtide llaves`, `sudo backtide tarea` and the rest. So does Telegram.
- Block the addresses you see in `/var/log/nginx/backtide.access.log`, in your firewall (each `429` line has one; an attacker who stays under the cap leaves none, but its requests to `/entrar/llave/` are there). For IPv6, block the whole `/64`, not the address the log shows.
- To use the web anyway, remove `public_origin` from both files and restart, and go back to the SSH tunnel. The keys of each name wait in their own file.

As soon as the flood stops, the bucket refills and you can sign in again.

## Things to know

- **A proxy or CDN in front of nginx** (Cloudflare and the like) makes every visitor look like one address, and then one flood locks everyone out. Set nginx's `set_real_ip_from` to that provider's ranges only and `real_ip_header` to the header it sends (`CF-Connecting-IP` for Cloudflare), and remember that it also sees the link's token and may log it.
- **The agent can be a visitor too.** It has no way to the server's addresses from its cage, and its proxy refuses private ones, but if your domain has a public address the agent can ask for it like anyone on the internet. It meets what anyone meets, a page that asks for a passkey, and it can spend the same cap.
- **Other proxies.** Caddy needs a plugin for a cap per address (`caddy-ratelimit`, not in its standard build), which is why the example is nginx. Whatever you use has to do everything in the table, and must not buffer the live pages (the paths that end in `/stream`, which nginx learns from their `X-Accel-Buffering: no`).
- **The answers you may see.** A `400 Host not allowed` means the proxy is not passing your domain as `Host`, or `public_origin` has another name or port. A `403` on a change means `Origin` is not your domain. A `503` from the web means it could not check a session just then, and does not mean you are signed out. A `429` comes from nginx: wait a minute. A `502` means nginx could not reach the web: it is not running (`sudo systemctl status backtide-web`), or SELinux stops nginx (see step 3).
