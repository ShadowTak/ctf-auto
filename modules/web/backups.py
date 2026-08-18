"""Backup files, source-control disclosure and config leaks."""
from core import httpx
from core.flag import extract_flags
from core.notfound import calibrator_for
from core.parallel import pmap

CHECKS = [
    # path, description
    (".git/HEAD", "Git repository exposed"),
    (".git/config", "Git config exposed"),
    (".git/", "Git dir listing"),
    (".env", "Env file"),
    (".env.backup", "Env backup"),
    (".env.local", "Env local"),
    (".htaccess", "Apache .htaccess"),
    (".htpasswd", "Apache .htpasswd"),
    ("config.php.bak", "config backup"),
    ("config.php~", "config editor backup"),
    ("config.php.swp", "config vim swap"),
    ("index.php.bak", "index backup"),
    ("index.php~1", "index backup"),
    ("index.php~", "index editor backup"),
    ("index.html.bak", "index html backup"),
    ("wp-config.php", "WordPress config"),
    ("wp-config.php.bak", "WordPress config backup"),
    ("composer.json", "composer manifest"),
    ("package.json", "npm manifest"),
    ("package-lock.json", "npm lockfile"),
    ("Dockerfile", "Dockerfile"),
    ("docker-compose.yml", "docker-compose"),
    ("server.js", "node server"),
    ("app.js", "node app"),
    ("main.js", "node main"),
    (".DS_Store", "macOS .DS_Store"),
    ("backup.zip", "backup zip"),
    ("backup.tar", "backup tar"),
    ("backup.tar.gz", "backup tar.gz"),
    ("backup.sql", "SQL dump"),
    ("db.sql", "SQL dump"),
    ("dump.sql", "SQL dump"),
    ("database.sql", "SQL dump"),
    ("data.db", "SQLite db"),
    ("sqlite.db", "SQLite db"),
    ("flag.txt", "flag file!"),
    ("flag.php", "flag file!"),
    ("secret.txt", "secret file"),
    ("users.txt", "users file"),
    ("passwords.txt", "passwords file"),
    ("note.txt", "note file"),
    ("notes.txt", "notes file"),
    ("key.pem", "private key"),
    ("id_rsa", "ssh private key"),
    ("id_rsa.pub", "ssh public key"),
    ("credentials.json", "credentials"),
    ("serviceAccount.json", "service account"),
    ("auth.json", "auth token"),
    (".npmrc", "npm config"),
    (".pypirc", "pypi config"),
    ("web.config", "IIS config"),
    ("crossdomain.xml", "crossdomain policy"),
    ("phpinfo.php", "phpinfo"),
    ("info.php", "phpinfo"),
    ("test.php", "test script"),
    ("shell.php", "webshell?"),
    ("upload.php", "upload script"),
]

LEAK_MARKERS = {
    ".git/config": [b"[core]", b"repositoryformatversion"],
    ".git/HEAD": [b"ref:"],
    ".env": [b"="],
    ".htpasswd": [b":"],
    "wp-config.php": [b"DB_PASSWORD", b"DB_USER"],
    "composer.json": [b"require"],
    "package.json": [b"dependencies"],
    "Dockerfile": [b"FROM", b"RUN"],
    "id_rsa": [b"-----BEGIN"],
    "key.pem": [b"-----BEGIN"],
    "credentials.json": [b"{"],
    ".npmrc": [b"token", b"registry"],
}


def run_backup_checks(base, workers=24):
    """Check common leak paths in parallel. Returns (findings, flags)."""
    findings = []
    flags = []
    cal = calibrator_for(base)

    def check(entry):
        path, desc = entry
        r = httpx.get(base + "/" + path, timeout=6)
        if r is None or cal.is_missing(r):
            return None
        body = r.body
        markers = LEAK_MARKERS.get(path)
        if markers and not any(m in body for m in markers):
            # 200 but doesn't look like the real file — skip (redirect page etc.)
            if r.status == 200 and len(body) < 4000:
                return None
        return (path, desc, r.status, len(body), r.headers.get("content-type", ""))

    for entry, res in pmap(check, CHECKS, workers=workers, desc="leak check"):
        if isinstance(res, Exception) or res is None:
            continue
        path, desc, status, size, ctype = res
        findings.append((path, desc, status, size))
        # fetch body for flag scan on likely-text hits
        if status == 200 and size < 200_000:
            r = httpx.get(base + "/" + path, timeout=8)
            if r is not None:
                text = r.body.decode("latin-1", "replace")
                known, cands = extract_flags(text)
                flags.extend(known + cands)
                if known or cands:
                    findings.append((path, f"FLAG: {known or cands}", status, size))
    return findings, list(dict.fromkeys(flags))
