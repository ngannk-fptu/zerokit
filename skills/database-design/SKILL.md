---
name: database-design
description: Database Security Design. Schema hardening, SQL Injection prevention, Encryption at Rest, and Least Privilege access control.
tools: Read, Write, Edit, Glob, Grep
---

# Database Security Design

> "Data is the asset. The database is the vault."

## 1. Injection Prevention (The Basics)

### 🚩 Red Flags
- **String Concatenation**: `query = "SELECT * FROM users WHERE name = '" + name + "'"`
- **Dynamic Table Names**: `SELECT * FROM ${table}`
- **Unsafe ORM usage**: `sequelize.literal()`, `knex.raw()`

### ✅ The Fix
- Use **Parameterized Queries**: `db.execute('SELECT * FROM users WHERE name = ?', [name])`
- Use **Strict ORM Methods**: `prisma.user.findMany({ where: { name } })`

---

## 2. Schema Hardening

### Data Leakage
- **Select ***: Do not use `SELECT *`. You might return `password_hash` or `ssn` unintentionally.
- **DTOs**: Ensure the API layer maps DB entities to safe DTOs (Data Transfer Objects).

### Encryption at Rest
- **PII**: Emails, Phones, Names should be encrypted if high-risk.
- **Secrets**: API Keys, Tokens should be hashed (SHA256/Argon2).
- **Passwords**: **Argon2** or **Bcrypt**. Never MD5/SHA1.

---

## 3. Access Control (Least Privilege)

The Application User should NOT be `root`.

| Role | Permissions |
|------|-------------|
| **App_Read** | `SELECT` on specific tables. |
| **App_Write** | `INSERT`, `UPDATE` on specific tables. |
| **Migration** | `ALTER`, `CREATE`, `DROP` (Run only in CI/CD). |
| **Root** | `ALL` (Locked away). |

---

## 4. ORM Specifics

### Prisma
- **Audit**: Check `schema.prisma`. Are sensitive fields marked?
- **Mass Assignment**: Prisma protects this mostly, but check for spread operators `...input`.

### TypeORM / Sequelize
- **Raw Queries**: Grep for `.query()`, `.raw()`. High risk.

---

## 5. When to Use
- "Audit the database schema for sensitive data exposure."
- "Check if this SQL query is vulnerable to injection."
- "Review the database user permissions."
