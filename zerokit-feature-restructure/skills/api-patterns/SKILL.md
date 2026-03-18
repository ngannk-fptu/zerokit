---
name: api-patterns
description: Security patterns for APIs (REST, GraphQL, tRPC). Broken Object Level Authorization (BOLA), Rate Limiting, Injection, and Mass Assignment.
tools: Read, Write, Edit, Glob, Grep
---

# API Security Patterns

> "The API is the door to the database. Is it locked?"

## 1. Top API Vulnerabilities (OWASP API Top 10)

| ID | Name | The "Smell" |
|----|------|-------------|
| **API1** | **BOLA (IDOR)** | `/api/user/123` -> Can I see user 124? |
| **API2** | **Broken Auth** | Weak tokens, no rotation, exposed keys. |
| **API3** | **BFLA (Function Level)** | `/admin/deleteUser` -> Can a regular user call this? |
| **API6** | **Mass Assignment** | `updateUser({ role: 'admin' })` -> Did it work? |

---

## 2. Analysis Methodology

### Step 1: Endpoint Enumeration
Find the routes.
- **REST**: Look for `app.get()`, `router.post()`.
- **GraphQL**: Look for `type Query`, `type Mutation`.
- **tRPC**: Look for `.query()`, `.mutation()`.

### Step 2: Auth Check
Map the middleware.
- Matches: `app.use(authMiddleware)`
- **Gaps**: Are there routes *defined before* the middleware?
- **Logic**: Does the middleware actually *validate* the token?

### Step 3: Authorization (The Hard Part)
Does the controller check ownership?
```javascript
// BAD
app.get('/notes/:id', (req) => {
  return db.find(req.params.id); // Returns note regardless of owner
})

// GOOD
app.get('/notes/:id', (req) => {
  return db.find({ id: req.params.id, ownerId: req.user.id });
})
```

---

## 3. Technology Specifics

### REST
- **Verb Tampering**: Can I use `HEAD` to bypass auth?
- **Content-Type**: Can I send XML (XXE) to a JSON endpoint?

### GraphQL
- **Introspection**: Is it enabled in prod? (Info disclosure)
- **Depth Limit**: Can I ask for `user { friends { user { friends ... } } }`? (DoS)

### tRPC
- **Input Validation**: Is Zod validation applied to inputs?
- **Context**: Is `ctx.user` trusted blindly?

---

## 4. Semgrep Rules for APIs

```yaml
rules:
  - id: express-shadowed-middleware
    patterns:
      - pattern: |
          app.get($ROUTE, ...)
          app.use($MIDDLEWARE)
    message: "Route defined before middleware. It might be unauthenticated."
    severity: ERROR
```

---

## 5. When to Use
- "Review this API for IDOR."
- "Check if Mass Assignment is possible on the update profile endpoint."
- "Audit the GraphQL schema for excessive complexity."
