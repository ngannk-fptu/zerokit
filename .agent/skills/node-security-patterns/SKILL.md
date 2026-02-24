---
name: node-security-patterns
description: Advanced Node.js/JavaScript security patterns. Prototype Pollution, Event Loop Lag, VM escape, Buffer manipulation.
tools: Read, Grep, Glob
---

# Node.js Security Patterns

## 1. Prototype Pollution
The ability to modify `Object.prototype` allows attackers to affect code execution globally.
- **Pattern**: Recursive merge functions (`lodash.merge`, `extend`).
- **Sink**: `target[key] = value` on `__proto__`.
- **Impact**: DoS, RCE (if gadgets exist), Auth Bypass.

## 2. Event Loop Lag (ReDoS)
Node.js is single-threaded. One regex can kill it.
- **Pattern**: `(a+)+` regex on user input.
- **Impact**: Denial of Service (100% CPU).

## 3. Server-Side Request Forgery (SSRF) in JS
- **Pattern**: `axios.get(user_url)` or `fetch(user_url)`.
- **Bypass**: DNS Rebinding, IPv6 `[::]`, Octal IPs `0177.0.0.1`.

## 4. Buffer Manipulation
- **Pattern**: `new Buffer(number)` (Old Node) -> Uninitialized memory leak.
- **Pattern**: `Buffer.from(input, 'base64')` -> Type confusion if input is not string.

## 5. VM Sandbox Escape
- **Library**: `vm2` (Deprecated/Vulnerable), `vm` (Not security).
- **Pattern**: Accessing `this.constructor.constructor("return process")()`.
