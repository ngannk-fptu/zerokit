---
name: php-security-patterns
description: Advanced PHP security patterns. Type Juggling, Unsafe Deserialization, PHP Wrappers, Magic Methods.
tools: Read, Grep, Glob
---

# PHP Security Patterns

## 1. Type Juggling (Loose Comparison)
- **Pattern**: `if ($hash == "0e123...")`
- **Logic**: PHP treats strings starting with `0e` as float (0.0). `0.0 == 0.0` is true.
- **Fix**: Use `===` (Strict comparison).

## 2. Object Injection (Deserialization)
- **Pattern**: `unserialize($user_input)`
- **Gadgets**: `__wakeup`, `__destruct`, `__toString` in loaded classes (Guzzle, Laravel, Symfony).
- **Impact**: RCE (PHPGGC tool usage).

## 3. PHP Wrappers (LFI -> RCE)
- **Pattern**: `include($file)`
- **Exploit**: `php://filter/react=convert.base64-encode/resource=index.php` (Read source).
- **Exploit**: `php://input`, `expect://id` (RCE).
- **New**: `php://filter` chain attacks (RCE via encoding chains).

## 4. Variable Variables
- **Pattern**: `$$key = $value;`
- **Impact**: Overwriting globals, `_SESSION`, or config values.
