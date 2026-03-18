---
name: python-security-patterns
description: Advanced Python security patterns. Pickle, SSTI (Jinja2), PyYAML, Format String vulnerabilities.
tools: Read, Grep, Glob
---

# Python Security Patterns

## 1. Pickle Deserialization
- **Pattern**: `pickle.loads(user_input)`
- **Impact**: Immediate RCE via `__reduce__`.
- **Fix**: Never unpickle untrusted data. Use JSON.

## 2. SSTI (Server Side Template Injection)
- **Target**: Flask/Jinja2, Django.
- **Pattern**: `Template("Hello " + user_input).render()`
- **Exploit**: `{{ config.items() }}`, `{{ "".__class__.__mro__[1]... }}` (RCE).

## 3. PyYAML
- **Pattern**: `yaml.load(input)` (Old versions).
- **Fix**: Use `yaml.safe_load(input)`.

## 4. Format String Injection
- **Pattern**: `"{person.secret}".format(person=user_controlled)` (Less common, but possible).
- **Newer**: f-strings are compile-time (safe), but `eval(f"...")` is RCE.
