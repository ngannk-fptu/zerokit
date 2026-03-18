---
name: java-security-patterns
description: Advanced Java security patterns. Gadget Chains, OGNL Injection, Spring SpEL, XXE, Deserialization.
tools: Read, Grep, Glob
---

# Java Security Patterns

## 1. Java Deserialization
- **Pattern**: `ObjectInputStream.readObject()` on tainted data.
- **Gadgets**: CommonsCollections, Spring, Hibernate gadget chains (ysoserial).
- **Impact**: RCE.

## 2. Expression Language Injection
- **SpEL (Spring)**: `expression.getValue()`
- **OGNL (Struts)**: `ValueStack` manipulation.
- **Impact**: RCE.

## 3. SQL Injection (HQL/JPQL)
- **Pattern**: Direct concatenation in Hibernate/JPA.
- **Bypass**: HQL injection often allows data exfiltration even without `UNION`.

## 4. XXE (XML External Entity)
- **Pattern**: `DocumentBuilderFactory` without `setFeature("...disallow-doctype-decl", true)`.
- **Impact**: File Read, SSRF, DoS.

## 5. JNDI Injection
- **Pattern**: `InitialContext.lookup(user_input)`.
- **Impact**: RCE (Log4Shell style) via LDAP/RMI.
