---
name: architecture-mapper
description: Automated codebase mapping. Generates `routes.json` and `middleware.json` to speed up recon.
tools: Read, Run, Grep, Glob
scripts: map_routes.py
---

# Architecture Mapper

> "Don't guess where the code is. Know where the code is."

## Purpose

Instead of manually grepping for `app.get` or `@Controller`, run the mapper to generate a JSON index of the application's structure.

## Usage

```bash
python .agent/skills/architecture-mapper/scripts/map_routes.py --target .
```

## Output Format (`routes.json`)

```json
[
  {
    "method": "POST",
    "path": "/login",
    "file": "src/controllers/AuthController.ts",
    "line": 45,
    "framework": "express",
    "middleware": ["rateLimit", "csrf"]
  }
]
```

## Supported Frameworks (Regex Based)

- **Node**: Express, Fastify, Hono
- **Python**: Flask, FastAPI, Django
- **Java**: Spring Boot (`@RequestMapping`)
- **PHP**: Laravel (`Route::get`), Symfony
- **Go**: Gin, Echo, standard `http`

## Integration

Use this output to feed `cve-researcher`.
> "I see a POST /login in AuthController.ts. Check it for NoSQL injection."
