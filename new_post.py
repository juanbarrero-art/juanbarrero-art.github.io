"""
new_post.py - Crea una nueva entrada del blog con front matter.

Uso:
    python new_post.py "Titulo de la entrada" [tags]
    python new_post.py "Windows internals: procesos" "windows, blue team"

Crea el archivo en content/posts/YYYY-MM-DD-slug.md
"""

import datetime
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
POSTS_DIR = os.path.join(ROOT, "content", "posts")

PLANTILLA = """---
title: {title}
date: {date}
tags: {tags}
summary: Escribe aqui un resumen corto de la entrada.
---

# {title}

Escribe aqui el contenido en Markdown.

## Subtitulo

- Punto uno
- Punto dos
"""


def slugify(s):
    s = s.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    s = re.sub(r"[\s_-]+", "-", s)
    return s.strip("-")


def main():
    if len(sys.argv) < 2:
        print('Uso: python new_post.py "Titulo" [tags]')
        sys.exit(1)

    title = sys.argv[1]
    tags = sys.argv[2] if len(sys.argv) > 2 else "general"
    os.makedirs(POSTS_DIR, exist_ok=True)

    date = datetime.date.today().isoformat()
    slug = slugify(title)
    filename = f"{date}-{slug}.md"
    path = os.path.join(POSTS_DIR, filename)

    if os.path.exists(path):
        print(f"Ya existe: {path}")
        sys.exit(1)

    with open(path, "w", encoding="utf-8") as f:
        f.write(PLANTILLA.format(title=title, date=date, tags=tags))

    print(f"Creado: content/posts/{filename}")
    print("Edita el archivo y luego ejecuta: python build.py")


if __name__ == "__main__":
    main()
