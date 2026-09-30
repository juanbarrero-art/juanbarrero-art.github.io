"""
build.py - Generador estatico del blog KANON UFO.

Lee los posts en Markdown de `content/posts/`, los convierte a HTML con las
plantillas de `templates/` y genera:
  - blog/<slug>.html        (una pagina por entrada)
  - blog/index.html         (listado de entradas)
  - actualiza index.html    (seccion "Ultimas entradas" entre marcadores)

Sin dependencias externas (solo stdlib). Markdown soportado:
encabezados, negrita, cursiva, codigo inline, bloques de codigo, enlaces,
imagenes, listas, citas, separadores y parrafos.

Uso:
    python build.py
"""

import html
import os
import re
import datetime
import glob

ROOT = os.path.dirname(os.path.abspath(__file__))
POSTS_DIR = os.path.join(ROOT, "content", "posts")
BLOG_DIR = os.path.join(ROOT, "blog")
TPL_DIR = os.path.join(ROOT, "templates")
INDEX = os.path.join(ROOT, "index.html")

SITE = "KANON UFO"
# Cuantas entradas mostrar en la portada
HOME_COUNT = 3

MESES = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"]


# ------------------------------- Markdown -------------------------------
def md_inline(s):
    """Convierte el Markdown en linea a HTML (sobre texto ya escapado)."""
    s = html.escape(s, quote=False)
    # Codigo inline primero (protege su contenido)
    tokens = []

    def guard(m):
        tokens.append(m.group(1))
        return f"\x00{len(tokens) - 1}\x00"

    s = re.sub(r"`([^`]+)`", guard, s)
    # Imagenes y enlaces
    s = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", r'<img src="\2" alt="\1" loading="lazy">', s)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', s)
    # Negrita / cursiva
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", s)
    # Restaurar codigo inline
    s = re.sub(r"\x00(\d+)\x00", lambda m: f"<code>{html.escape(tokens[int(m.group(1))], quote=False)}</code>", s)
    return s


def md_to_html(md):
    """Convierte un subconjunto de Markdown a HTML."""
    lines = md.replace("\r\n", "\n").split("\n")
    out = []
    para = []

    def flush():
        if para:
            out.append("<p>" + md_inline(" ".join(para)) + "</p>")
            para.clear()

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]

        if line.startswith("```"):
            flush()
            lang = line[3:].strip()
            code = []
            i += 1
            while i < n and not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            cls = f' class="lang-{lang}"' if lang else ""
            out.append(f"<pre><code{cls}>{html.escape(chr(10).join(code))}</code></pre>")

        elif re.match(r"^#{1,4} ", line):
            flush()
            level = len(line) - len(line.lstrip("#"))
            out.append(f"<h{level}>{md_inline(line[level + 1:].strip())}</h{level}>")

        elif line.strip() in ("---", "***", "___"):
            flush()
            out.append("<hr>")

        elif line.startswith("> "):
            flush()
            quote = []
            while i < n and lines[i].startswith("> "):
                quote.append(lines[i][2:])
                i += 1
            out.append("<blockquote>" + md_to_html("\n".join(quote)) + "</blockquote>")
            continue

        elif re.match(r"^\s*[-*] ", line):
            flush()
            items = []
            while i < n and re.match(r"^\s*[-*] ", lines[i]):
                items.append("<li>" + md_inline(re.sub(r"^\s*[-*] ", "", lines[i])) + "</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue

        elif re.match(r"^\s*\d+\. ", line):
            flush()
            items = []
            while i < n and re.match(r"^\s*\d+\. ", lines[i]):
                items.append("<li>" + md_inline(re.sub(r"^\s*\d+\. ", "", lines[i])) + "</li>")
                i += 1
            out.append("<ol>" + "".join(items) + "</ol>")
            continue

        elif line.strip().startswith("|"):
            flush()
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(lines[i].strip())
                i += 1

            def cells(r):
                return [c.strip() for c in r.strip("|").split("|")]

            header = cells(rows[0])
            body = [cells(r) for r in rows[2:]] if len(rows) > 2 else []
            th = "".join(f"<th>{md_inline(c)}</th>" for c in header)
            trs = "".join(
                "<tr>" + "".join(f"<td>{md_inline(c)}</td>" for c in r) + "</tr>" for r in body
            )
            out.append(f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>")
            continue

        elif line.strip() == "":
            flush()

        else:
            para.append(line.strip())

        i += 1

    flush()
    return "\n".join(out)


# ------------------------------- Posts -------------------------------
def parse_front_matter(text):
    meta = {}
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            fm = text[3:end].strip()
            for raw in fm.splitlines():
                if ":" in raw:
                    k, v = raw.split(":", 1)
                    meta[k.strip().lower()] = v.strip()
            text = text[end + 4:]
    return meta, text.lstrip("\n")


def slugify(s):
    s = s.lower().strip()
    s = re.sub(r"[^\w\s-]", "", s, flags=re.UNICODE)
    s = re.sub(r"[\s_-]+", "-", s)
    return s.strip("-")


def fmt_date(iso):
    try:
        d = datetime.date.fromisoformat(iso)
        return f"{d.day:02d} {MESES[d.month - 1]} {d.year}"
    except Exception:
        return iso


def tags_html(tags):
    if not tags:
        return ""
    items = [t.strip() for t in tags.split(",") if t.strip()]
    return " ".join(f'<span class="tag">#{html.escape(t)}</span>' for t in items)


def reading_time(text):
    words = len(re.findall(r"\w+", text))
    return max(1, round(words / 200))


def load_posts():
    posts = []
    for path in glob.glob(os.path.join(POSTS_DIR, "*.md")):
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        meta, body = parse_front_matter(raw)
        name = os.path.splitext(os.path.basename(path))[0]
        # slug: quita el prefijo de fecha si existe
        slug = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", name)
        date = meta.get("date") or name[:10]
        posts.append({
            "title": meta.get("title", slug.replace("-", " ").title()),
            "date": date,
            "date_h": fmt_date(date),
            "tags": meta.get("tags", ""),
            "summary": meta.get("summary", ""),
            "serie": meta.get("serie", ""),
            "slug": slug,
            "draft": meta.get("draft", "").lower() in ("true", "1", "yes"),
            "body": body,
            "reading": reading_time(body),
        })
    posts = [p for p in posts if not p["draft"]]
    posts.sort(key=lambda p: p["date"], reverse=True)
    return posts


def render_template(name, repl):
    with open(os.path.join(TPL_DIR, name), "r", encoding="utf-8") as f:
        tpl = f.read()
    for k, v in repl.items():
        tpl = tpl.replace("{{" + k + "}}", v)
    return tpl


def card_html(post, prefix):
    href = f"{prefix}{post['slug']}.html"
    summary = f'<p class="entrada__resumen">{html.escape(post["summary"])}</p>' if post["summary"] else ""
    return (
        f'<li>\n'
        f'  <a class="entrada" href="{href}">\n'
        f'    <p class="entrada__fecha">// {post["date_h"]}</p>\n'
        f'    <h3 class="entrada__titulo">{html.escape(post["title"])}</h3>\n'
        f'    {summary}\n'
        f'    <span class="entrada__enlace">Leer m&aacute;s &rarr;</span>\n'
        f'  </a>\n'
        f'</li>'
    )


def serie_html(post):
    """Devuelve el enlace a la serie del post (o vacio)."""
    if not post.get("serie"):
        return ""
    s = slugify(post["serie"])
    return f'<p class="post__serie">Serie: <a href="serie/{s}.html">{html.escape(post["serie"])}</a></p>'


def build():
    os.makedirs(BLOG_DIR, exist_ok=True)
    posts = load_posts()

    # Paginas de cada post
    for p in posts:
        content = md_to_html(p["body"])
        page = render_template("post.html", {
            "title": html.escape(p["title"]),
            "summary": html.escape(p["summary"]),
            "date": p["date_h"],
            "reading": str(p["reading"]),
            "tags": tags_html(p["tags"]),
            "serie": serie_html(p),
            "content": content,
            "site": SITE,
        })
        with open(os.path.join(BLOG_DIR, p["slug"] + ".html"), "w", encoding="utf-8") as f:
            f.write(page)

    # Indice del blog
    cards = "\n".join(card_html(p, "") for p in posts)
    if not posts:
        cards = '<li class="entradas__vacio">A&uacute;n no hay entradas. Pronto.</li>'
    index_page = render_template("blog-index.html", {"posts": cards, "site": SITE})
    with open(os.path.join(BLOG_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(index_page)

    # Paginas de serie (investigacion) - orden cronologico
    series = {}
    for p in posts:
        if p.get("serie"):
            series.setdefault(p["serie"], []).append(p)
    if series:
        os.makedirs(os.path.join(BLOG_DIR, "serie"), exist_ok=True)
    for nombre, items in series.items():
        items.sort(key=lambda x: x["date"])
        s_cards = "\n".join(card_html(p, "../") for p in items)
        s_page = render_template("serie.html", {
            "titulo": html.escape(nombre),
            "posts": s_cards,
            "site": SITE,
        })
        with open(os.path.join(BLOG_DIR, "serie", slugify(nombre) + ".html"), "w", encoding="utf-8") as f:
            f.write(s_page)

    # Portada: ultimas entradas entre marcadores
    if os.path.exists(INDEX):
        with open(INDEX, "r", encoding="utf-8") as f:
            idx = f.read()
        home_cards = "\n".join(card_html(p, "blog/") for p in posts[:HOME_COUNT])
        if not home_cards:
            home_cards = '<li class="entradas__vacio">A&uacute;n no hay entradas. Pronto.</li>'
        new = re.sub(
            r"(<!-- POSTS:START -->).*?(<!-- POSTS:END -->)",
            lambda m: m.group(1) + "\n" + home_cards + "\n" + m.group(2),
            idx,
            flags=re.DOTALL,
        )
        if new != idx:
            with open(INDEX, "w", encoding="utf-8") as f:
                f.write(new)

    print(f"OK -> {len(posts)} post(s) generado(s)")
    for p in posts:
        print(f"   - blog/{p['slug']}.html  ({p['date_h']})")


if __name__ == "__main__":
    build()
