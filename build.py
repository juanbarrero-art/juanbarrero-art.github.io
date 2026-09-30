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
import json
import os
import re
import email.utils
import datetime
import glob

ROOT = os.path.dirname(os.path.abspath(__file__))
POSTS_DIR = os.path.join(ROOT, "content", "posts")
BLOG_DIR = os.path.join(ROOT, "blog")
TPL_DIR = os.path.join(ROOT, "templates")
INDEX = os.path.join(ROOT, "index.html")

SITE = "KANON UFO"
SITE_URL = "https://juanbarrero-art.github.io"
SITE_DESC = "Blog personal de ciberseguridad: notas, writeups y laboratorio."
AUTHOR = "Juan Barrero"
AUTHOR_ALIAS = "KANON UFO"
AUTHOR_URL = "https://github.com/juanbarrero-art"

# Palabras clave base para SEO (nicho: malware research / Windows internals)
BASE_KEYWORDS = [
    "windows internals", "syscalls", "indirect syscalls", "malware analysis",
    "red team", "blue team", "EDR", "ntdll", "Windows kernel", "FreshyCalls",
    "reverse engineering", "offensive security", "ciberseguridad",
    "seguridad informatica", "Windows x64", "MASM",
]
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
                    v = v.strip()
                    # Quitar comillas envolventes ("..." o '...')
                    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
                        v = v[1:-1]
                    meta[k.strip().lower()] = v
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
            "orden": int(meta["orden"]) if meta.get("orden", "").strip().isdigit() else None,
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


def rss_date(iso):
    try:
        d = datetime.datetime.fromisoformat(iso)
    except ValueError:
        d = datetime.datetime.now()
    return email.utils.format_datetime(d.replace(tzinfo=datetime.timezone.utc))


def build_rss(posts):
    items = []
    for p in posts:
        url = f"{SITE_URL}/blog/{p['slug']}.html"
        items.append(
            "  <item>\n"
            f"    <title>{html.escape(p['title'])}</title>\n"
            f"    <link>{url}</link>\n"
            f'    <guid isPermaLink="true">{url}</guid>\n'
            f"    <pubDate>{rss_date(p['date'])}</pubDate>\n"
            f"    <description>{html.escape(p['summary'])}</description>\n"
            "  </item>"
        )
    now = email.utils.format_datetime(datetime.datetime.now(datetime.timezone.utc))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n<channel>\n'
        f"  <title>{SITE}</title>\n"
        f"  <link>{SITE_URL}</link>\n"
        f"  <description>{SITE_DESC}</description>\n"
        "  <language>es</language>\n"
        f"  <lastBuildDate>{now}</lastBuildDate>\n"
        + "\n".join(items)
        + "\n</channel>\n</rss>\n"
    )


def build_sitemap(posts):
    urls = [f"{SITE_URL}/", f"{SITE_URL}/blog/"]
    for p in posts:
        urls.append(f"{SITE_URL}/blog/{p['slug']}.html")
    for s in sorted({slugify(p["serie"]) for p in posts if p.get("serie")}):
        urls.append(f"{SITE_URL}/blog/serie/{s}.html")
    body = "".join(f"  <url><loc>{u}</loc></url>\n" for u in urls)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + body
        + "</urlset>\n"
    )


def build_robots():
    return f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}/sitemap.xml\n"


def first_image(body):
    """Devuelve el nombre del primer archivo de imagen referenciado en el post."""
    m = re.search(r"!\[[^\]]*\]\(([^)]+)\)", body)
    if not m:
        return ""
    return m.group(1).split("/")[-1]


def post_seo(p, content):
    """Calcula los campos SEO de una entrada."""
    img = first_image(p["body"])
    ogimage = f"{SITE_URL}/assets/{img}" if img else f"{SITE_URL}/assets/banner.gif"
    canonical = f"{SITE_URL}/blog/{p['slug']}.html"
    tags_list = [t.strip() for t in p["tags"].split(",") if t.strip()]
    keywords = ", ".join(dict.fromkeys(BASE_KEYWORDS + tags_list))
    tag_meta = "\n".join(
        f'  <meta property="article:tag" content="{html.escape(t)}">' for t in tags_list
    )
    jsonld = json.dumps({
        "@context": "https://schema.org",
        "@type": "BlogPosting",
        "headline": p["title"],
        "description": p["summary"],
        "datePublished": p["date"],
        "dateModified": p["date"],
        "author": {"@type": "Person", "name": AUTHOR, "alternateName": AUTHOR_ALIAS, "url": AUTHOR_URL},
        "publisher": {"@type": "Person", "name": AUTHOR_ALIAS, "url": AUTHOR_URL},
        "image": ogimage,
        "keywords": keywords,
        "articleSection": p.get("serie") or "Blog",
        "inLanguage": "es",
        "mainEntityOfPage": {"@type": "WebPage", "@id": canonical},
        "url": canonical,
    }, ensure_ascii=False, indent=2)
    return {
        "canonical": canonical,
        "ogimage": ogimage,
        "keywords": html.escape(keywords),
        "date_iso": p["date"],
        "tag_meta": tag_meta,
        "jsonld": jsonld,
    }


def build():
    os.makedirs(BLOG_DIR, exist_ok=True)
    posts = load_posts()

    # Paginas de cada post
    for p in posts:
        content = md_to_html(p["body"])
        repl = {
            "title": html.escape(p["title"]),
            "summary": html.escape(p["summary"]),
            "date": p["date_h"],
            "reading": str(p["reading"]),
            "tags": tags_html(p["tags"]),
            "serie": serie_html(p),
            "content": content,
            "site": SITE,
        }
        repl.update(post_seo(p, content))
        page = render_template("post.html", repl)
        with open(os.path.join(BLOG_DIR, p["slug"] + ".html"), "w", encoding="utf-8") as f:
            f.write(page)

    # Indice del blog
    cards = "\n".join(card_html(p, "") for p in posts)
    if not posts:
        cards = '<li class="entradas__vacio">A&uacute;n no hay entradas. Pronto.</li>'
    idx_canonical = f"{SITE_URL}/blog/"
    idx_jsonld = json.dumps({
        "@context": "https://schema.org",
        "@type": "Blog",
        "name": f"{SITE} - Blog",
        "description": SITE_DESC,
        "url": idx_canonical,
        "inLanguage": "es",
        "author": {"@type": "Person", "name": AUTHOR, "alternateName": AUTHOR_ALIAS},
        "blogPost": [
            {"@type": "BlogPosting", "headline": p["title"],
             "url": f"{SITE_URL}/blog/{p['slug']}.html", "datePublished": p["date"]}
            for p in posts
        ],
    }, ensure_ascii=False, indent=2)
    index_page = render_template("blog-index.html", {
        "posts": cards, "site": SITE, "canonical": idx_canonical,
        "ogimage": f"{SITE_URL}/assets/banner.gif",
        "keywords": html.escape(", ".join(BASE_KEYWORDS)),
        "jsonld": idx_jsonld,
    })
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
        items.sort(key=lambda x: (x.get("orden") if x.get("orden") is not None else 10 ** 9, x["date"]))
        s_cards = "\n".join(card_html(p, "../") for p in items)
        s_canonical = f"{SITE_URL}/blog/serie/{slugify(nombre)}.html"
        s_jsonld = json.dumps({
            "@context": "https://schema.org",
            "@type": "CollectionPage",
            "name": f"Serie: {nombre}",
            "url": s_canonical,
            "inLanguage": "es",
            "hasPart": [
                {"@type": "BlogPosting", "headline": it["title"],
                 "url": f"{SITE_URL}/blog/{it['slug']}.html", "datePublished": it["date"]}
                for it in items
            ],
        }, ensure_ascii=False, indent=2)
        s_page = render_template("serie.html", {
            "titulo": html.escape(nombre),
            "posts": s_cards,
            "site": SITE,
            "canonical": s_canonical,
            "ogimage": f"{SITE_URL}/assets/banner.gif",
            "keywords": html.escape(", ".join(BASE_KEYWORDS)),
            "jsonld": s_jsonld,
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

    # RSS, sitemap y robots
    with open(os.path.join(ROOT, "feed.xml"), "w", encoding="utf-8") as f:
        f.write(build_rss(posts))
    with open(os.path.join(ROOT, "sitemap.xml"), "w", encoding="utf-8") as f:
        f.write(build_sitemap(posts))
    with open(os.path.join(ROOT, "robots.txt"), "w", encoding="utf-8") as f:
        f.write(build_robots())

    print(f"OK -> {len(posts)} post(s) generado(s)")
    for p in posts:
        print(f"   - blog/{p['slug']}.html  ({p['date_h']})")


if __name__ == "__main__":
    build()
