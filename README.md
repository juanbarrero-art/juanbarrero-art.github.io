# KANON UFO — Blog personal

Base de mi **blog personal de ciberseguridad**, publicado gratis con **GitHub Pages**.
Estilo **cyberpunk / hacker**, sin frameworks en la web: solo HTML, CSS y JavaScript vanilla.

> Notas, writeups y laboratorio sobre **análisis de malware** y **Windows internals**.
> Enfoque **Blue Team** con base **Red Team**.

## Cómo funciona

El blog usa un **generador estático en Python** (sin dependencias externas):

- Las entradas se escriben en **Markdown** en `content/posts/`.
- `build.py` las convierte a HTML y genera:
  - `blog/<slug>.html` — una página por entrada.
  - `blog/index.html` — el listado de entradas.
  - Actualiza las "Últimas entradas" de `index.html` (entre marcadores `POSTS:START/END`).

## Estructura

```
.
├── index.html            # Portada (hero, últimas entradas, laboratorio, sobre mí)
├── styles.css            # Tema cyberpunk (mobile-first, BEM)
├── script.js             # Menú móvil, año y animaciones (vanilla)
├── assets/favicon.svg
├── content/posts/        # Entradas en Markdown
├── templates/            # Plantillas HTML (post y listado)
├── blog/                 # Generado por build.py
├── build.py              # Generador estático
└── new_post.py           # Crea una entrada nueva
```

## Uso

```bash
# Crear una entrada nueva
python new_post.py "Título de la entrada" "tags, separados, por comas"

# Editar el Markdown en content/posts/ y regenerar el sitio
python build.py

# Publicar
git add . && git commit -m "post: ..." && git push
```

## Ver en local

Abre `index.html` en el navegador (no requiere servidor ni build).
Las páginas de entrada están en `blog/`.

## Publicación

**GitHub Pages** desde la rama `main` (raíz): `https://juanbarrero-art.github.io`

## Convenciones

- HTML semántico, CSS mobile-first, **JavaScript vanilla** (sin frameworks).
- Nomenclatura **BEM**.
- Accesibilidad **WCAG 2.1 AA** (foco visible, `aria-*`, `prefers-reduced-motion`).
- Código comentado.

## Próximos pasos

- SEO (sitemap, RSS) y datos estructurados.
- Categorías/etiquetas con filtrado.
- Búsqueda de entradas.
