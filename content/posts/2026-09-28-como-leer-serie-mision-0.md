---
title: "Cómo leer esta serie + Misión 0: ve una syscall con tus ojos"
date: 2026-09-28
tags: guia, introduccion, principiantes, windows internals, syscalls
serie: Kagemusha
summary: El punto de entrada de la serie. Explica cómo leerla (niveles y recorrido), y trae la Misión 0: tres experimentos guiados para VER con tus propios ojos que todo programa le pide cosas a Windows, y dónde vive ntdll.
---

# Cómo leer esta serie + Misión 0

Antes de entrar en materia, dos cosas. La primera: **cómo leer esta serie** para no perderte. La
segunda: una **Misión 0** para que **veas con tus ojos** de qué hablamos, sin instalar nada
raro y sin saber programar. Si eres curioso y nunca has tocado "lo profundo" de Windows, esta
entrada es para ti.

> Esta serie es un **diario de laboratorio** sobre `indirect syscalls` en Windows. No hace falta
> que sepas todo para empezar. Hace falta **curiosidad** y ganas de **probar**.

---

## Parte 1 — Cómo leer esta serie

### La idea, en una frase

Todo programa, cuando hace *casi cualquier cosa* (abrir un archivo, crear un proceso, conectarse
a internet), tiene que **pedirle permiso al núcleo de Windows**. Esa petición se llama **system
call** (syscall). Esta serie estudia cómo se hacen esas peticiones, cómo se pueden hacer de forma
"indirecta" (para que no las vea un antivirus moderno) y, sobre todo, **cómo se verifica** que
funcionan. Es investigación **defensiva hecha con mentalidad ofensiva**.

### Niveles: no todo es para todo el mundo

Cada entrada está pensada para un nivel. Identifícalo con este semáforo:

| Nivel | Para quién | Qué necesitas saber |
| --- | --- | --- |
| 🟢 **Curioso** | Alguien con ganas, sin experiencia | Usar Windows y leer con calma |
| 🟡 **Con base** | Sabes algo de programar o de sistemas | Conceptos básicos de procesos y memoria |
| 🔴 **Investigador** | Análisis de malware / Windows internals | C/C++, ASM, debuggers, PE |

### El recorrido recomendado

- **Si empiezas de cero 🟢:** lee **esta entrada** → la
  [Guía de syscalls](/blog/guia-syscalls-windows.html) → la
  [Visión general](/blog/kagemusha-indirect-syscalls.html). Con eso ya entiendes el mapa. Las
  fases técnicas son opcionales: te las puedes saltar y volver luego.
- **Si ya programas 🟡:** guía → visión general → [Fases 0–3](/blog/kagemusha-fases-0-3.html) →
  [Fase 4](/blog/kagemusha-fase-4-ejecucion-indirecta.html).
- **Si eres investigador 🔴:** puedes ir directo a las fases 4–7 (ejecución indirecta, aridad,
  robustez, baterías y CET), pero la **metodología** de la visión general es obligatoria: es lo
  que hace creíble el resto.

### Cómo está pensada cada entrada

Todas siguen el mismo patrón, para que sepas qué esperar:

1. **El objetivo** (qué queremos lograr).
2. **La implementación** (cómo se hizo).
3. **Las pruebas** (con **oráculos independientes**: no nos creemos a nosotros mismos).
4. **La evidencia** (transcripts del debugger, reproducibles).
5. **Qué aprendimos** (honesto, incluidos los fallos y los límites).

Y todas cierran con **bibliografía**, para que puedas profundizar.

> Regla de oro de la serie: **una afirmación sin prueba es solo una opinión.** Eso incluye las
> mías.

---

## Parte 2 — Misión 0: ve una syscall con tus ojos

Vamos a hacer algo que **cualquiera** puede hacer en su Windows, sin programar. Al terminar,
entenderás por qué esta serie existe.

### El mapa mental (30 segundos)

```text
Tu programa  ->  pide algo  ->  Windows lo hace por ti
 (user-mode)      (una        (kernel-mode)
                 syscall)
```

Piénsalo como un restaurante: tú eres el cliente (tu programa), no entras a la cocina (el
kernel); le pides al **mesero** (una función del sistema) y la cocina cocina. Esa "comanda" es
una **syscall**.

### Experimento 0.A — Mira a un programa "pedir cosas" (10 min)

Vamos a **ver** esas peticiones en vivo.

1. Descarga **Process Monitor** (gratis, de Microsoft Sysinternals):
   `https://learn.microsoft.com/sysinternals/downloads/procmon`.
2. Ábrelo. Verás una lista llena de eventos que se mueven.
3. Abre el **Bloc de notas** (Notepad) y **guarda un archivo** con cualquier texto.
4. Vuelve a Process Monitor. Verás eventos como `CreateFile`, `WriteFile`, `CloseFile` con el
   nombre de tu archivo.

**¿Qué estás viendo?** Cada una de esas operaciones es el resultado de **peticiones al sistema**.
Por debajo, el Bloc de notas ejecutó "comandas" al kernel: exactamente el tipo de cosa que, en la
serie, aprenderemos a hacer **de forma indirecta**.

> Si te fijas, verás también muchísimo `RegOpenKey` y `QueryDirectory`. Casi todo lo que hace un
> programa son **peticiones**; esa es la idea.

### Experimento 0.B — Encuentra `ntdll.dll` (5 min)

El "mesero" principal se llama **`ntdll.dll`**. Vive aquí:

```text
C:\Windows\System32\ntdll.dll
```

1. Abre esa carpeta en el Explorador (puede que tengas que mostrar archivos del sistema).
2. Busca `ntdll.dll` y mira su tamaño (suele ser ~2 MB). Ese archivo contiene **miles** de
   funciones `Nt*`, la capa nativa que habla con el kernel.
3. (Opcional) Haz clic derecho → Propiedades → **Detalles**, y observa su versión.

**¿Por qué importa?** Porque en toda la serie, cuando digamos "el `syscall` se ejecuta dentro de
`ntdll`", estarás pensando en **este archivo concreto** que acabas de ver.

### Experimento 0.C (avanzado, opcional) — Ve una syscall de verdad

Si te atreves y tienes una máquina virtual (¡no lo hagas en el PC de trabajo!), puedes ver el
"salto" con un debugger. Con **WinDbg**, en una terminal:

```text
cdb -g -G notepad.exe
bp ntdll!NtClose
g
```

Cuando el Bloc de notas cierre algo, el debugger **parará** en `ntdll!NtClose`. Míralo con `u`:
verás el `mov eax, 0Fh` y el `syscall`. **Ese** es el momento que estudiamos en la serie. Si esto
te abruma, no pasa nada: vuelve cuando hayas leído la [guía](/blog/guia-syscalls-windows.html).

### Qué acabas de aprender

- Todo programa **pide** cosas a Windows mediante **peticiones** (y por debajo, syscalls).
- Esas peticiones pasan por **`ntdll.dll`**, que vive en `System32`.
- Un **debugger** puede "ver" el momento exacto en que un programa salta al kernel.

Si has llegado hasta aquí, ya tienes el **80% del mapa mental** de la serie. Lo demás es detalle
(y bastante divertido).

---

## Parte 3 — ¿Por qué "Misión 0" y no "Capítulo 0"?

Porque la serie es **experimental**: no queremos que "leas y creas", queremos que **leas y
pruebes**. Cada entrada tendrá, de ahora en adelante, una caja **🧪 Experimenta tú** con algo que
puedas ejecutar y comparar. La idea es que no seas espectador, sino que **hagas las misiones**.

### Lo que viene

1. **Esta entrada** — el mapa y la Misión 0.
2. [Guía de syscalls](/blog/guia-syscalls-windows.html) — los conceptos, bien explicados.
3. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html) — el proyecto.
4. [Fases 0 a 3](/blog/kagemusha-fases-0-3.html) · [Fase 4](/blog/kagemusha-fase-4-ejecucion-indirecta.html) ·
   [Fase 5](/blog/kagemusha-fase-5-generalizacion.html) · [Fase 6](/blog/kagemusha-fase-6-robustez.html) ·
   [Fase 7 y baterías](/blog/kagemusha-fase-7-baterias-cet.html).

---

## Bibliografía y referencias

- Microsoft Sysinternals — *Process Monitor* (`learn.microsoft.com/sysinternals/downloads/procmon`).
- Microsoft Learn — *Ntdll* y *System Calls*.
- Russinovich, Solomon, Ionescu — *Windows Internals, 7.ª ed.* (Microsoft Press).

> Aprender a romper para poder defender.
