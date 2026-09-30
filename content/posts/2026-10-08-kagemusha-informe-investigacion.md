---
title: "Kagemusha — Informe de investigación (paper): tesis, diseño y contribuciones"
date: 2026-10-08
tags: windows internals, red team, syscalls, investigacion, informe
serie: Kagemusha
summary: Documentación del informe técnico del repositorio (docs/research/informe.md): título, abstract, introducción y contribuciones, diseño, metodología, experimentos (E1–E4), limitaciones y trabajo futuro.
---

# Kagemusha — Informe de investigación (paper)

Esta entrada documenta el **informe técnico** del repositorio (`docs/research/informe.md`), que se
describe a sí mismo como *"Documento acumulativo. Se completa a medida que avanzan las fases.
Formato paper."*

---

## Título (tentativo, del informe)

> *Kagemusha: ejecución de indirect syscalls en Windows x64 con resolución de SSN en runtime por
> orden de export y verificación por oráculos independientes.*

## Abstract (del informe)

> *"Se presenta un sistema que ejecuta funciones `Nt*` mediante indirect syscalls (el `syscall` se
> ejecuta dentro de `ntdll`), resolviendo los números de servicio (SSN) en runtime mediante
> FreshyCalls (índice del export ordenado por dirección virtual) y sin leer bytes de stub. El
> sistema se somete a una metodología de verificación con oráculos independientes y se documentan,
> de forma medible, sus propiedades y su superficie de detección."*

## 1. Introducción (del informe)

- **Motivación:** *"ejecutar syscalls sin tocar los stubs hookeables de ntdll en user-mode."*
- **Contribución:**
  - **(a)** implementación *indirect-only* de técnica única;
  - **(b)** verificación por **oráculos**;
  - **(c)** herramientas de observación (***ledger***, extensión de debugger);
  - **(d)** análisis de **detectabilidad** del indirect "puro".

## 2. Diseño (del informe)

- **Módulos:** `util`, `resolver`, `asm`, `wrappers`, `core`, `tests`.
- **Resolución:** FreshyCalls (sort-by-VA). Invariante: *"en Windows 10/11 los stubs `Nt*` residen
  en `.text` en orden de SSN."*
- **Ejecución:** *"trampolín que carga `EAX`=SSN y salta al gadget `syscall;ret` de ntdll."*

> Nota de fidelidad: el informe dice "sort-by-VA"; el código (`freshycalls.c`) ordena por **RVA**
> (equivalente para el orden dentro del módulo). Ver la entrada de
> [Fases 0–3](/blog/kagemusha-fases-0-3.html).

## 3. Metodología

El informe remite a `metodologia.md`. La documentamos en su propia entrada:
[Metodología de verificación](/blog/kagemusha-metodologia-verificacion.html).

## 4. Experimentos y resultados (del informe)

El informe los lista así (es un *borrador vivo*, y su estado se actualiza en otros documentos):

- **E1 (parcial):** Tabla de SSN por build (ver `README.md`).
- **E2 (pendiente\*):** Matriz de detección de user-mode.
- **E3 (pendiente\*):** Análisis de call-stack del indirect puro.
- **E4 (pendiente\*):** Benchmarks indirecto vs API nativa.

\* En el repositorio, estos experimentos **ya están documentados** en `docs/research/` y cubiertos
en las entradas de la serie:
- **E2** → [Visibilidad y evasión](/blog/kagemusha-visibilidad-evasion.html) (instrumentation
  callbacks / ETW-TI).
- **E3** → [Visibilidad y evasión](/blog/kagemusha-visibilidad-evasion.html) (firma de call-stack).
- **E4** → [Fase 7 y baterías](/blog/kagemusha-fase-7-baterias-cet.html) (rendimiento ≈ nativo) y
  [Evasión en acción](/blog/kagemusha-evasion-e4b-cet-spoofing.html) (E4b/E4c).

## 5. Limitaciones (del informe)

> *"El caller visible en un stack walk sigue siendo el módulo propio (ausencia de stack spoofing,
> fuera de alcance de v1); se cuantifica en E3."*

(En el repositorio, E3 confirma esa firma y E4c/2b demuestra que el *spoofing* clásico choca con
CET; ver [Evasión en acción](/blog/kagemusha-evasion-e4b-cet-spoofing.html).)

## 6. Trabajo futuro (del informe)

- *"Núcleo de ingeniería propio (macro + generador), ledger y `!kage` (Fase 7B)."*
- *"Robustez multi-build y test de hook simulado (Fase 6)."*

(El repo ya tiene macro, ledger, CLI y pruebas de robustez; queda `!kage`.)

---

## Cómo sigue la serie

Toda la serie (navegable): **[Kagemusha](/blog/serie/kagemusha.html)**.

## Bibliografía y referencias

- Fuente primaria: `docs/research/informe.md`, `docs/research/metodologia.md`, `README.md`.
- Russinovich, Solomon, Ionescu — *Windows Internals, 7.ª ed.*
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`).

> Aprender a romper para poder defender.
