---
title: "Kagemusha — Metodología de verificación (oráculos independientes)"
date: 2026-10-09
tags: windows internals, investigacion, metodologia, informe
serie: Kagemusha
orden: 13
summary: Documentación del informe metodológico del repositorio (docs/research/metodologia.md): la regla de los oráculos independientes, la tabla de oráculos, el protocolo por hito, los criterios de aceptación y la reproducibilidad.
---

# Kagemusha — Metodología de verificación

Esta entrada documenta el **informe metodológico** del repositorio
(`docs/research/metodologia.md`), que describe **cómo se valida** cada componente.

---

## La regla central (del informe)

> *"Ninguna afirmación se comprueba contra el propio sistema. Siempre existe un **oráculo
> independiente**."*

## 1. Oráculos utilizados (del informe)

| Tipo | Oráculo | Uso |
| --- | --- | --- |
| API Windows | `GetModuleHandleW` | base real de `ntdll` para contrastar el PEB walk |
| API Windows | `GetProcAddress` | dirección real de un export para contrastar `UtlGetExportByHash` |
| Bytes de disco/memoria | patrón `4C 8B D1 B8 <ssn>` | SSN real del stub para contrastar FreshyCalls |
| Bytes de memoria | patrón `0F 05 C3` | gadget real para contrastar el localizador |
| Herramienta externa | cálculo DJB2 en PowerShell (BigInteger) | vectores esperados del hash |
| Sistema | `VirtualAlloc(PAGE_NOACCESS)` | caso negativo de `UtlIsReadableRange` |

## 2. Protocolo por hito (del informe)

*"Cada hito (Mx) produce evidencia en dos formatos:"*

1. **Test automatizado** en `tests/run_tests.c` con oráculo independiente (PASS/FAIL).
2. **Transcript del debugger** en `docs/evidencias/mX.txt`, reproducible con un script en
   `tools/cdb_scripts/`.

## 3. Criterios de aceptación (del informe)

- La suite completa debe salir con **0 FAIL**.
- En el debugger debe poder observarse la propiedad **física** del sistema (p. ej. `RIP` dentro de
  `ntdll`).
- Si una verificación depende de la build de Windows, se **registra el número de build** junto al
  resultado.

## 4. Reproducibilidad (del informe)

- Sin valores *hardcodeados* dependientes de la build: todo se resuelve en **runtime**.
- Los scripts de `cdb` se ejecutan sobre el mismo binario y producen el transcript.
- Los benchmarks (Fase 7B) se ejecutan **N veces** y se reporta **media/percentiles**.

---

## Por qué esto importa

La metodología es lo que hace que las fases sean **creíbles**: cada afirmación (PEB walk, export,
SSN, gadget, `RIP` dentro de `ntdll`, `NTSTATUS`) tiene su **oráculo externo**, y cada hito deja
**dos** pruebas reproducibles (test + transcript). Esta es la base que siguen todas las entradas
de la serie; ver, por ejemplo, [Fases 0–3](/blog/kagemusha-fases-0-3.html) y
[Fase 4](/blog/kagemusha-fase-4-ejecucion-indirecta.html).

---

## Cómo sigue la serie

Toda la serie (navegable): **[Kagemusha](/blog/serie/kagemusha.html)**.

## Bibliografía y referencias

- Fuente primaria: `docs/research/metodologia.md`, `docs/research/informe.md`.
- Microsoft Learn — *Ntdll* y *x64 calling convention*.

> Aprender a romper para poder defender.
