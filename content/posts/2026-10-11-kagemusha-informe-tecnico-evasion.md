---
title: "Kagemusha — Informe técnico: evasión de EDR (del mecanismo de syscall a la jerarquía de detección)"
date: 2026-10-11
tags: windows internals, red team, blue team, edr, evasion, investigacion, informe
serie: Kagemusha
summary: Documentación del informe técnico del repositorio (docs/research/informe-tecnico-evasion.md): el marco conceptual de la evasión de EDR unificado con los experimentos E1–E4, los planos de observación, la jerarquía conducta>ejecución>mecanismo, la matriz de evasión y las recomendaciones para el lado azul.
---

# Kagemusha — Informe técnico: evasión de EDR

Esta entrada documenta el **informe técnico** del repositorio
(`docs/research/informe-tecnico-evasion.md`), un documento de análisis conceptual y técnico.

> Del informe: *"No contiene recetas operativas ni código malicioso; describe principios,
> arquitectura y hallazgos empíricos obtenidos con un harness propio y reproducible."*

## Las cinco conclusiones (resumen ejecutivo del informe)

1. **Visibilidad no es detección.** *"Un EDR puede ver cada syscall y no alertar…"* Lo comprobaron: Defender observó los syscalls y no generó ninguna detección.
2. **Jerarquía de impacto: conducta/OPSEC > técnica de ejecución > mecanismo de syscall.**
3. **El indirecto resuelve exactamente un vector** (hooks inline de user-mode); el **stack spoofing** resuelve un segundo (la firma de pila). Ambos son necesarios contra un EDR que hookea o inspecciona pilas.
4. **CET y stack spoofing clásico son mutuamente excluyentes.**
5. **El techo es el kernel:** ETW-TI y los callbacks no se pueden cegar desde user-mode (se resuelve bajando a kernel, BYOVD, con privilegios de un paso previo).

## Arquitectura de un EDR y sus planos (del informe)

Cuatro planos: **usuario, kernel, memoria y telemetría**. Tabla del informe:

| Plano | Mecanismo | ¿Ve el indirect? | Neutralizable desde user-mode |
| --- | --- | --- | --- |
| Usuario | hooks inline en `Nt*` | No | — (ya lo evita) |
| Usuario | instrumentation callback | Sí | Sí (limpiar/capar) |
| Telemetría user | ETW (`EtwEventWrite`) | Sí | Sí (patch) |
| Kernel | ETW-TI / callbacks | Sí | **No** |
| Memoria | scans | Depende | Parcial (sleep obfuscation) |

## El límite user / kernel (del informe)

El código de user-mode **solo puede modificar cosas dentro de su espacio y con su token**. De ahí:

1. **Toda la evasión de user-mode está disponible en contexto usuario** (patchear su propio `ntdll`, su ETW, su callback; indirect syscalls).
2. No puede tocar callbacks de kernel ni ETW-TI ni el driver del EDR.
3. La evasión tiene **dos techos**: user-mode y kernel. *"Explica por qué la evasión es incremental y no un acto único."*

## Jerarquía de evasión (del informe)

1. **Conducta / OPSEC (lo que haces)** — dominante; el EDR alerta por el **patrón**, no por un syscall aislado.
2. **Técnica de ejecución (cómo arrancas/cargas)** — define la huella inicial.
3. **Mecanismo de syscall (cómo invocas el kernel)** — evita hooks y oculta la pila, pero **no cambia qué hace el proceso**.

> *"El mecanismo de syscall es como abrir bien la cerradura; la ejecución es no hacer ruido…"*

## Visibilidad vs detección (del informe)

Separar **sensor**, **telemetría**, **regla** y **alerta**: un hecho puede ser **observado** y **no
detectado**. La evasión consiste en **reducir la señal** y **evitar los patrones** que las reglas
describen. *"'El EDR me ve' no implica 'el EDR me pilla'."*

### Mapa de los experimentos sobre el marco (tabla del informe)

| Experimento | Qué midió | Lectura |
| --- | --- | --- |
| Defender (estático/conductual) | ¿Alerta? | No, conducta benigna |
| E2 (instrumentation callback) | ¿Ve? | Sí, ve cada syscall |
| E3 (call-stack) | ¿Firma? | Sí: return address en módulo propio |
| E4c (CET vs spoofing) | ¿Compatible? | Incompatibles |
| E4b (ETW patch) | ¿Ciega user? | Sí |

## Matriz de evasión (Apéndice E del informe)

| Vector | Técnica requerida | Kagemusha | Límite |
| --- | --- | --- | --- |
| Hooks inline user-mode | Indirect + FreshyCalls | ✅ | — |
| Pila / return address | Stack spoofing | ✅ (stealth) | incompatible con CET |
| Instrumentation callback in-proceso | Limpiar callback | ✅ | por-proceso |
| ETW user-mode | ETW patch | ✅ | solo user-mode |
| AMSI | (patch AMSI) | — | solo scripting |
| Memoria en reposo | Sleep obfuscation | ⏳ futuro | complejidad |
| ETW-TI / callbacks de kernel | Kernel (BYOVD) | ❌ | techo de user-mode |
| Conducta/OPSEC | Disciplina operativa | (marco) | dominante |

## Estado del proyecto (Apéndice B del informe)

- **Builds:** **stealth** (sin CET, con spoofing) y **CET** (`/CETCOMPAT`).
- **Tests:** **178 PASS** (stealth) / **182 PASS** (CET), 0 FAIL.

## Metodología y verificación (del informe)

Se apoya en **oráculos independientes** (nunca validar contra el propio sistema), **falsabilidad**,
**evidencia física** (debugger), **fallo ruidoso** y **reproducibilidad**. Ver la entrada
[Metodología de verificación](/blog/kagemusha-metodologia-verificacion.html).

## Recomendaciones para el lado azul (del informe)

1. **No confiar solo en hooks de user-mode**: priorizar telemetría de kernel (callbacks, minifiltros, **ETW-TI**).
2. **Vigilar la integridad** de stubs/módulos (comparar `.text` en memoria vs disco).
3. **Inspeccionar la pila** en el punto de syscall (RIP a mitad de stub; caller no-sistema).
4. **High-signal: la conducta** (patrones, no syscalls aislados).
5. **Endurecer el kernel** (HVCI, blocklist de drivers, monitorizar cargas de drivers).
6. **CET / Shadow Stack** donde sea viable (rompe el stack spoofing clásico).
7. **Correlación XDR**.

> *"Contra un EDR moderno, la defensa del atacante es reducir señal; la del defensor es diversificar sensores."*

## Preguntas abiertas (Apéndice C del informe)

Entre otras: ¿existe un **stack spoofing CET-safe**?; ¿cuál es el **umbral exacto** de detección por
ETW-TI?; ¿cuánto de la detección es **conducta vs mecanismo**?; ¿es medible la **señal agregada** en
XDR?; ¿se puede cegar ETW-TI desde user-mode de forma soportada? (hasta ahora, no).

## Artefactos (Apéndice F, extracto)

`src/core/` (`core.c`, `ledger.c`, `instrument.c`, `telemetry.c`, `avatest.c`),
`src/ref_layered/HookModule.cpp` (stack spoofing, con atribución), `tests/run_tests.c` (T0–T31),
`tools/build.cmd` / `build_cet.cmd` / `verify.ps1` / `cdb_scripts/`.

---

## Cómo sigue la serie

Toda la serie (navegable): **[Kagemusha](/blog/serie/kagemusha.html)**.

---

## Bibliografía y referencias

- Fuente primaria: `docs/research/informe-tecnico-evasion.md`.
- Referencias del informe: Microsoft (ETW/ETW-TI, callbacks, CET/HVCI, blocklist de drivers);
  `paranoidninja/Process-Instrumentation-Syscall-Hook` (detector de referencia);
  `WKL-Sec/LayeredSyscall` (mecanismo de stack spoofing integrado).

> Aprender a romper para poder defender.
