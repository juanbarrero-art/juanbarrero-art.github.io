---
title: "Kagemusha — Fase 6: robustez, hooks y límites reales"
date: 2026-10-04
tags: windows internals, red team, syscalls, investigacion
serie: Kagemusha
summary: Simulamos un hook de EDR en un stub de ntdll y comprobamos que FreshyCalls no se inmuta y la ejecución indirecta sigue funcionando. Además: 488/488 stubs coinciden, fuzz del parser PE, concurrencia y el límite real de la técnica.
---

# Kagemusha — Fase 6: robustez, hooks y límites reales

Un sistema que funciona en el caso ideal no vale mucho. La Fase 6 es la del **mundo hostil**:
¿qué pasa si un EDR **modifica** un stub de `ntdll`? ¿Y si le damos basura al parser PE? ¿Y si
varios hilos ejecutan syscalls a la vez? Aquí dejamos de "demostrar que funciona" y empezamos a
**intentar romperlo**.

> 12 experimentos, todos en verde. Y un hallazgo que define un **límite real** de FreshyCalls.

## La implementación

- **`KageIsStubHooked` (`src/resolver/gadget.c`)** — detecta el prólogo de un hook: un `jmp`
  relativo (`E9 xx xx xx xx`) o indirecto (`FF 25 ...`) al inicio del stub.
- **Endurecimiento del parser PE** (`exhash.c`, `freshycalls.c`) — antes de leer cabeceras NT,
  se valida que `e_lfanew` (el offset que apunta a la cabecera PE) esté en un rango razonable
  (`[0x40, 0x1000]`). Así un PE malformado no provoca lecturas fuera de rango.

## Los 12 experimentos

![Diagrama: hook de EDR vs ejecucion indirecta](../assets/diag-hook.svg)

| # | Experimento | Cómo se probó | Resultado |
| --- | --- | --- | --- |
| 1 | Instalar un hook `E9` en el stub de `NtClose` | `VirtualProtect` + escribir `E9 00 00 00 00` | hook instalado |
| 2 | **Detectar** el hook | `KageIsStubHooked(stub) == TRUE` | ✅ |
| 3 | **Inmunidad de FreshyCalls** | resolver SSN con el stub hookeado | ✅ mismo SSN (no lee el stub) |
| 4 | El gadget sigue válido | resolver gadgets con el stub hookeado | ✅ encuentra `0F 05 C3` |
| 5 | **Ejecución indirecta con stub hookeado** | `NtClose_I(handle válido)` | ✅ `STATUS_SUCCESS` |
| 6 | Restauración | restaurar bytes → `KageIsStubHooked == FALSE` | ✅ |
| 7 | Re-init con hook presente | `KageInitialize()` durante el hook | ✅ `KAGE_OK` |
| 8 | SSN de **todo** el catálogo `Nt*` | FreshyCalls vs oráculo del stub | ✅ **488/488** |
| 9 | Exports `Nt*` sin SSN | prólogo ≠ `4C 8B D1 B8` | ✅ 2 detectados |
| 10 | **Fuzz del parser PE** | 9 PE malformados (`e_lfanew` extremo) | ✅ sin crash |
| 11 | **Concurrencia** | 4 hilos × 1000 syscalls | ✅ 0 fallos |
| 12 | Init idempotente | 100 × `KageInitialize()` | ✅ tablas estables |

Los experimentos 2–5 son el corazón: **instalamos un hook** (en nuestra propia copia privada
*Copy-On-Write* del stub, sin EDR real), y comprobamos que:

- FreshyCalls **no se inmuta** (SSN idéntico) porque **nunca lee los bytes del stub**.
- El gadget sigue encontrándose (no buscamos dentro del stub hookeado).
- La **ejecución indirecta funciona igual**: se usa el gadget de `ntdll`, no el stub.

> Esta es la recompensa por haber elegido una técnica **inmune a hooks por diseño** (sort-by-VA)
> en lugar de una que dependa de leer el stub (como Hell's Gate / Halo's Gate).

## El hallazgo: un límite real de FreshyCalls

Al resolver **todo** el catálogo de `ntdll` (no solo el nuestro), nos topamos con:

| Métrica | Valor |
| --- | --- |
| Exports `Nt*` en esta build | **490** |
| Stubs de syscall reales (prólogo `4C 8B D1 B8`) | **488** |
| Exports que **no** son stubs de syscall | **2** |
| Coincidencia FreshyCalls ↔ SSN real (en los 488) | **100%** |

Los 2 "raros" son:

| Export | Prólogo | Realidad |
| --- | --- | --- |
| `NtGetTickCount` | `E9 ...` | `jmp` (implementado en ntdll) |
| `NtQuerySystemTime` | `E9 ...` | `jmp ntdll!RtlQuerySystemTime` |

FreshyCalls **los cuenta** al ordenar por VA. En **esta build**, el índice ordenado sigue
coincidiendo con el SSN real para **los 488 stubs** (0 discrepancias). Pero es un **límite a
vigilar**: si en otra build el número de exports "no-stub" cambia, el índice podría desplazarse.

> Un investigador honesto **cuantifica** este límite en vez de esconderlo. Es exactamente el
> tipo de detalle que hace que un reporte sea creíble.

## Nota de seguridad (debugger)

`NtClose(handle inválido)` provoca una **excepción first-chance** `c0000008` que `ntdll` maneja.
En los scripts de `cdb` hay que ignorarla (`sxi c0000008`) para que la sesión continúe. Queda
documentado para futuros transcripts.

## Qué significa todo esto

- **La robustez se prueba, no se afirma.** Simular el hook y ver que el sistema sigue en pie vale
  más que cualquier frase grandilocuente.
- **Cada técnica tiene límites.** FreshyCalls tolera exports sin SSN, pero hay que saberlo y
  medirlo.
- **La entrada adversa importa.** Un parser que revienta con un PE malformado es una
  vulnerabilidad; fuzzearlo es parte del trabajo.
- **La concurrencia cuenta.** 4 hilos × 1000 syscalls sin fallos dan confianza en que las tablas
  y el init transaccional están bien hechos.

## Próximos pasos

- **Fase 7 (I+D propia):** macro propia consolidada, *hashes* en tiempo de compilación, un
  ***ledger*** de syscalls (ring buffer volcable por CLI y por la extensión de debugger `!kage`)
  y modos de línea de comandos.
- **Fase 8 (visibilidad):** el informe publicable y —lo más interesante— el **análisis de
  detección**: qué *ve* realmente un EDR con el indirect puro (stack walk, telemetría, ETW). Sin
  esconder nada: midiendo.

## Cierre (por ahora)

Con M0–M6 verificados, **101 PASS / 0 FAIL** y **0 instrucciones `syscall`** en el módulo, la
tesis está confirmada **y es falsable**: cada afirmación tiene su oráculo y su transcript. Lo
que queda (ledger, `!kage`, análisis de detección) es donde el proyecto deja de ser "una
implementación más" y empieza a aportar **conocimiento medido**.

## Bibliografía y referencias

- am0nsec & smelly__vx — *Hell's Gate* (`github.com/am0nsec/HellsGate`); Sektor7 — *Halo's Gate*.
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`).
- Microsoft Learn — *ETW*, *kernel callbacks* y telemetría de seguridad.
- Fuentes primarias: `docs/research/experimentos-fase6.md`, `docs/evidencias/m5.txt`.

> Aprender a romper para poder defender.

## Cómo sigue la serie

1. [Guía de syscalls](/blog/guia-syscalls-windows.html)
2. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html)
3. [Fases 0 a 3: del toolchain al gadget](/blog/kagemusha-fases-0-3.html)
4. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html)
5. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html)
6. **Fase 6: robustez, hooks y límites reales** (esta entrada)
