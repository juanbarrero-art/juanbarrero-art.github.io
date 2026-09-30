---
title: "Kagemusha: visión general, tesis y metodología"
date: 2026-09-30
tags: windows internals, red team, syscalls, investigacion
serie: Kagemusha
summary: Documento maestro de la serie: el problema, la tesis, los cinco principios de diseño, el alcance de la v1, la arquitectura por módulos, la metodología con oráculos independientes y el estado actual (M0–M6 verificados).
---

# Kagemusha: visión general, tesis y metodología

Si llegas nuevo, empieza por la [Guía de syscalls para principiantes](/blog/guia-syscalls-windows.html),
que explica desde cero qué es una syscall, qué es un stub y qué significa "indirecto". Esta
entrada es el **documento maestro** de la serie: aquí están la tesis del proyecto, sus reglas
de diseño, su arquitectura y —lo más importante— **cómo verificamos que lo que decimos es
cierto**.

> **Kagemusha** (影武者, "guerrero sombra") es un sistema de ejecución de **indirect syscalls**
> para Windows x64, escrito en **C + MASM**, con **una sola técnica**: el `syscall` se ejecuta
> dentro de `ntdll`, nunca en nuestro módulo.

## El problema, en una frase

Los stubs `Nt*` de `ntdll` son el punto donde un EDR de user-mode coloca sus *hooks*. Si tú
ejecutas el `syscall` tú mismo (*direct syscall*), dejas una instrucción `0F 05` en tu binario;
si llamas normal, pasas por el hook. Las **indirect syscalls** buscan un punto medio: tu código
**salta** a un fragmento `syscall;ret` que **ya vive dentro de `ntdll`**, de modo que el
`syscall` ocurre en memoria legítima y en tu módulo no hay `0F 05`.

## La tesis

> Es posible construir un sistema de syscalls **indirecto puro, de una sola técnica,
> auditable y reproducible**, resolviendo los números de servicio (SSN) en runtime por
> **orden de export** (*FreshyCalls*), **sin leer bytes de los stubs**, y verificando **cada
> afirmación con un oráculo independiente**.

La palabra clave es **auditable**: el objetivo no es "hacer magia indetectable", sino construir
algo **medible y falsable**. Si una afirmación no se puede comprobar con una fuente externa a
nuestro propio código, no la damos por buena.

## Los cinco principios de diseño

1. **Solo indirect syscalls.** Ninguna instrucción `0F 05` en nuestro binario. Es una propiedad
   **verificable en el debugger**: escaneamos `.text` de nuestro módulo y el resultado debe ser
   **cero** instrucciones `syscall`.
2. **Una sola técnica de resolución de SSN: FreshyCalls.** Sin híbridos, sin fallbacks
   silenciosos, sin "Hell's Gate" ni "Halo's Gate". Una técnica, bien entendida, vale más que
   cinco a medias.
3. **Resolución en runtime.** Los SSN **dependen de la build de Windows**. Escribirlos "a fuego"
   (hardcodear) garantiza romperse en la siguiente actualización. Todo se resuelve al arrancar.
4. **Código real y medido.** Cero pseudocódigo: el repositorio es código C + ASM que compila y
   corre, y cada función tiene un test con un oráculo independiente.
5. **Fallar de forma ruidosa.** Ante cualquier inconsistencia se **aborta con un error claro**;
   nunca se "adivina" un SSN ni se continúa con una tabla a medio llenar.

## Alcance de la v1: qué SÍ y qué NO

Igual de importante que decir lo que el proyecto hace es decir lo que **no** hace. Así se
mantiene honesto y acotado:

| Incluido en v1 | Fuera de alcance (v2 o nunca aquí) |
| --- | --- |
| Resolución de SSN por FreshyCalls (sort-by-VA) | Direct syscalls como mecanismo de producción |
| Localización y validación de gadget `syscall;ret` | Stack/call-stack spoofing (SilentMoonwalk, Unwinder, CallStackSpoofer) |
| Trampolín MASM por función | Sleep obfuscation / cifrado (Shelter) |
| Wrappers C tipados por syscall | VEH + hardware breakpoints (LayeredSyscall, RustVEHSyscalls) |
| PEB walk, hash DJB2, logging | Unhooking / mapeo de ntdll limpio desde KnownDlls |
| Harness de pruebas determinista | x86, WoW64 (Heaven's Gate), ARM64 |
| Verificación en cdb (RIP dentro de ntdll) | Inyección de procesos / carga de payloads |

> Dejar explícito el "no" es parte de la ingeniería. La v1 resuelve **un** problema bien:
> invocación indirecta pura, medible y reproducible.

## Stack tecnológico: por qué MSVC + MASM

Elegir el *toolchain* no es un detalle. Tras comparar opciones, la elección fue **MSVC
(`cl.exe`) + MASM (`ml64.exe`)**:

- **Integración nativa:** MASM se ensambla como un paso más del build MSVC (`.asm` → `ml64 /c`),
  sin ensambladores externos ni formatos intermedios.
- **PDBs de primera clase:** los símbolos (`Kagemusha!NtClose_I`, `Kagemusha!KageStubStart`)
  permiten *breakpoints* simbólicos limpios en `cdb`. Sin esto, la verificación sería un infierno.
- **Paridad con la referencia:** los proyectos de referencia generan stubs MASM para MSVC, así
  que nuestras comparaciones son 1:1.
- **Inspección estática incluida:** `dumpbin /disasm` viene con el toolchain.
- **Cero dependencias extra:** un instalador (Build Tools) trae `cl`, `ml64`, `link` y `dumpbin`.

Y para verificar: **`cdb.exe`** (Debugging Tools for Windows), porque es 100% CLI y
*scriptable* (`-cf`, `-logo`), usa el mismo motor que WinDbg y trae símbolos perfectos con MSVC.

## Arquitectura por módulos

El sistema está separado en capas, de arriba (tests) a abajo (utilidades):

```text
+--------------------------------------------------------------+
| tests/     HARNESS DE PRUEBAS (run_tests.c, casos deterministas)|
+--------------------------------------------------------------+
| wrappers/  CAPA C TIPADA        NtClose_I(h), NtQuery*_I...    |
+--------------------------------------------------------------+
| asm/       TRAMPOLINES x64 (1 PROC por syscall)                |
|            mov r10,rcx ; mov eax,[SSN] ; jmp [GADGET]          |
+--------------------------------------------------------------+
| core/      TABLAS + CICLO DE VIDA  g_SsnTable[], g_GadgetTable[]|
+-----------------------------+--------------------------------+
| resolver/  SSN + GADGET     |  util/  PEB, HASH, LOG, RANGOS |
| FreshyCalls (sort-by-VA)    |  UtlPeb*, UtlGetExportByHash,  |
| gadget.c (0F 05 C3)         |  UtlLog*, UtlGetModuleRange    |
+-----------------------------+--------------------------------+
```

- **`util/`** — utilidades base: `UtlGetCurrentPeb` (`gs:[0x60]`), `UtlFindModuleByHash`
  (recorre `InLoadOrderModuleList`), `UtlGetExportByHash` (hash **DJB2**), `UtlGetModuleRange`
  (rango `.text`) y `UtlLog`.
- **`resolver/`** — `freshycalls.c` (resolución de SSN) y `gadget.c` (localización del
  `syscall;ret`).
- **`core/`** — las tablas (`g_SsnTable`, `g_GadgetTable`) y **`KageInitialize` transaccional**
  (o todo se resuelve, o falla con error detallado).
- **`asm/`** — un `PROC` por syscall: `mov r10,rcx; mov eax,[tabla]; jmp [tabla]`. **Sin `0F 05`.**
- **`wrappers/`** — capa C tipada (`NtClose_I`, …) que devuelve el `NTSTATUS` real del kernel.
- **`tests/`** — el harness con oráculos independientes.

## La técnica, resumida

Tres piezas que ya explicamos en la guía, pero que aquí atan el diseño:

1. **SSN por FreshyCalls.** Se enumeran las exports `Nt*`, se ordenan por **dirección virtual**,
   y el **índice** es el SSN. **No se leen bytes del stub** → inmune a hooks.
2. **Gadget validado.** Se busca la secuencia real `0F 05 C3` **dentro de `.text` de `ntdll`**
   y se valida con bytes + rango. Un `syscall;ret` sirve para cualquier syscall (el SSN viaja en `EAX`).
3. **Trampolín.** El wrapper C llama al stub ASM; el stub mueve el 1.º argumento a `R10`,
   carga el SSN en `EAX` y hace `jmp` al gadget. El `ret` del gadget vuelve al wrapper
   (el `jmp` preservó el frame).

## Metodología: oráculos independientes

Esta es la parte que hace que el proyecto valga la pena. La regla es tajante:

> **Ninguna afirmación se comprueba contra el propio sistema. Siempre hay un oráculo independiente.**

| Afirmación | Oráculo independiente |
| --- | --- |
| PEB walk correcto | `GetModuleHandleW` (API de Windows) |
| Export resuelto correcto | `GetProcAddress` |
| Hash DJB2 correcto | vectores calculados con una herramienta aparte |
| SSN correcto | **bytes reales del stub** (`4C 8B D1 B8 <ssn>`) |
| Gadget correcto | bytes `0F 05 C3` + rango `.text` de `ntdll` |
| `syscall` en ntdll (Fase 4) | **`RIP` dentro de `ntdll`** observado en cdb |

Cada hito produce **dos** formatos de evidencia: un **test automatizado** (PASS/FAIL) y un
**transcript del debugger** (`docs/evidencias/mX.txt`), regenerable con scripts de
`tools/cdb_scripts/`. Si una verificación depende de la build de Windows, se registra el build
junto al resultado. Nada se "recuerda": todo se reproduce.

## Estado actual: M0–M6 verificados

| Fase | Hito | Estado |
| --- | --- | --- |
| 0 | Toolchain + debugger + hola-ASM | ✅ verificado (M0) |
| 1 | `util/` (PEB, exports por hash, rangos, log) | ✅ verificado (M1) |
| 2 | Resolución de SSN (FreshyCalls) | ✅ verificado (M2) |
| 3 | Gadget `syscall;ret` validado | ✅ verificado (M3) |
| 4 | Ejecución indirecta real + wrapper `NtClose_I` | ✅ verificado (M4) |
| 5 | Generalización a ≥ 8 syscalls | ✅ verificado (M5) |
| 6 | Robustez multi-build + hook simulado | ✅ verificado (M6) |
| 7 | Núcleo macro + ledger + `!kage` | 📋 planificada |
| 8 | Visibilidad / informe publicable | 📋 en curso |

Resultados de la build de referencia (Windows 11):

- **101 PASS / 0 FAIL** en `Kagemusha_tests.exe` (exit 0).
- **0 instrucciones `syscall`** en ambos ejecutables (`verify.ps1` con `dumpbin`).
- `NtClose_I(0xDEADBEEF)` → `0xC0000008`; `NtClose_I(handle válido)` → `0x00000000`.

## Tabla de SSN (FreshyCalls) vs stub real

| Función | SSN | Función | SSN |
| --- | --- | --- | --- |
| NtClose | 0x00F | NtAllocateVirtualMemory | 0x018 |
| NtCreateFile | 0x055 | NtProtectVirtualMemory | 0x050 |
| NtOpenProcess | 0x026 | NtReadFile | 0x006 |
| NtQuerySystemInformation | 0x036 | NtWriteFile | 0x008 |
| NtQueryInformationProcess | 0x019 | NtOpenKey | 0x012 |
| NtCreateThreadEx | 0x0C9 | NtWaitForSingleObject | 0x004 |

## Riesgos y límites del indirect "puro"

Un investigador honesto enumera lo que **no** resuelve su técnica:

- **Retorno visible en la pila.** El *caller* inmediato que ve un *stack walk* sigue siendo
  nuestro módulo. **No hay *stack spoofing* en v1.** Cualquier telemetría que inspeccione la
  pila puede verlo. Eso se **mide** (Fase 8), no se oculta.
- **Hot-patching del gadget.** Si `ntdll` se modifica tras nuestro init, el gadget podría
  invalidarse. Mitigación prevista: flag de re-validación por llamada.
- **SSN por build.** Resueltos siempre en runtime, nunca hardcodeados.

## Cómo sigue la serie

1. [Guía de syscalls para principiantes](/blog/guia-syscalls-windows.html)
2. **Visión general, tesis y metodología** (esta entrada)
3. [Fases 0 a 3: del toolchain al gadget](/blog/kagemusha-fases-0-3.html)
4. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html)
5. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html)
6. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html)

> Aprender a romper para poder defender.
