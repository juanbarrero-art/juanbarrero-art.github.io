---
title: "Kagemusha — Fase 4: ejecución indirecta real"
date: 2026-10-01
tags: windows internals, red team, syscalls, investigacion
serie: Kagemusha
summary: Trampolín ASM en C + MASM que salta al syscall;ret de ntdll. NtClose_I devuelve el NTSTATUS real y el módulo no contiene ninguna instrucción syscall.
---

# Kagemusha — Fase 4: ejecución indirecta real

En la [primera entrada](/blog/kagemusha-indirect-syscalls.html) dejamos la tesis y las
fases M0–M3 verificadas. Hoy toca lo importante: **ejecutar de verdad** una `Nt*` de forma
indirecta y demostrarlo en el debugger.

> Objetivo: que el `syscall` ocurra **dentro de `ntdll`** y que nuestro módulo **no contenga
> ninguna instrucción `syscall`**.

## Implementación

- `src/core/core.c` — tablas del núcleo (`g_SsnTable`, `g_GadgetTable`) e `KageInitialize`
  **transaccional** (o todo o nada).
- `src/asm/syscalls.asm` — el trampolín `KageNtCloseStub`:

```asm
; KageNtCloseStub: sin 0F 05
mov  r10, rcx                 ; arg1 -> R10 (ABI syscall)
mov  eax, [g_SsnTable]        ; EAX = SSN
jmp  qword ptr [g_GadgetTable]; salta al syscall;ret de ntdll
KageStubStart:
KageStubEnd:
```

- `src/wrappers/wrappers.c` — `NtClose_I(HANDLE)` que devuelve el `NTSTATUS` real del kernel.

## Cómo funciona

El wrapper llama al stub; el stub mueve el primer argumento a **`R10`** (ABI de syscall),
carga el **SSN** en `EAX` y hace `jmp` al gadget `syscall;ret` de `ntdll`. El `ret` del
gadget vuelve al wrapper porque el `jmp` **preservó la dirección de retorno**.

## Pruebas (T9 + T10)

- `NtClose_I(0xDEADBEEF)` → `STATUS_INVALID_HANDLE` (`0xC0000008`).
- `NtClose_I(handle de NUL)` → `STATUS_SUCCESS` (`0`).
- El stub indirecto tiene **0 bytes `0F 05`**.
- El **módulo completo** tiene **0 instrucciones `syscall`** (verificado con `dumpbin` a nivel
  de mnemónico en `tools/verify.ps1`).

## Evidencia (cdb — `docs/evidencias/m4.txt`)

```text
bp Kagemusha!NtClose_I ; g
? poi(Kagemusha!g_GadgetTable) = 00007ffc`48540fa2
g
00007ffc`48540fa2 0f05        syscall            ; RIP DENTRO de ntdll
rax=000000000000000f                            ; EAX = SSN de NtClose
rcx=00000000deadbeef  r10=00000000deadbeef      ; arg1 en RCX y R10 (ABI syscall)
rip=00007ffc48540fa2
ntdll  00007ffc`483e0000 - 00007ffc`48647000    ; RIP dentro del rango
```

## M4+ — Experimentos de falsabilidad

Dos pruebas cierran la fase intentando **tumbar** la afirmación:

**1. La línea de retorno vuelve a nuestro código.**

```text
u Kagemusha!KageNtCloseStub L5
  4c8bd1        mov  r10, rcx
  8b05.....     mov  eax, dword ptr [Kagemusha!g_SsnTable]
  ff25.....     jmp  qword ptr [Kagemusha!g_GadgetTable]
dps @rsp L2
  00007ff6`c7712da3  Kagemusha!NtClose_I+0x13   ; vuelve al wrapper
```

**2. El SSN de la tabla gobierna el syscall** (sin llegar a ejecutarlo):

```text
ew Kagemusha!g_SsnTable 0x55
g
eax=55                    ; el stub cargó 0x55 (no depende de los bytes del stub)
rip=00007ffc48540fa2      ; sigue en el gadget de ntdll
```

## Próximos pasos

- **Fase 5:** generalizar a ≥ 8 syscalls (registro tabular, misma técnica).
- **Fase 6:** robustez multi-build y **test de hook simulado**.
- Y, de forma honesta, seguir midiendo la **superficie de detección** (stack walk incluido).

## Cierre

Tesis confirmada y **falsable**: el módulo no contiene `syscall`, el `RIP` cae dentro de
`ntdll`, el SSN lo gobierna nuestra tabla en runtime y el retorno vuelve a nuestro código.
Cada afirmación tiene su oráculo y su transcript reproducible.

> Aprender a romper para poder defender.
