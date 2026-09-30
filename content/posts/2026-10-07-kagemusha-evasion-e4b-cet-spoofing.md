---
title: "Kagemusha — Evasión en acción: supresión de telemetría (E4b), build dual y CET vs stack spoofing (E4c/2b)"
date: 2026-10-07
tags: windows internals, red team, syscalls, investigacion, evasión, etw, cet
serie: Kagemusha
summary: Documentación de la fase de evasión del repositorio: parcheo de ETW de user-mode y limpieza del instrumentation callback (E4b, T31), build dual stealth/_cet (T29) y el hallazgo de que el stack spoofing clásico es incompatible con CET (E4c/2b).
---

# Kagemusha — Evasión en acción

Esta entrada documenta los avances de **evasión** del repositorio, tal como están en el `README.md`
y en `docs/research/`: supresión de telemetría de user-mode (**E4b**), **build dual** stealth/`_cet`
y el **hallazgo central** de que el stack spoofing clásico es incompatible con CET (**E4c/2b**).

---

## E4b — Supresión de telemetría (ETW + instrumentation callback)

De `docs/research/experimento-e4b-etw.md`. Objetivo: *"reducir la visibilidad que descubrimos en
E2 (instrumentation callbacks / ETW)."*

**Implementado:**
- **`KageEtwPatch`** (`src/core/telemetry.c`): localiza `ntdll!EtwEventWrite` y lo parchea a
  `xor eax,eax; ret` (`0x33 0xC0 0xC3`) → deja de emitir eventos **ETW de user-mode**. Con
  `KageEtwRestore` para revertir.
- **`KageClearInstrumentationCallback`**: `NtSetInformationProcess(ProcessInstrumentationCallback,
  NULL)` → elimina el callback que un monitor pudiera haber puesto en el proceso (lo de E2).

**Pruebas.** Test **T31** (5 checks: localización de `EtwEventWrite`, estado inicial, parche
aplicado, bytes verificados y restauración). Pasa en ambas builds.

**Alcance y límite (del documento, importante):**
- **Neutraliza:** ETW de user-mode (proveedores que llaman `EtwEventWrite`) y el instrumentation
  callback del proceso.
- **NO neutraliza:** **ETW-TI emitido por el kernel** (`Microsoft-Windows-Threat-Intelligence`),
  que el kernel genera sin pasar por `EtwEventWrite` de user-mode. Ese **residual de kernel** queda
  abierto (requeriría otro enfoque, fuera del alcance de user-mode).

---

## Build dual: stealth (sin CET) vs `_cet`

Del README (*"build dual (default stealth sin CET con spoofing; variante `_cet`) + T29 + guards"*):

- **Default (stealth, sin CET):** binario pensado para evasión con spoofing.
- **`_cet` (`/CETCOMPAT`):** variante CET-compatible.

Resultados por build (del README):
- **Default (stealth, sin CET): 178 PASS / 0 FAIL** (`bin\Kagemusha_tests.exe`).
- **CET (`/CETCOMPAT`): 182 PASS / 0 FAIL** (`bin_cet\Kagemusha_tests.exe`).

---

## E4c/2b — Hallazgo: CET y stack spoofing clásico son incompatibles

De `docs/research/experimento-e4c2b-cet-vs-spoofing.md`.

**Qué se hizo:** se integró el mecanismo **probado** de `WKL-Sec/LayeredSyscall`
(`HookModule.cpp`, con atribución) en Kagemusha (`src/ref_layered/`), usando **nuestra** SSN
(FreshyCalls) y una API legítima no interactiva (`LoadLibraryA("user32.dll")`). Modo `--refspoof`.

**Resultado (revelador):**

| Build | Resultado |
| --- | --- |
| Kagemusha **sin** `/CETCOMPAT` | **FUNCIONA**: `NtClose = 0xC0000008`, traza HW bp→ntdll→syscall→restore |
| Kagemusha **con** `/CETCOMPAT` (nuestro build) | **`#CP`** (0xC0000409) |

Salida real (build no-CET):

```text
[*] Hardware Breakpoint hit at 0x...0f90 (syscall)
[*] Inside ntdll after setting TF at 0x...1a90
[*] Generating stack & changing RIP & invoking intended syscall (ssn: 0xf)
[*] Hardware Breakpoint hit at 0x...0fa4 (ret)
[*] Restoring stack pointer
refspoof: NtClose = 0xC0000008 (esperado 0xC0000008)
```

**Causa raíz (del documento):** *"En Windows 11 con Shadow Stack en modo compatibilidad, solo los
binarios CET-compatibles (`/CETCOMPAT`) reciben shadow stack. La referencia (LayeredSyscall) no está
marcada → corre sin shadow stack → su spoofing funciona. Nuestro binario sí está marcado → el `ret`
de la ruta de trazado incumple el shadow stack → `#CP`."*

**Conclusión central:** el stack spoofing clásico (ret/ROP + VEH) es **incompatible con CET**; un
binario CET-compatible **no puede** usar esa técnica. Lograrlo requiere un enfoque **CET-safe propio**
(problema abierto; la técnica pública no lo resuelve). Esto **corrobora E4c/1**.

**Decisión de proyecto (pendiente, del documento):**
- **(a)** Sin `/CETCOMPAT` → stack spoofing funcionando (renuncias a CET/Shadow Stack).
- **(b)** Con `/CETCOMPAT` → sin spoofing clásico; exige técnica **CET-safe propia** (I+D).

*"Es una disyuntiva real: no puedes tener ambos con esta técnica."*

**Reproducir (del documento):**

```text
bin\Kagemusha.exe --refspoof        :: #CP (binario CET-compatible)
bin\Kagemusha_noCET.exe --refspoof  :: funciona (binario no-CET)
```

---

## Cómo se encaja con lo demás

- **E2** (instrumentation callbacks / ETW-TI) se observa en el kernel; **E4b** neutraliza la parte
  de **user-mode** (`EtwEventWrite` + callback), pero **deja abierto ETW-TI de kernel**.
- **E3** (firma de pila) se "cierra" con stack spoofing; pero **E4c/2b** demuestra que ese spoofing
  **no es compatible con CET**, forzando la disyuntiva del build dual.

---

## Cómo sigue la serie

1. [Cómo leer la serie + Misión 0](/blog/como-leer-serie-mision-0.html)
2. [Guía de syscalls](/blog/guia-syscalls-windows.html)
3. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html)
4. [Fases 0 a 3: del toolchain al gadget](/blog/kagemusha-fases-0-3.html)
5. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html)
6. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html)
7. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html)
8. [Fase 7 y baterías (T19–T22): ledger, CLI y CET](/blog/kagemusha-fase-7-baterias-cet.html)
9. [Visibilidad y evasión (Defender, E2, E3, E4c)](/blog/kagemusha-visibilidad-evasion.html)
10. **Evasión en acción: E4b, build dual y CET vs spoofing (E4c/2b)** (esta entrada)

---

## Bibliografía y referencias

- Fuentes primarias: `README.md`, `docs/research/experimento-e4b-etw.md`,
  `docs/research/experimento-e4c2b-cet-vs-spoofing.md`, `docs/research/experimento-e4c2a-veh-rip.md`,
  `src/core/telemetry.c`, `docs/evidencias/ref-layeredsyscall.txt`.
- WKL-Sec — *LayeredSyscall* (mecanismo de referencia integrado con atribución).
- Microsoft Learn — *ETW / ETW-TI* y *Control-flow Enforcement Technology (CET)*.

> Aprender a romper para poder defender.
