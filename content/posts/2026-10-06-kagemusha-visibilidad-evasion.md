---
title: "Kagemusha — Visibilidad y evasión: Defender, instrumentation callbacks (E2), firma de pila (E3) y CET (E4c)"
date: 2026-10-06
tags: windows internals, red team, syscalls, investigacion, deteccion, edr
serie: Kagemusha
summary: Documentación de la cara de detección/evasión del repositorio: experimento con Microsoft Defender (0 detecciones), instrumentation callbacks / ETW-TI (E2, T25), firma residual en el call-stack (E3, T26) y evasión bajo CET/Shadow Stack (E4c, T27).
---

# Kagemusha — Visibilidad y evasión

Esta entrada documenta la parte **más interesante** de la investigación: qué ve **realmente** un
EDR cuando usas un indirect syscall, y qué queda por atacar. Tal como está registrado en el
`README.md` y en `docs/research/`.

![Diagrama: superficie de deteccion](../assets/diag-detection.svg)

---

## Detección por Microsoft Defender (del README y `experimento-defender.md`)

**Entorno:** Windows 11, Microsoft Defender activo (tiempo real ON, `AMRunningMode=Normal`),
motor `1.1.26090.9`, firmas `1.459.471.0`.

**Método:**
1. **Estático:** `MpCmdRun.exe -Scan -ScanType 3 -File` sobre `Kagemusha.exe` y `Kagemusha_tests.exe`.
2. **Conductual:** ejecución del demo, del CLI y de la **suite completa** (que incluye tests que
   parchean `ntdll` en memoria: hooks `E9` y `FF25`).
3. Monitorización de `Get-MpThreatDetection`, `Get-MpThreat` y del log
   `Microsoft-Windows-Windows Defender/Operational`.

**Resultados (del documento):**

| Prueba | Resultado |
| --- | --- |
| Escaneo estático de ambos binarios | **0 amenazas** |
| Suite completa (incl. parcheo de ntdll) | **166 PASS, exit 0** |
| Detecciones / eventos tras ejecutar | **ninguna** |
| Historial de amenazas | **vacío** |
| ¿Defender inline-hookea `Nt*`? | **No** — 488/488 stubs con prólogo limpio |

Interpretación (del documento): *"Defender en Windows 11 **no inline-hookea** los stubs `Nt*`; su
detección se apoya en **ETW-TI y callbacks de kernel**, no en hooks de user-mode."* Y: *"Resultado
de evasión: Defender (estático y conductual) no detectó a Kagemusha."*

---

## Instrumentation callbacks / ETW (E2, test T25)

**Objetivo (del documento):** comprobar si un **mecanismo de EDR moderno** observa los indirect
syscalls, a diferencia de los hooks inline (que FreshyCalls evita).

**Referencia:** `x86matthew/InstrumentationCallbackSyscallLogger` (MIT). Se **portó** la técnica a
Kagemusha como `src/core/instrument.c` (con atribución en el código) y modo CLI **`--instrument`**;
se añadió el test **T25** (IC1 registra, IC2 verifica observación).

**Resultado (del documento):** con el callback activo, Kagemusha ejecuta su catálogo y el callback
**captura cada indirect syscall**:

```text
NtClose(0xDEADBEEF, ...)              (ret: 0xC0000008)
NtQuerySystemInformation(0x0, ...)    (ret: 0x0)
NtQueryInformationProcess(0xFFFF... ) (ret: 0x0)
NtQuerySystemTime(0x...F660, ...)     (ret: 0x0)
NtYieldExecution(0x6, ...)            (ret: 0x40000024)
```

Test T25: **IC2** confirma `After >= Before + 5` → los 5 indirect syscalls fueron observados.

**Hallazgo central (del documento):**

> *"Hooks inline …: Kagemusha los **evita** … **Instrumentation callbacks** (y por extensión
> **ETW-TI**): se disparan en el kernel en **cada transición de syscall del proceso**, así que
> **ven el indirect syscall igual que uno normal**. La inmunidad a hooks inline **no** protege
> aquí."*

Y: *"la defensa moderna contra indirect syscalls no es el hook de user-mode, sino la
**telemetría de kernel / instrumentation callback / ETW-TI**."*

---

## Firma residual del indirect (E3, test T26)

De `docs/research/experimento-e3-callstack.md` y `docs/evidencias/e3.txt`. Pila capturada en el
momento del syscall (RIP en el gadget de `ntdll`):

```text
Child-SP          RetAddr               Call Site
00000023`ae0ff838 00007ff6`355838b9     ntdll!NtClose+0x12          ; RIP a mitad de stub
00000023`ae0ff840 00007ff6`355817c2     Kagemusha!NtClose_I+0x29    ; llamador = nuestro modulo
00000023`ae0ff880 00007ff6`355820a0     Kagemusha!M4_Execute+0x82
00000023`ae0ff950 00007ffc`4680cd87     Kagemusha!__scrt_common_main_seh+0x10f
00000023`ae0ff990 00007ffc`4848caec     KERNEL32!BaseThreadInitThunk+0x17
```

Señales residuales (del documento):

1. **RIP a mitad de stub:** el syscall entra en `ntdll!NtClose+0x12`, **no** en la entrada
   (`NtClose+0x0`). Formalizado en el test **T26 / E3a**: el gadget siempre está desplazado
   respecto a la entrada del stub.
2. **El llamador es un módulo de usuario (no-Microsoft, sin firmar):** la pila muestra
   `Kagemusha!NtClose_I` llamando directo a un `Nt*`. *"Es el tell más fuerte."*
3. **Pila coherente y "walkeable":** no está rota; `k` la resuelve entera (el indirect puro **no**
   oculta la pila; eso requeriría *stack spoofing*, fuera de v1).

Conclusión (del documento):

| Mecanismo del EDR | ¿Ve el indirect? |
| --- | --- |
| Hooks inline en stubs `Nt*` | No |
| Inspección de pila / ETW-TI / callbacks de kernel | **Sí** (RIP mid-stub + llamador de usuario) |

---

## Evasión bajo CET / Shadow Stack (E4c, test T27)

Del README:

> *"`KageShadowStackProbe` (`--cetprobe`) demuestra que el stack spoofing **clásico (ret/ROP)
> falla** bajo CET/Shadow Stack: el hijo termina con `0xC0000409` (#CP). Test **T27**. El camino de
> evasión válido es **CET-safe** (call-based o VEH-based, ver
> `docs/research/experimento-e4c-cet-spoofing.md`)."*

Esto conecta con la Fase 7 (T22): el trampolín `jmp` es **CET-safe por diseño**, pero intentar
cerrar la firma de pila con un `ret`/ROP clásico **rompe** bajo shadow stack.

---

## Síntesis (del README, secciones E2/E3/Defender)

| Mecanismo | ¿Ve el indirect puro? |
| --- | --- |
| Hooks inline (user-mode) | **No** |
| Instrumentation callbacks / ETW-TI | **Sí** |
| Inspección de pila / callbacks de kernel | **Sí** |
| Microsoft Defender (estático + conductual) | **No** (0 detecciones) |

La investigación deja claro el mapa: **el indirect puro reduce la superficie frente a hooks
inline, pero deja firma en la pila**, y la telemetría de kernel (ETW-TI / callbacks) sí lo ve.

---

## Resultados (del README)

- **171 PASS / 0 FAIL** · `Kagemusha_tests.exe` (exit 0).
- Módulo sin `syscall`: `verify.ps1` → 0 instrucciones.
- Defender: 0 amenazas en escaneo estático; 0 eventos conductuales.

## Reproducir (del README)

```text
bin\Kagemusha.exe --instrument    :: vuelca cada syscall observado por el callback (E2)
bin\Kagemusha.exe --cetprobe      :: prueba de stack spoofing bajo CET (E4c)
bin\Kagemusha_tests.exe           :: T25, T26, T27
```

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
9. **Visibilidad y evasión (Defender, E2, E3, E4c)** (esta entrada)

---

## Bibliografía y referencias

- Fuentes primarias: `README.md`, `docs/research/experimento-defender.md`,
  `experimento-instrumentation-callback.md`, `experimento-e3-callstack.md`,
  `experimento-e4c-cet-spoofing.md`, `docs/evidencias/e3.txt`, `src/core/instrument.c`.
- x86matthew — *InstrumentationCallbackSyscallLogger* (`github.com/x86matthew/InstrumentationCallbackSyscallLogger`).
- Microsoft Learn — *ETW-TI* y *Control-flow Enforcement Technology (CET)*.

> Aprender a romper para poder defender.
