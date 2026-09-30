---
title: "Kagemusha: visión general, tesis y metodología"
date: 2026-09-30
tags: windows internals, red team, syscalls, investigacion
serie: Kagemusha
summary: Documento maestro de la serie. El problema de los hooks y los EDR, el panorama de técnicas de syscalls (direct, indirect, Hell's Gate, Halo's Gate, FreshyCalls), la tesis, los cinco principios de diseño, el alcance de la v1, la arquitectura por módulos, la metodología con oráculos independientes y el estado actual (M0–M6).
---

# Kagemusha: visión general, tesis y metodología

Si llegas nuevo, empieza por la [Guía de syscalls para principiantes](/blog/guia-syscalls-windows.html):
ahí se explican desde cero la transición a kernel, los stubs de `ntdll`, los SSN y la
diferencia entre syscalls directas e indirectas. Esta entrada es el **documento maestro** de la
serie: el problema, la tesis, las reglas de diseño, la arquitectura y —lo más importante— **cómo
verificamos que lo que decimos es cierto**.

> **Kagemusha** (影武者, "guerrero sombra") es un sistema de ejecución de **indirect syscalls**
> para Windows x64, escrito en **C + MASM**, con **una sola técnica**: el `syscall` se ejecuta
> dentro de `ntdll`, nunca en nuestro módulo.

> **Serie de nicho para investigadores en malware y Windows internals.** Cada entrada es una
> pieza de un laboratorio reproducible: objetivo, implementación, pruebas con **oráculos
> independientes**, evidencia de debugger y **bibliografía**. Nada se da por cierto sin prueba.

---

## 1. El contexto: por qué los EDR miran `ntdll`

Para entender el proyecto hay que entender **a quién se enfrenta**. Un **EDR** (Endpoint
Detection and Response) no es un antivirus de firmas: observa *comportamiento*. Y para observar
lo que un programa va a pedirle al sistema, la técnica clásica es el **hooking**.

**¿Qué es un hook?** Imagina que el stub `NtClose` en `ntdll` es una puerta. Un EDR
**reemplaza el principio de esa puerta** por un desvío: cuando tu programa llega, en vez de
ejecutarse el `syscall` original, corre primero el código del EDR, que inspecciona los
argumentos y **decide** si deja pasar la llamada.

En bytes, ese desvío suele ser un `jmp`:
- **Relativo (`E9 xx xx xx xx`)**: salta a otro punto.
- **Indirecto (`FF 25 ...`)**: salta a la dirección guardada en un puntero.

El problema para el atacante/investigador: **cualquier llamada normal** a `NtClose` pasa por ese
hook. Y el problema para el defensor es simétrico: quien **entiende** el hook, entiende cómo
puede intentar evitarlo. Mi posición es clara: **entender la técnica es requisito para
detectarla**. Este proyecto es, ante todo, **defensivo en su propósito** aunque su técnica sea
"ofensiva".

### El dilema de las syscalls

Cuando llamas a `NtClose` "normal", pasas por el stub (y por el hook). Existen dos formas de
intentar saltarte eso, y cada una tiene un precio:

- **Direct syscall:** tu código carga el SSN y ejecuta `syscall` él mismo. Evitas el stub… pero
  dejas una instrucción **`0F 05` en tu binario**, que un analista ve al instante.
- **Indirect syscall:** tu código **salta** a un `syscall;ret` que ya existe en `ntdll`. El
  `syscall` ocurre en memoria legítima y tu módulo no contiene `0F 05`.

Kagemusha es **indirecto puro**: no hay `0F 05` en nuestro código, y el `RIP` en el momento del
`syscall` cae dentro de `ntdll`.

---

## 2. Panorama de técnicas (y por qué elegimos una)

El "campo" tiene varios enfoques conocidos. Documentarlos es parte de la honestidad: saber qué
existe y **por qué** elegimos lo que elegimos.

| Técnica | Idea | ¿Lee bytes del stub? | ¿Inmune a hooks de user-mode? |
| --- | --- | --- | --- |
| **Direct syscall** | `syscall` en tu propio módulo | No (SSN hardcodeado) | Sí, pero deja `0F 05` en tu binario |
| **Hell's Gate** | Lee `mov eax, SSN` del stub de `ntdll` | **Sí** | **No** (si el stub está hookeado, lee basura) |
| **Halo's Gate** | Como Hell's Gate, pero "cuenta vecinos" si el stub está hookeado | **Sí** (con heurística) | Parcial (heurística frágil) |
| **FreshyCalls** | Ordena los exports `Nt*` por dirección; el índice es el SSN | **No** | **Sí** (no toca el stub) |
| **LayeredSyscall / VEH** | Resuelve SSN vía *Exception Directory* y VEH | No | Sí, pero añade estado y fragilidad |

Kagemusha elige **FreshyCalls + indirect puro** por tres razones:

1. **Una sola técnica** clara y auditable (menos superficie, más fácil de razonar).
2. **Inmunidad a hooks por diseño**: no lee bytes de stubs, así que modificarlos no la afecta.
3. **Determinismo**: el resultado depende solo del orden de exports, reproducible en cada arranque.

Lo que **dejamos fuera** (VEH, *stack spoofing*, *sleep obfuscation*) no es "mejor ni peor": es
otro problema. La v1 resuelve **uno** bien.

---

## 3. La tesis

> Es posible construir un sistema de syscalls **indirecto puro, de una sola técnica,
> auditable y reproducible**, resolviendo los números de servicio (SSN) en runtime por
> **orden de export** (*FreshyCalls*), **sin leer bytes de los stubs**, y verificando **cada
> afirmación con un oráculo independiente**.

La palabra clave es **auditable**. El objetivo no es "magia indetectable", sino algo **medible
y falsable**. Si una afirmación no se puede comprobar con una fuente externa a nuestro propio
código, no la damos por buena. Esa disciplina es más valiosa que la técnica.

---

## 4. Los cinco principios de diseño

1. **Solo indirect syscalls.** Ninguna instrucción `0F 05` en nuestro binario. Propiedad
   **verificable**: escaneamos `.text` de nuestro módulo y debe dar **cero** `syscall`.
2. **Una sola técnica de SSN: FreshyCalls.** Sin híbridos ni fallbacks silenciosos.
3. **Resolución en runtime.** Los SSN **cambian por build**; hardcodearlos garantiza romperse.
4. **Código real y medido.** Cero pseudocódigo; cada función tiene un test con oráculo.
5. **Fallar de forma ruidosa.** Ante una inconsistencia, se aborta con un error claro.

Estos principios no son decorativos: cada uno se traduce en decisiones concretas de
implementación y en pruebas que lo comprueban.

---

## 5. Alcance de la v1: qué SÍ y qué NO

| Incluido en v1 | Fuera de alcance (v2 o nunca aquí) |
| --- | --- |
| SSN por FreshyCalls (sort-by-VA) | Direct syscalls como mecanismo de producción |
| Gadget `syscall;ret` validado | Stack/call-stack spoofing (SilentMoonwalk, Unwinder, CallStackSpoofer) |
| Trampolín MASM por función (macro) | Sleep obfuscation / cifrado (Shelter) |
| Wrappers C tipados por syscall | VEH + hardware breakpoints |
| PEB walk, hash DJB2, logging, rangos | Unhooking / mapeo de ntdll limpio desde KnownDlls |
| Harness determinista + cdb | x86, WoW64 (Heaven's Gate), ARM64 |
| Verificación de `RIP` dentro de ntdll | Inyección de procesos / carga de payloads |

> Dejar explícito el "no" es ingeniería, no cobardía. Acotar el problema hace que la solución
> sea **verificable**.

---

## 6. Stack tecnológico: por qué MSVC + MASM

Elegir *toolchain* no es un detalle. Tras comparar opciones, la elección fue **MSVC
(`cl.exe`) + MASM (`ml64.exe`)**:

- **Integración nativa:** MASM se ensambla como un paso del build MSVC, sin ensambladores externos.
- **PDBs de primera clase:** los símbolos (`Kagemusha!NtClose_I`) permiten *breakpoints*
  simbólicos limpios en `cdb`. Sin esto, la verificación sería infierno.
- **Paridad con la referencia:** los proyectos base generan stubs MASM para MSVC → comparaciones 1:1.
- **Inspección incluida:** `dumpbin /disasm` viene con el toolchain.
- **Cero dependencias extra:** un instalador (Build Tools) trae `cl`, `ml64`, `link`, `dumpbin`.

Para verificar: **`cdb.exe`** (Debugging Tools), 100% CLI y *scriptable* (`-cf`, `-logo`), mismo
motor que WinDbg, símbolos perfectos con MSVC.

---

## 7. Arquitectura por módulos

![Diagrama: arquitectura por capas](../assets/diag-architecture.svg)

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

- **`util/`** — `UtlGetCurrentPeb` (`gs:[0x60]`), `UtlFindModuleByHash` (`InLoadOrderModuleList`),
  `UtlGetExportByHash` (hash DJB2), `UtlGetModuleRange` (rango `.text`), `UtlLog`.
- **`resolver/`** — `freshycalls.c` (SSN) y `gadget.c` (`syscall;ret`).
- **`core/`** — `g_SsnTable`, `g_GadgetTable` y **`KageInitialize` transaccional**.
- **`asm/`** — un `PROC` por syscall (macro `KAGE_STUB`), **sin `0F 05`**.
- **`wrappers/`** — capa C tipada (`NtClose_I`, …), devuelve `NTSTATUS` real.
- **`tests/`** — el harness con oráculos independientes.

---

## 8. La técnica, resumida

1. **SSN por FreshyCalls.** Enumerar exports `Nt*`, ordenar por **dirección virtual**; el
   **índice** es el SSN. **Sin leer bytes del stub** → inmune a hooks.
2. **Gadget validado.** Buscar `0F 05 C3` **dentro de `.text` de `ntdll`** y validar (bytes +
   rango + no-hook). Un `syscall;ret` sirve para cualquier syscall (el SSN viaja en `EAX`).
3. **Trampolín.** El wrapper C llama al stub ASM; el stub mueve el 1.º argumento a `R10`
   (ABI de syscall), carga el SSN en `EAX` y hace `jmp` al gadget. El `ret` del gadget vuelve al
   wrapper porque el `jmp` **preservó el frame**; además, no tocar la pila hace que los
   argumentos 5+ lleguen intactos al kernel.

### El flujo completo, paso a paso

```text
[1] Wrapper C:  NtClose_I(handle)
        |  valida estado (init, tablas)
        v
[2] Stub ASM:   mov r10, rcx          ; arg -> R10
                mov eax, [g_SsnTable]  ; SSN resuelto en runtime
                jmp  [g_GadgetTable]   ; salta a ntdll (sin 0F 05 aqui)
        |
        v
[3] Gadget en ntdll:  syscall ; ret    ; <-- el syscall ocurre DENTRO de ntdll
        |
        v  (ret vuelve al wrapper; la pila sigue intacta)
[4] Kernel:     SSDT[EAX] -> NtClose     ; hace el trabajo real
        |
        v
[5] Wrapper C:  devuelve el NTSTATUS tal cual
```

---

## 9. Metodología: oráculos independientes

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
`tools/cdb_scripts/`. Nada se "recuerda": **todo se reproduce**. Si una verificación depende de
la build, se registra el build junto al resultado.

---

## 10. Estado actual: M0–M6 verificados

| Fase | Hito | Estado |
| --- | --- | --- |
| 0 | Toolchain + debugger + hola-ASM | ✅ verificado (M0) |
| 1 | `util/` (PEB, exports, hash, rangos, log) | ✅ verificado (M1) |
| 2 | Resolución de SSN (FreshyCalls) | ✅ verificado (M2) |
| 3 | Gadget `syscall;ret` validado | ✅ verificado (M3) |
| 4 | Ejecución indirecta real (`NtClose_I`) | ✅ verificado (M4) |
| 5 | Generalización a ≥ 8 syscalls | ✅ verificado (M5) |
| 6 | Robustez multi-build + hook simulado | ✅ verificado (M6) |
| 7 | Núcleo macro + ledger + CLI + `!kage` | 🟡 en curso (ledger + CLI hechos) |
| 8 | Visibilidad / informe publicable | 📋 en curso |

Resultados de la build de referencia (Windows 11):

- **171 PASS / 0 FAIL** en `Kagemusha_tests.exe` (exit 0), incluidas las baterías T0–T27 (E2/E3/E4c).
- **0 instrucciones `syscall`** en ambos ejecutables (`verify.ps1` con `dumpbin`).
- `NtClose_I(0xDEADBEEF)` → `0xC0000008`; `NtClose_I(handle válido)` → `0x00000000`.

### Tabla de SSN (FreshyCalls) vs stub real

| Función | SSN | Función | SSN |
| --- | --- | --- | --- |
| NtClose | 0x00F | NtAllocateVirtualMemory | 0x018 |
| NtCreateFile | 0x055 | NtProtectVirtualMemory | 0x050 |
| NtOpenProcess | 0x026 | NtReadFile | 0x006 |
| NtQuerySystemInformation | 0x036 | NtWriteFile | 0x008 |
| NtQueryInformationProcess | 0x019 | NtOpenKey | 0x012 |
| NtCreateThreadEx | 0x0C9 | NtWaitForSingleObject | 0x004 |

---

## 11. Riesgos y límites del indirect "puro"

Un investigador honesto enumera lo que **no** resuelve:

- **Retorno visible en la pila.** El *caller* inmediato de un *stack walk* sigue siendo nuestro
  módulo. **No hay *stack spoofing* en v1.** Se **mide** (Fase 8), no se oculta.
- **Hot-patching del gadget.** Si `ntdll` cambia tras el init, el gadget podría invalidarse.
  Mitigación prevista: re-validación por llamada (flag).
- **SSN por build.** Resueltos siempre en runtime.
- **Exports `Nt*` que no son stubs.** Como `NtQuerySystemTime`, que hace `jmp Rtl*` (lo vimos en
  la Fase 5 y se cuantificó en la Fase 6: 488/488 stubs reales coinciden, 2 excepciones).

---

## 12. Cómo reproducirlo tú mismo

1. Instala **VS Build Tools** (C++ + SDK) y las **Debugging Tools for Windows** (`cdb`).
2. Configura `_NT_SYMBOL_PATH` (ver la [guía](/blog/guia-syscalls-windows.html)).
3. `tools\build.cmd` → genera `bin\Kagemusha.exe` y `bin\Kagemusha_tests.exe` (+ PDB).
4. `bin\Kagemusha_tests.exe` → suite (esperado: 0 FAIL).
5. `powershell -File tools\verify.ps1` → **0 instrucciones `syscall`** en el módulo.
6. `cdbX64 -cf tools\cdb_scripts\m4_nclose.txt -logo docs\evidencias\m4.txt bin\Kagemusha.exe`
   → observa el `syscall` **dentro de `ntdll`**.

---

## 13. Preguntas frecuentes

**¿Esto me hace indetectable?** No. Evita *hooks de user-mode*, pero el kernel sigue viendo la
llamada y hay telemetría (callbacks, ETW, stack walks). El proyecto **mide** esa visibilidad.

**¿Por qué no usar direct syscalls?** Dejan `0F 05` en tu binario: firma evidente. El indirecto
puro mueve el `syscall` a `ntdll` sin esa firma.

**¿Por qué FreshyCalls y no Hell's Gate?** FreshyCalls **no lee bytes del stub**, así que es
inmune a que el stub esté hookeado.

**¿Es legal/ético?** Es **investigación educativa y defensiva**, en laboratorio aislado.
Entender la técnica es requisito para **detectarla**.

---

## 14. Cómo sigue la serie

1. [Guía de syscalls para principiantes](/blog/guia-syscalls-windows.html)
2. **Visión general, tesis y metodología** (esta entrada)
3. [Fases 0 a 3: del toolchain al gadget](/blog/kagemusha-fases-0-3.html)
4. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html)
5. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html)
6. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html)
7. [Fase 7 y baterías (T19–T22): ledger, CLI y CET](/blog/kagemusha-fase-7-baterias-cet.html)
8. [Visibilidad y evasión (Defender, E2, E3, E4c)](/blog/kagemusha-visibilidad-evasion.html)

## Diseño en profundidad: por qué cada decisión

Detrás de cada decisión de la v1 hay una razón concreta. Nada es "porque sí".

**¿Por qué `jmp` y no `call` en el trampolín?** En la ABI x64, un `call` empujaría una nueva
dirección de retorno a la pila. Entonces, el `ret` del gadget de `ntdll` **volvería al stub**,
no al wrapper, y el flujo se rompería (o volvería a ejecutar el stub en bucle). El `jmp` (un
*tail call*) **preserva** el frame del wrapper: el `ret` del gadget regresa **directamente** al
wrapper. Además, como no tocamos la pila, los argumentos 5+ (que viajan en ella) llegan
intactos al kernel.

**¿Por qué init transaccional?** Si `KageInitialize` resolviera solo *parte* del catálogo, tendrías
un sistema a medio construir: unas syscalls listas y otras no, con fallos aleatorios difíciles de
depurar. O se resuelve **todo** (SSN + gadget para cada entrada) o se **falla con un error
detallado**. Así el estado del sistema es siempre coherente.

**¿Por qué una sola técnica?** Cinco fallbacks distintos son cinco superficies de error. Una
técnica, bien entendida y verificada, es más fácil de auditar y de defender. FreshyCalls se elige
porque es **inmune a hooks por diseño** (no lee bytes de stub).

**¿Por qué el ASM no contiene el SSN literal?** Porque el SSN depende de la build. El stub **lee**
el SSN de la tabla (`g_SsnTable`), que se llena en runtime. Y por diseño, el ASM **nunca** contiene
`0F 05`: solo un `jmp` a la tabla de gadgets.

**¿Por qué evitamos la IAT?** Porque `GetModuleHandle`/`GetProcAddress` son visibles y dependen de
`kernel32`. El PEB walk + exports por hash hacen lo mismo sin esa dependencia en el camino
crítico.

---

## Criterios de aceptación de la v1

La v1 se considera "terminada" cuando cumple, **con evidencia**, todo esto:

- **M0–M6** alcanzados en orden, con transcript de `cdb` archivado por fase.
- **Init transaccional**: éxito completo o error detallado (sin estados parciales).
- **FreshyCalls** como única técnica, sin fallbacks.
- **Gadget siempre validado** (bytes + rango + no-hook) antes de usarse.
- **Suite en verde** y **≥ 8 syscalls** con wrappers tipados.
- En el debugger: `RIP` del `syscall` **dentro de `ntdll`**, `EAX == SSN`, y **cero `0F 05`** en
  nuestro módulo.
- **Ninguna dependencia de IAT sensible** en el camino crítico.
- Documentación final con diagrama de módulos y guía de práctica reproducible.

Estos criterios son la definición de "hecho": no se "intuye" que funciona, se **demuestra**.

---

## Cómo se ve la evidencia

Cada hito deja **dos** pruebas:

1. **Test automatizado** (PASS/FAIL) con un **oráculo independiente**.
2. **Transcript del debugger** (`docs/evidencias/mX.txt`), regenerable con un script de
   `tools/cdb_scripts/`.

Un ejemplo de evidencia "buena" versus "mala":

```text
; MALA: "creo que el SSN es 0x0F porque lo lei en algun sitio"
; BUENA: contrastar contra el stub real y contra el SSN ejecutado
uf ntdll!NtClose         ; el stub dice: mov eax, 0Fh
r @eax                   ; en el breakpoint del gadget: eax == 0x0F
```

La regla es simple: **cada afirmación tiene una fuente externa**. Si no la tiene, no cuenta.

---

## Qué NO es este proyecto

Delimitar también es enseñar:

- **No es malware.** No hay payloads, no hay inyección, no hay persistencia. Es un **laboratorio**.
- **No es un "kit de evasión" listo para usar.** Es un sistema **medible** y **documentado**,
  pensado para entender.
- **No promete invisibilidad.** Al contrario: mide y **declara** su superficie de detección.
- **No resuelve "todo" de una vez.** Cada fase es un escalón con su prueba, no el final.

Si en algún momento una entrada parece "magia", es que me faltó explicar el **porqué**. Dímelo.

---

## Reproducibilidad: la parte que hace creíble el resto

Un resultado que no se puede repetir no vale para investigar. Por eso la serie se apoya en tres
reglas:

1. **Nada hardcodeado dependiente de la build.** Los SSN y los gadgets se resuelven en **runtime**.
2. **Todo con oráculo.** Cada afirmación se contrasta con una fuente externa (`GetProcAddress`,
   bytes del stub, rango `.text` de `ntdll`).
3. **Todo con transcript.** Cada hito deja un `docs/evidencias/mX.txt` regenerable con un script.

Con esas tres reglas, cualquiera con el mismo Windows de referencia puede **reproducir** y
**contradecir**. Y poder ser contradicho es lo que hace fuerte a un experimento.

---

## Bibliografía y referencias

**Fundamentos**
- Russinovich, Solomon, Ionescu — *Windows Internals, 7.ª ed.* (Microsoft Press).
- Microsoft Learn — *System Calls*, *Ntdll*, *x64 calling convention* (`learn.microsoft.com/windows/win32/`).

**Técnicas de resolución de SSN**
- am0nsec & smelly__vx — *Hell's Gate* (`github.com/am0nsec/HellsGate`).
- Sektor7 — *Halo's Gate*.
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`).
- thefLink — *RecycledGate* (`github.com/thefLink/RecycledGate`).
- MDSec — *LayeredSyscall*.
- jthuraisamy — *SysWhispers* (`github.com/jthuraisamy/SysWhispers`).

**Fuera de alcance v1 (referencias)**
- klezvirus — *SilentMoonwalk* (`github.com/klezvirus/SilentMoonwalk`).
- Kudaes — *Unwinder* (`github.com/Kudaes/Unwinder`).
- mgeeky — *CallStackSpoofer*.

**Fuentes primarias**
- Repositorio Kagemusha (privado): `docs/evidencias/`, `docs/research/`, `docs/plan-arquitectura-v1.md`.

> Aprender a romper para poder defender.
