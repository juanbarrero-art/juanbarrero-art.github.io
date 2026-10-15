---
title: "Kagemusha F11–F13 — Del staging al full-stack: correlación, Mimikatz y sueño"
date: 2026-10-14
tags: kagemusha, edr, evasion, windows internals, syscalls, threadpool, defender, research
serie: Kagemusha
orden: 17
summary: F11–F13 del proyecto Kagemusha. Staging en secciones pagefile con vistas W^X y ejecución en worker del thread pool (0 protects, 0 hilos), correlador propio R1–R4 calibrado contra el pipeline (baseline 3/4 real), sondas de integridad del instrumentation callback, Mimikatz real por el pipeline con Defender activo, capa RC4 con doble CRC, sleep obfuscation y el full-stack encadenado (staging+RC4+shim+sueño) con 0 protects/0 hilos verificado por ledger, cdb y Ghidra.
---

# Kagemusha F11–F13 — Del staging al full-stack: correlación, Mimikatz y sueño

La entrada anterior de esta serie cerró la **Fase 10**: habíamos aprendido a encadenar y filtrar el *instrumentation callback* de un EDR, con un techo medido (la fusión kernel-vs-callback). Pero la capa de **ejecución** —el cómo y el dónde ejecutas el código— seguía apoyada en la arquitectura de la Fase 9: una asignación privada, un protect RW→RX y a correr. Eso funciona, pero deja huellas que la Fase 9 ya había medido: región privada ejecutable, un hilo propio, un patrón temporal simple.

**F11, F12 y F13** son el tramo que ataca exactamente eso. Tres preguntas, tres bloques:

1. **F11 — ¿Dónde se ejecuta?** El payload deja de vivir en memoria privada: se mueve a una **sección de pagefile + dos vistas W^X** y se ejecuta en un **worker del thread pool que ya existía** (0 hilos nuevos, 0 protects). Además, el proyecto construye un **correlador propio (R1–R4)** que convierte las reglas de detección conceptuales en predicados medibles, y unas **sondas de integridad** que dan la vuelta al shim de F10: sirven para *detectar* contra-instrumentación.
2. **F12 — ¿Qué se ejecuta?** Payloads de verdad: un MessageBox autocontenido de 69 bytes, blobs de hasta 16 MB a ~27 MB/s, y **Mimikatz real (1.32 MB) cargado y ejecutado por el pipeline** — con **Defender activo** (RTP + Behavior + IOAV, 0 exclusiones). Incluye la capa RC4 de transporte con doble CRC y una corrección incómoda pero necesaria: un experimento anterior había medido con Defender **apagado** sin saberlo.
3. **F13 — ¿Cómo duerme y qué se encadena?** *Sleep obfuscation* (durante el sueño: sin vista ejecutable y sin payload en claro), una pantalla `--help` completa, y el **full-stack**: staging + RC4 + shim F10 + sueño, encadenado y medido pieza a pieza con tres oráculos independientes.

Este artículo es honesto de principio a fin: incluye la historia del **bug intermitente** que tuvo a tres tests fuera de la suite durante semanas (y su causa raíz, que resultó ser un hilo huérfano creado por nuestra propia calibración), las discrepancias que encontramos entre documentación y código, y los límites que quedan. Como siempre en esta serie: **un informe sin límites es publicidad**.

## Resumen ejecutivo (para quien tiene prisa)

- **Staging F11:** ejecución desde sección pagefile con vistas RW/RX (W^X por vistas, cero `NtProtectVirtualMemory`) y desde un worker preexistente del thread pool: **0 protects y 0 hilos** medidos por el ledger. Los modos `--staged` / `--staged-worker` reparten el ciclo entre dos procesos (crear/escribir en uno, mapear RX y ejecutar en otro) mediante una sección heredable.
- **Correlador R1–R4:** motor propio de predicados conductuales (ventana de 10 s por PID), con **T55 10/10** y una calibración honesta: la R4 se ajustó a N=2 porque el pipeline real hace exactamente 2 mutaciones por ciclo. Baseline real del ciclo clásico: **3/4 reglas completas** (no 4/4: hallazgo incómodo y valioso). Objetivo del staging: **≤1/4**.
- **Sondas de integridad del IC:** un callback hostil se delata por el **código de fallo** con el que rompe el proceso. El canary de `RCX` da `0x80000002` **idéntico en stealth y CET**. Con RE independiente de `KiSetupForInstrumentationReturn` que confirma el contrato del kernel por segunda vía.
- **Payloads F12:** `--msgbox` (69 bytes, verificado en cdb), `--payloadexec` (cadena observable: gadget de ntdll ← wrapper ← región), `--bigblob` (16 MB a ~27 MB/s; 20 MB rechazado fail-loud), `--exec-file` (200 KB en 7.7 ms), `--pack-file`/`--exec-blob` (RC4 de transporte con doble CRC).
- **Mimikatz real:** 1 386 571 bytes vía Donut, `privilege::debug` OK, `token::whoami` OK, `exit` 0. Con **Defender encendido** (E12.5): sin detecciones nuevas — y con la explicación honesta de por qué (ausencia de gatillos conductuales, no "evasión general").
- **Sleep obfuscation F13:** 252 muestras del inspector (stealth), **0 con vista RX, 0 con patrón en claro**, despertar verificado (retorno 42). La variante buena (la que usa el full-stack) hace *unmap* de la vista ejecutable en vez de protect: **0 protects**.
- **Full-stack `--full`:** staging + RC4 + shim + sueño encadenados: **ledger del ciclo: protects=0, threads=0**; tarea en TP en 8.2 ms; shim reenviando 27 syscalls al EDR-sim con 0 drops. Verificado con tres oráculos: ledger interno, cdb por capas (con Mimikatz real) y Ghidra (161 057 instrucciones, **0 SYSCALL**).
- **Suite del tramo:** 446/413 (fin F10) → 473/431 (catálogo 13 slots) → 483/441 (correlador) → 489/447 (sondas IC) → **507/465** tras el fix del flaky (hoy, con F14/F15, 520/479).

## 1. Dónde quedamos y qué viene en este tramo

Para situar el tramo hacen falta dos piezas de contexto de fases anteriores:

- **F9** dejó una capa de ejecución "económica": asignar, escribir, proteger RW→RX, ejecutar en hilo propio. Medida contra un baseline naive RWX, pasaba de 5→3 syscalls por ciclo y eliminaba las ventanas RWX. Pero el resultado seguía siendo **una región privada ejecutable** (`MEM_PRIVATE` o pagefile `MEM_MAPPED`) y un **hilo nuevo**: exactamente los dos rasgos que un clasificador de memoria o un correlador de eventos buscan.
- **F10** dejó un shim que encadena y filtra el *instrumentation callback* de un EDR con el discriminador correcto (`[rsp]`, el call-site). Pero el shim, hasta ahora, solo se había medido en el catálogo de syscalls de Kagemusha; nadie lo había puesto a convivir con un ciclo de ejecución completo.

El tramo F11–F13 responde, en orden, a tres preguntas de ingeniería:

1. **¿Dónde se puede ejecutar el payload sin crear regiones ejecutables anónimas propias ni hilos nuevos?** → secciones de pagefile, dos vistas con W^X por vista, ejecución en worker del thread pool (F11).
2. **¿Qué se puede ejecutar, a qué escala y con qué se topa?** → payloads reales (Mimikatz), tamaño (hasta 16 MB), transporte cifrado (RC4) y la confrontación con Defender encendido (F12).
3. **¿Cómo se duerme de forma verificable y cómo se encadena todo?** → sleep obfuscation con oráculo propio y el modo `--full` que une las capas anteriores en una sola secuencia medida (F13).

Además, el tramo produce dos artefactos que no son "evasión" sino **medición**:

- el **correlador R1–R4**, que formaliza reglas de detección como predicados y permite decir con números "el ciclo clásico cierra 3 de 4 reglas; el staging las baja a 1";
- las **sondas de integridad del IC**, que responden a la pregunta defensiva "¿cómo sabes que tu callback de instrumentación no ha sido secuestrado por un shim?".

## 2. F11 — Ingeniería inversa primero: semántica de secciones, thread pool y herencia

Antes de escribir el staging, el proyecto cerró tres preguntas (`Q11.1`–`Q11.3`) con oráculos de kernel32 y `cdb`. La regla del repo es inmutable: **nadie implementa nada que dependa de una pregunta sin cerrarla antes con evidencia**.

### 2.1 Q11.1 — ¿Qué permite una sección pagefile?

Se probaron las combinaciones con un modo de diagnóstico (`--sectionprobe`) y oráculos de `CreateFileMappingW`:

- Una sección anónima (`CreateFileMappingW(INVALID_HANDLE_VALUE, PAGE_EXECUTE_READWRITE)`) funciona; las vistas **RW, RD y RX coexisten** sobre la misma sección y son **coherentes** (verificado con `memcmp` inmediato).
- **Sorpresa medida:** la vista **RWX es aceptada** (`err=0`), en contra de la hipótesis del plan, que esperaba un rechazo. El mecanismo la evita igualmente por diseño —W^X por vistas— pero el dato es el dato: en esta build, la sección no bloquea la vista RWX. La evidencia conserva incluso la línea con la expectativa vieja ("rechazo esperado" junto a `err=0`), que es un bonito monumento a "el plan se equivoca, la medición manda".

### 2.2 Q11.3 — ¿Dónde corre un callback del thread pool?

Se ejecutó una tarea por el TP y se capturó la pila con `cdb`:

```text
ntdll!TppWorkerThread+0x819  <- frame superior del worker
ntdll!TppSimplepExecuteCallback+0x14d
Kagemusha!KageStageTpCall
```

Y el contador de syscalls del ledger reveló la vía de movilización: `NtSetInformationWorkerFactory` 1 vez (el submit), `NtWaitForWorkViaWorkerFactory` 4 veces (los workers), `NtSetIoCompletion` **0 veces**. Es decir: el thread pool de Windows moviliza una **worker factory**, no un puerto de completación. Traducción para el modelo de amenaza: el hilo que ejecuta tu payload **ya existía**, su frame superior es código de `ntdll`, y no hay evento de creación de hilo.

### 2.3 Q11.2 — Herencia de handles entre procesos

Para el ciclo en dos procesos (P1 crea y escribe, P2 mapea y ejecuta) hace falta heredar la sección. Medido:

- Con `OBJ_INHERIT` en la creación de la sección + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + `bInheritHandles=TRUE`: el handle llega al hijo **estable en valor** (`0xB0 → 0xB0`), los datos son visibles y el VAD del hijo reporta `MEM_MAPPED (0x40000)` con protección de lectura — la distinción de VAD que el correlador R3 explota.
- **Fixture clave:** sin `OBJ_INHERIT`, el spawn con `HANDLE_LIST` **falla con error 87** (parámetro inválido). Es un fail-noisy del sistema que la implementación documenta y usa como control.

## 3. F11 — Staging: sección pagefile, dos vistas y un worker que ya existía

### 3.1 El diseño

`KageStageCreateSection` crea la sección con cuatro decisiones deliberadas:

- `SEC_COMMIT` sobre **pagefile** (sin fichero backing): la región vive en memoria respaldada por el sistema.
- Máscara de acceso `SECTION_ALL_ACCESS` y protección máxima `PAGE_EXECUTE_READWRITE` en el **objeto** sección.
- `OBJ_INHERIT` en los atributos, para el ciclo en dos procesos.
- Nada de `NtProtectVirtualMemory` en todo el ciclo: **W^X por vistas**.

El detalle que conviene no maquillar: la sección **nace declarando ERW**. El W^X es *por vista* — la vista de escritura es RW y la de ejecución es RX, y son vistas distintas del mismo objeto —, pero un sensor que consulte el **objeto sección** (en vez de las vistas) ve una sección que admite ejecución y escritura. Es inherente a la técnica y queda anotado (matriz v3 lo mediría después: la vista de escritura aparece incluso como `EXECUTE_WRITECOPY`).

El ciclo de uso es:

```text
KageStageCreateSection   -> seccion (pagefile, OBJ_INHERIT)
KageStageMap(RW)         -> vista de escritura
   ... escribir/RC4 ...
KageStageMap(RX)         -> vista de ejecucion (ViewUnmap: no protege, mapea distinto)
KageStageExecTp(RX)      -> worker del thread pool ejecuta desde la vista RX
KageStageUnmap / NtClose -> teardown
```

Dos formas de ejecutar, con costes medidos distintos:

- `KageStageExecThread`: hilo propio con `StartRoutine = base RX` (el inicio del payload cae **dentro** de la región: juega a favor del correlador, ver §4). Espera acotada y, tras el fix de revisión **B-M1**, `WaitForSingleObject(INFINITE)` después de `TerminateThread` antes de cerrar el handle — la versión original tenía un **use-after-free** por cerrar el handle mientras el hilo moría.
- `KageStageExecTp`: **worker preexistente** del thread pool. El código actual usa `CreateThreadpoolWork` + `SubmitThreadpoolWork` + `WaitForThreadpoolWorkCallbacks(Work, TRUE)` + `CloseThreadpoolWork`, y espera por **evento** con `Sleep(1)` de respaldo. Esto también viene de una corrección de revisión (**M1**: antes, `TrySubmitThreadpoolCallback` podía dejar un callback encolado ejecutándose cuando el ciclo ya había desmapeado la sección).

### 3.2 Modos CLI y resultados

| Modo | Qué hace | Ledger medido |
|---|---|---|
| `--sectionmap` | Ciclo intra-proceso con hilo propio | **protects=0, threads=1** |
| `--tpexec` | Ciclo intra-proceso en worker TP | **protects=0, threads=0** |
| `--staged` / `--staged-worker` | P1 crea+escribe, P2 (spawn con `HANDLE_LIST`) mapea RX y ejecuta en TP | **P2 exit 0, protects P1=0** |

Idéntico en la build CET. Y una particularidad de implementación que merece confesión operativa: `ModeStaged` pasa el **valor** del handle por la línea de comandos al hijo (fiándose de que la herencia preserve el valor, medido estable en `Q11.2` y en todos los runs). Si un día el runtime del hijo reordenara los handles, el hijo fallaría **ruidosamente** (mapeo distinto → error), nunca en silencio.

### 3.3 El catálogo crece a 13 syscalls (y se rompe la compilación si mientes)

Para el staging hacen falta tres syscalls más: `NtCreateSection`, `NtMapViewOfSection` y `NtUnmapViewOfSection`. Se añaden por el proceso estándar del proyecto — nada de llamadas "raw":

- Enum en `core.h`, tabla `g_Catalog` en `core.c` (13 entradas), stubs por la macro `KAGE_STUB` (slots 10–12), wrappers tipados con `KAGE_REQUIRE_INIT` y registro en el ledger.
- **Guard de compilación**: `KageCatalogMatchesSlots` rompe el build si el enum, la tabla y el ASM se desincronizan. No es cosmético: con 13 slots, el shim de F10 también crece (tres bloques de clasificación nuevos, bits `0x04/0x08/0x10` del segundo byte de la máscara).
- El tail-call de los stubs soporta la aridad de 10 argumentos de `NtMapViewOfSection` sin cambios: es el dividendo del diseño de Fase 5 (el `jmp` preserva pila y argumentos 5+).

**Bug de calibración encontrado en una demo manual:** `KageCbShimCalibrate` registraba los call-sites de 10 de los 13 slots en modo aislado. La demo en vivo lo destapó (hacía falta calibrar los slots 10–12 con argumentos benignos: crear sección RW, mapear vista, desmapear, cerrar). Corregido, hoy `--cbshim` reporta **13/13**.

## 4. F11 — El correlador R1–R4: convertir reglas en números

### 4.1 Qué es y por qué importa

Todo este proyecto gira alrededor de una jerarquía: **conducta > ejecución > mecanismo**. El mecanismo (indirect syscalls) y la ejecución (staging, sleep, full-stack) ya tienen medición. La conducta —las reglas que correlacionan eventos— era hasta F11 una caja negra: "esto probablemente dispara reglas". El correlador la abre: es un motor propio que ingiere eventos tipados `(Pid, Tid, TsMs, Kind, A0..A2)`, con ventana de 10 segundos por PID y tope de 512 eventos, y evalúa cuatro reglas formales:

| Regla | Predicados | Qué modela |
|---|---|---|
| **R1** (3) | (a) ancla `ALLOC` privado de un PID; (b) `PROTECT_RX` o `MAP_RX` de esa base, mismo PID; (c) `THREAD_START` con StartRoutine **dentro** de `[base, base+size)`, mismo PID | Inyección clásica: asignar, hacer ejecutable, lanzar un hilo ahí |
| **R2** (2) | `SYSCALL` con caller **unbacked** + caller = frame 0 | La firma de pila de E3: el retorno cae en memoria sin módulo |
| **R3** (3) | (a) ancla `EXEC`; (b) la base tiene `ALLOC`/`PROTECT_RX` **propio** (una vista `MAP` no cuenta: el backing es ajeno); (c) `SYSCALL` con call-site dentro de esa base | Región "sin dueño" ejecutando syscalls |
| **R4** (1) | ≥2 mutaciones de memoria (`ALLOC/PROTECT/MAP/FREE`) del mismo PID en **<5 ms** | Frecuencia: el patrón de asignar+proteger en ráfaga |

El motor se valida con **T55: 10/10** usando streams sintéticos: baseline 4/4 con predicados exactos (3/2/3/1), staged con el exec movido fuera de la región (R1 ≤1/3, total ≤1/4 y R2 viva), ventana expirada y reset.

### 4.2 La calibración que corrige al plan (R4 = 2, no 3)

El plan estimaba N=3 mutaciones para R4. La medición del pipeline real dice otra cosa: el ciclo clásico hace **exactamente 2** (un `ALLOC` + un `PROTECT`). Así que `KAGE_CORR_R4_MUTANTS` quedó en **2**, calibrado contra medición, no contra intuición. Con N=2, el ciclo clásico **dispara** R4 y el staging (que reparte 1+1 mutaciones entre dos PIDs) **no**.

### 4.3 Baseline real: 3/4, y una regla que se queda abierta

`--correlate` corre el ciclo clásico de F9 y alimenta el motor con los valores reales del ciclo:

```text
R1 2/3 incompleta   (el ThreadStart real cae FUERA de la region)
R2 2/2 COMPLETA
R3 3/3 COMPLETA
R4 1/1 COMPLETA     -> baseline 3/4
```

El hallazgo incómodo y valioso: **R1(c) no cierra** en el ciclo clásico, porque el `StartRoutine` real es `KageExecThreadEntry` (el thunk de la **imagen** de Kagemusha), no una dirección dentro de la región asignada. La hipótesis del plan ("R1 cierra 3/3") era falsa: la señal de inyección del ciclo clásico no vive en R1 sino en **R2/R3**. El modo imprime el contraste explícitamente ("FUERA de la region") para que el número no se pueda leer mal.

Con el staging, el delta esperado es **3/4 → ≤1/4**: el exec se muda a un worker preexistente, la vista RX es una vista de sección (no una base propia) y las mutaciones se reparten entre procesos. Lo único que sigue en pie como techo es **R2** (la pila), que es justo el techo S4 declarado en fases anteriores.

### 4.4 La letra pequeña (para que el número no engañe)

Honestidad de laboratorio sobre lo que este "3/4" es y no es:

- El demo `--correlate` alimenta **R2 con constantes** (`A1=1`, `A2=1`) por construcción, apoyándose en lo que E3/T26 ya midieron con cdb. Las anclas de R1/R3 (base, tamaño, ThreadStart, exec) **sí son valores reales** del ciclo recién corrido. El motor queda validado por T55; el baseline tiene **una regla alimentada por medición previa**, no por telemetría externa en vivo.
- El correlador **aún no consume streams externos** (ETW): los eventos vienen del propio proceso. Convertirlo en consumidor real llegará con la telemetría de kernel (F14/F15, próxima entrada).
- El tope de 512 eventos se descarta **en silencio** si se supera; R3 depende del orden del feed. Deuda declarada.

## 5. F11 — El otro lado: sondas de integridad del instrumentation callback

El tramo no es solo ofensivo. En F10 aprendimos a poner un shim delante del callback de un EDR; en F11 el proyecto construye las **sondas de integridad**: si un EDR quiere saber si *su* callback sigue siendo el suyo, ¿qué puede hacer desde user-mode? Recordemos que la query del slot es negativa (`0xC0000003`) y el TEB no señaliza: **no se puede leer el puntero**. Pero se puede hacer algo mejor: **provocar un fallo controlado y mirar el código con el que el proceso rompe**.

### 5.1 La técnica: el código de fallo como huella

`--cbsentinel` lanza cuatro hijos (`--cbsentinel-child <modo>`), cada uno con un callback de prueba hostil distinto y una sonda; el veredicto se lee por **exit code**:

| IC de prueba | Sonda | Stealth | CET |
|---|---|---|---|
| Conforme (harness) | Hilo nuevo + `CreateEventA` | exit 0 | exit 0 |
| `ret` (1 byte `C3`) | Hilo nuevo | **0xC0000005** (AV) | 0xC0000409 |
| `rcx` (suplanta RCX = dir del callback y salta) | Hilo nuevo | **0x80000002** | **0x80000002** |
| `rax` (`mov eax, STATUS_ERROR; jmp r10`) | `CreateEventA` | 0x600D0001 | 0xC0000409 |

El más robusto es el **canary de RCX**: `0x80000002` (misaligned) **idéntico en stealth y CET**. Y tiene una lectura bonita: es exactamente el fallo que produciría el shim de F10 **en su versión pre-fix** (la que pisaba RCX y mataba los hilos nuevos). Es decir, la sonda delata al shim que se equivoque en el contrato, y resulta que el "error" delatado tiene firma estable.

Complemento in-process: **T59** (6 checks) instala un IC hostil de tipo `rax`, verifica que `CreateEventA` falla (la API ve el STATUS corrupto), desinstala y verifica que vuelve a funcionar.

### 5.2 Por qué funciona: RE independiente del kernel

Para no tratar la técnica como magia, el proyecto decompiló `nt!KiSetupForInstrumentationReturn` (Ghidra + PDB de `ntoskrnl`) y confirmó el contrato del kernel **por segunda vía** (la primera fue el PDB en Q10.5):

```c
// Si hay callback y el frame vuelve a usuario (CS == 0x33 en frame+0x170):
*(ULONG64 *)(frame + 0x58)  = *(ULONG64 *)(kprocess + 0x168);
//            ^ slot de RIP del frame      ^ KPROCESS.InstrumentationCallback
```

El kernel escribe el puntero del callback **en el slot de RIP del marco de excepción/retorno**. De ahí sale todo: que el callback entre con la pila del usuario intacta, que `RCX` apunte a sí mismo, y que un callback que "use `ret`" o pise registros del contrato haga explotar al hilo de formas distinguibles. El offset `+0x168` queda confirmado por **dos rutas independientes** (PDB y decompilado).

**Novedad declarada:** revisado el estado del arte en F10, la fusión "contrato de RCX → sonda de integridad por código de fallo" no aparece publicada: los precedentes usan RCX para *suplantar* (Wave) o para verificar su propio puntero (Hyperion). Aquí se usa para **clasificar contra-instrumentación sin leer el slot**, que desde user-mode es imposible.

## 6. F11 — La saga del flaky T56–T58 (el bug que solo pasaba en la suite)

Esta historia merece su propia sección porque es el mejor ejemplo de método del tramo, y porque empieza con una decisión incómoda.

### 6.1 El síntoma y la decisión

Los tests T56–T58 (staging intra, tpexec y staged end-to-end) fallaban con una **excepción de acceso `0xC0000005` no determinista**, solo dentro de la suite completa, en ambas builds, con el punto de crash **variable** (a veces T56.7, a veces T57.4, a veces ni se reproducía). Reproducir en fresco: 0 fallos en 30 corridas. Bajo `cdb`: no crashea (el debugger altera mitigaciones). `WER` sin dump.

La decisión de integridad fue quitar los tres tests de la suite (`#if 0` + comentario) y dejar los modos CLI como verificación, **declarando el flaky** en vez de convivir con un rojo intermitente. Suite: 483/441.

### 6.2 La bisección (E11.4b)

Primera campaña forense: desactivar F10 entero → **sin crash** (434/0). Reactivar por partes → **solo T52** (shim + filtro con drops) es precondición. ¿Los `NtClose` inválidos? No: sin ellos, igual. ¿El estado global? Con procesos frescos no pasa. Conclusión parcial publicada: *"T52 es la precondición del flaky; causa raíz pendiente"*. El repo quedó con la suite estable (483/441) y la deuda documentada — sin maquillaje.

### 6.3 El cierre (E14.0 / L7): cazado a la primera

La causa se cazó al reactivar T56–T58 con un **`SetUnhandledExceptionFilter` de diagnóstico**. Crónica del crash capturado en la primera corrida:

```text
EXCEPTION_ACCESS_VIOLATION (EXECUTE) en direccion 0
RIP = 0
Stack: BaseThreadInitThunk+0x17  <- el hilo arranco y salto a NULL
```

Un **hilo que empieza con `StartRoutine = NULL`**: el kernel crea el hilo y cuando el nuevo hilo va a arrancar, ejecuta `call NULL`. Y el punto variable era puro **scheduling**: cuanto más vivía el proceso (suite completa), más probable que el hilo huérfano llegara a correr dentro de la ventana del test.

**Causa raíz, confirmada:** `KageCbShimCalibrate` calibraba el slot 9 llamando a `NtCreateThreadEx` con `ProcessHandle = Self` y `StartRoutine = NULL`. La idea original era "el syscall fallará y el stub registrará igual el call-site" — y el stub lo registra, sí, pero el kernel **aceptaba crear el ETHREAD** con StartRoutine NULL, y el fallo era diferido (`call NULL` en el hilo nuevo). Encaja con toda la evidencia: sin F10 no hay `Calibrate`; T52 alarga la vida del proceso; los modos CLI no llaman a `Calibrate`; `--cbshim` termina antes de que el huérfano corra.

### 6.4 El fix (y la regresión que lo blinda)

El fix es quirúrgico: `ProcessHandle = (HANDLE)0xDEADBEEF` — **no múltiplo de 4** → `STATUS_INVALID_HANDLE` garantizado **antes** de crear el ETHREAD. El syscall falla temprano, el stub registra el call-site igual, y no nace ningún hilo. La revisión posterior validó la garantía estructural y añadió el cierre defensivo del handle. Y la lección se convirtió en test: **T51.1b** toma un snapshot de hilos (Toolhelp) antes y después de la calibración y exige que **no haya hilos nuevos**.

Resultado post-fix: **507/0 stealth (9/9 corridas), 465/0 CET (3/3)**, verify limpio. T56–T58 reincorporados.

## 7. F12 — Payloads de verdad: del MessageBox de 69 bytes a Mimikatz

Con el staging funcionando, la pregunta pasa a ser "¿y qué ejecutas?". F12 lleva el pipeline a payloads reales, mide su escala y lo confronta con Defender.

### 7.1 El pipeline y sus números

| Modo | Qué hace | Números medidos |
|---|---|---|
| `--msgbox` | Payload **autocontenido**: strings dentro de la propia región vía `lea rdx/r8, [rip+disp]` parcheado en tiempo de build | **69 bytes**; `cdb` confirma `MessageBoxA` con `rdx=region+0x2c`, `r8=region+0x3b` y **RetAddr=region+0x24** (el retorno cae dentro de la región: es el tell de E3, medido en vivo) |
| `--payloadexec` | Stub de 24 bytes que llama a `NtQuerySystemTime_I` desde la región | `cdb`: cadena `gadget de ntdll ← wrapper de la imagen ← región unbacked`; Ghidra desensambla el volcado y coincide byte a byte |
| `--bigblob <MB>` | Relleno de NOPs + `xor eax,eax; ret` (fault-in de todas las páginas) | 1 MB: 36.6 ms (**27.3 MB/s**) · 4 MB: 152.9 ms (26.2) · **16 MB: 600 ms (26.7)** · 20 MB: **rechazado fail-loud** ("fuera de rango") |
| `--exec-file` | Shellcode PIC arbitrario desde fichero | Smoke de 200 KB: **7.7 ms** |
| `--pack-file` / `--exec-blob` | Capa RC4: cifrar blob en disco / ejecutar blob cifrado | Ver §7.2 |

El tope del formato de blob es **16 MB** (`KAGE_BLOB_MAX_EXPAND`, fail-loud con error): subirlo sería "dos constantes y una regresión", pero queda declarado como decisión de diseño, no como límite accidental.

¿Por qué obsesiona la escala? Porque un pipeline que solo funciona con 256 bytes no demuestra nada operativo. El tamaño del payload no cambia la *naturaleza* de la señal (la región sigue siendo una región), pero cambia tres cosas que sí importan: la **ventana de escritura** (más páginas que fault-ear), el **tiempo de copia** y la **huella en memoria** (más bytes que un escáner puede muestrear). Con ~27 MB/s, un Mimikatz de 1.32 MB se copia en unas décimas de milisegundo y una carga tipo beacon de varios MB entra sin drama; el tope de 16 MB es sencillamente el punto donde el proyecto decidió que seguir subiendo exigía una razón — y la regresión correspondiente. La escala también afecta a la *forma* de la evidencia: a 16 MB, el `--bigblob` fuerza el fault-in de todas las páginas (la primera ejecución toca cada página), que es exactamente el patrón que un sensor de memoria puede muestrear. Medirlo era el objetivo; esconderlo, no.

### 7.2 El doble CRC (y el bug que escondía)

El formato de blob lleva **dos CRCs con clave**, y la razón merece explicación porque encierra un bug real:

- **`PayloadCrc`**: CRC del dato **tal y como está en el blob** (cifrado). Lo valida el parser con solo leer el fichero. Falla con `0xC0DE0002`.
- **`ExpectedPlainCrc`**: CRC del **plaintext**. Lo valida el pipeline **después de descifrar** en la región, antes de ejecutar. Falla con `0xC0DE0003`.

El bug original: al no separarlos, un blob cifrado **legítimo** era rechazado por el parser con `0xC0DE0002` (comparaba el CRC del plaintext contra el dato cifrado que tenía delante). La evidencia de la primera prueba contra Defender **termina literalmente en esa línea** (`[exec-blob] St=0xC0DE0002`): el fichero conserva la corrida del bug, y el éxito de la capa RC4 quedó evidenciado después, con el fix, en el experimento siguiente. Es exactamente el tipo de detalle que preferimos contar a esconder: una evidencia que documenta un fallo propio vale más que diez capturas perfectas.

Y una precisión que el artículo debe cargar: **RC4 aquí es transporte, no ejecución**. Protege el blob en disco/traslado; el PE acaba **en claro en memoria** cuando ejecuta (el staging y el sueño mitigan la ventana, no la eliminan).

### 7.3 Mimikatz real por el pipeline

Payload de verdad: **Mimikatz 2.2.0 x64 (trunk) → Donut v1.1 → `mk.bin` de 1 386 571 bytes (1.32 MB)**, shellcode PIC autocontenido con la orden `privilege::debug token::whoami exit`. Ejecutado por `--exec-file` a través del pipeline F9:

```text
Mimikatz 2.2.0 ... banner completo
Privilege '20' OK
token::whoami -> KANON\juano
Bye!
exit 0
```

(Mimikatz, Donut y `mk.bin` no se versionan; en el repo queda la salida. La carpeta temporal solo tuvo exclusión para almacenar el binario, y se declara.)

### 7.4 Defender: la secuencia completa, con la corrección incómoda

Esta es la parte donde el proyecto se mira al espejo. Tres experimentos:

| Exp | Estado de Defender | Qué midió de verdad | Resultado |
|---|---|---|---|
| **E12.3** | No verificado en su momento | Funcionalidad: cargar/ejecutar un PIC real de 1.32 MB | "No interrumpió" — **sin valor de evasión** |
| **E12.4** | **RTP/Behavior/IOAV OFF** (descubierto en la propia revisión) | (a) Escaneo estático a demanda sobre `mk2.bin` y `mk2.rc4.blob`: **pasan** (esto sí es válido: las firmas están en el archivo). (b) Funcionalidad de las capas 1/2 de punta a punta | CmdLine del operador **sí** registrada en `Get-MpThreatDetection`: **Defender ve al operador** (detección sin bloqueo) |
| **E12.5** | **RTP + Behavior + IOAV ON, 0 exclusiones** | Ejecución cruda (`--exec-file`) y capa RC4 (`--exec-blob`) con todo activo: Mimikatz completo, `exit 0`, archivos intactos, **0 detecciones nuevas**, RTP siguió en True | Sin detecciones |

E12.4 se **corrigió a sí mismo** con una nota que vale oro metodológico: *"con la protección desactivada, las capas 1/2 no prueban evasión"*. Y E12.5 se publicó con el análisis honesto de sus límites:

- **Sí demuestra:** en este escenario — PE interno cifrado por Donut, ejecución **in-process sin `CreateProcess`**, comandos que **no tocan LSASS** — no hubo gatillo estático ni conductual en esa corrida.
- **No demuestra:** "evasión general". Es **ausencia de gatillos**. El caso duro (`sekurlsa::*`, volcado de credenciales) **no se midió** — llevaría a detección conductual casi segura y volcaría credenciales del equipo: una decisión explícita que se deja fuera.
- Defender quedó **encendido** después de la prueba.

## 8. F13 — Dormir sin huella y encadenarlo todo

### 8.1 Sleep obfuscation: el oráculo del inspector

`--sleepobf` demuestra el concepto con un oráculo propio en vez de promesas. El ciclo (variante sobre región F9):

```text
RX -> RW (protect)  -> RC4 cifra -> Sleep(N) -> RC4 descifra -> RW -> RX (protect) -> ejecutar
```

Durante la fase de sueño, un **hilo inspector** muestrea cada 2 ms dos cosas: la protección real de la región (consulta al OS vía `NtQueryVirtualMemory_I`) y un **patrón testigo** dentro de la misma (¿sigue el relleno en claro?). Resultado: **252 muestras, 0 con vista RX, 0 con patrón visible** (stealth); 125 muestras en CET; despertar verificado con retorno **42** en ambos. Trade-off declarado: esta variante síncrona paga **+2 protects por ciclo**.

La variante "buena" —la que usa el full-stack— no protege: **quita la vista RX** (unmap) y cifra la vista RW. Durante el sueño no existe vista ejecutable y el payload no está en claro, con **0 protects**. (La evolución asíncrona por timers del thread pool, con duty de vista ejecutable medido y validación ETW-TI, es material de la próxima entrada.)

### 8.2 `--help`: una pantalla completa en español

E13.2 añadió la pantalla de uso completa del CLI (38 modos al cierre del tramo, organizados por secciones — mecanismo, contra-instrumentación, conducta, payloads, mejoras — con ejemplos, notas del invariante "0 syscalls" y el aviso de cuarentena de Defender), generada con GLM 5.3 e interpolando el build ID real. La evidencia contiene 37 entradas `--` (el commit cuenta 38 con el selftest; hoy, con F14, son 41). Detalle de rigor: la ayuda de `--sectionmap` quedó con una errata ("Worker Thread pool" cuando ese modo usa hilo propio) — corregible, anotada.

### 8.3 El full-stack `--full`

La pieza central de F13 es la cadena completa, en el orden exacto que el código ejecuta (y que el decompilado de Ghidra confirmó 1:1):

```text
[0] opcional: EDR-sim AVA + KageCbShimInstall (shim F10) o auto
[1] KageStageCreateSection (pagefile, OBJ_INHERIT) + vista RW     -> 0 protects
[2] payload a la vista RW; con clave: RC4 cifra y descifra (demo)
[3] vista RX de la misma seccion (coherencia memcmp contra el plaintext)
[4] KageStageExecTp(RX) - worker TP preexistente                  -> 0 hilos
[5] sleep: unmap vista RX + RC4 sobre la RW + Sleep + RC4 + remap
[6] segunda tarea por el TP
[7] teardown: shim uninstall, unmaps, close de la seccion
```

Números medidos del ciclo (`--full sc42.bin <clave> shim`):

- **Ledger: protects=0, threads=0.** La ejecución en TP tarda **8.2 ms** con un payload de 256 bytes.
- **Shim: fwd=27, drops=0** — el EDR-sim siguió viendo todos los syscalls del ciclo (CET: fwd=18).
- **Mimikatz real por el staging:** banner + `privilege::debug` OK + `token::whoami` desde la vista RX en el worker del TP. **Limitación del payload, no de la técnica:** el PE de Donut llama `ExitProcess` al terminar, matando al huésped (confirmado por `kb`: `NtTerminateProcess ← RtlExitUserProcess ← ExitProcessImplementation`);
- **Verificación cdb por capas:** breakpoints dedicados registran `HIT-SHIM-F10`=1, `HIT-STAGING-F11`=1, `HIT-RC4-E12`=2 (cifrar y descifrar), `HIT-TP-EXEC`=1, `HIT-EXIT`=2 — y tras el exec en TP se ve cargar `ole32.dll` (dependencias del PE corriendo desde la sección).
- **Verificación estática Ghidra:** 161 057 instrucciones, **0 SYSCALL** (el invariante de todo el proyecto), y el decompilado de `ModeFull` reproduce la secuencia de llamadas del encadenado.

### 8.4 La letra pequeña del full-stack

Tres matices que la revisión del código destapó y que este artículo carga:

1. **El plaintext existe más de lo que el diagrama sugiere.** En `--full`, el payload vive en el heap (`malloc`) durante **todo** el ciclo y en la vista RW en claro desde el `memcpy` hasta el cifrado, y de nuevo desde el descifrado hasta el teardown. La capa RC4 solo cifra de verdad **durante el sueño** (y en transporte con `--pack-file`/`--exec-blob`). El paso [2] del código es una **demo** de la capa, no protección pre-exec.
2. **`--full` con `sleep:N` y sin clave se salta el sueño en silencio** (el guard exige clave). Deuda declarada, pendiente de un aviso ruidoso.
3. **El oráculo de patrón de `--sleepobf` es de 1 byte** (offset 0x20 contra 0x41, determinista con la clave fija). Con otra clave podría dar un falso fallo (1/256) o pasar por alto una región parcialmente cifrada. El oráculo **fuerte** es el de protección (consulta al OS); el de patrón es complementario y débil por diseño.

## 9. Revisión completa del tramo: lo aplicado y lo que queda

Como en cada fase, el tramo pasó por revisión completa con GLM 5.3 (varias pasadas). Lo **aplicado** que toca a este material:

- **Over-read en `--exec-blob`**: se validaba el `PayloadLen` sin parsear antes → ahora `KageBlobParse` primero (nada de leer longitudes de un blob hostil).
- **Carrera del thread pool**: el ciclo podía desmapear con un callback encolado → drenaje con `WaitForThreadpoolWorkCallbacks` antes de cerrar.
- **Init-once real** del núcleo (CAS atómico, no "init cada vez"): evita carreras de inicialización concurrente.
- **Colisión de hash en la tabla de exports**: antes se tomaba el primer match en silencio; ahora `KAGE_ERR_COLLISION` ruidoso.
- **Use-after-free tras `TerminateThread`** (staging): espera `INFINITE` antes de cerrar handles.
- **`--exec-file`/`--exec-blob` con `seg>0`**: el pipeline es síncrono de un solo segmento; antes se ignoraba (ilegible), ahora se rechaza con exit 2.
- **Sonda de alineación del IC**: el harness comprueba `rsp % 16 == 8` en la entrada del callback (contrato de pila medido, T50.3b).
- **Callback de ejemplo sin lectura `[r10-10h]`**: se eliminó del ASM un acceso no validado señalado por la revisión.

**Deuda declarada** (no oculta, no resuelta): singletons no reentrantes del staging; `TerminateThread` en el camino de timeout (riesgo aceptado); el correlador descarta eventos >512 en silencio y R3 depende del orden del feed; `--full sleep:N` sin clave se ignora en silencio; el callback del TP no tiene SEH propio.

Y las **discrepancias doc-vs-código** que la revisión encontró (para dejarlas dichas): la ayuda de `--sectionmap` menciona el thread pool cuando usa hilo propio; el doc de E11.4 cita `TrySubmitThreadpoolCallback` cuando el código actual (post-fix de carrera) usa `CreateThreadpoolWork`; el paso [2] del doc de E13.3 describe "cifrado antes del exec" cuando el código descifra inmediatamente (demo); la evidencia de E12.4 termina en el bug del doble CRC (la buena es la de E12.5); el estado de Defender de E12.5 consta en el doc, no embebido en la evidencia; `Q11.4` prometía un "E11.5" que no llegó a existir con ese número (la visibilidad del lab llegó en E14); y el "20/20 por modo" de E11.4 es afirmación de sesión con una sola captura de evidencia. Ninguna invalida una medición: son exactamente el tipo de costuras que un repositorio de investigación honesto debe enseñar.

## 10. Límites y techos al cierre del tramo

| Techo / límite | Estado al cierre de F13 |
|---|---|
| **S4 — walk de pila / caller unbacked** | **Techo estructural**: R2 sigue completa incluso con el staging (los syscalls del payload retornan a la región). Es "lo único que queda" tras mover el resto |
| **S5 — IC de un EDR real** | El shim de F10 se probó contra el **EDR-sim propio** (forward 27/27 en el full-stack); contra un EDR comercial real, sin medir (el probe por firma existe) |
| **S6 — ETW-TI** | **No medido en este tramo** (declarado techo): se convirtió en observable en la fase siguiente, con consumidor propio — material de la próxima entrada |
| **S7 — ETW kernel** | No medido en el tramo; pendiente declarado. (Sysmon ya se sabía ciego a los protects locales desde F9) |
| **S8 — callbacks de kernel** | Intacto: no observable desde user-mode |
| **S9 — correlación** | El correlador propio existe, está calibrado y marca el objetivo (baseline 3/4 → staged ≤1/4). El feed real (telemetría externa) llega después |
| **Payload Donut** | El PE llama `ExitProcess` al salir: mata al huésped. Workaround documentado (`--exec-file` sin `exit`) para PEs interactivos |
| **Sleep sync** | +2 protects por ciclo en la variante sobre región F9 (la variante staging es la que usa 0) |
| **Escala** | Tope de blob 16 MB (fail-loud); RC4 es transporte, no ejecución (el PE queda en claro al correr) |

Y en la columna del **aporte propio** de este tramo, frente a lo publicado:

- **El correlador R1–R4 como marco de medición**: convertir reglas en predicados, **calibrarlos contra el pipeline real** (R4=2 medido, no asumido) y publicar un baseline **3/4** que incluye el hallazgo auto-crítico de que R1(c) queda abierta por el thunk de la imagen. El 3/4 honesto vale más que un 4/4 de laboratorio.
- **Sondas de integridad del IC por código de fallo** (canary `RCX` = `0x80000002`, estable en ambas builds), con RE independiente de `KiSetupForInstrumentationReturn`.
- **Composición full-stack medida con tres oráculos** (ledger, cdb por capas, Ghidra): 0 protects / 0 hilos / 0 SYSCALL, con Mimikatz real corriendo desde la sección.
- **La investigación del flaky** (bisección → causa raíz → garantía estructural → regresión): un caso de estudio de "el bug que solo pasa en la suite".
- **La metodología Defender** (corrección E12.4 → E12.5): declarar qué se midió con qué protección activa, y separar "sin gatillos" de "evasión".

Lo que es **reproducción de técnica conocida** (con ingeniería, sin novedad): secciones pagefile con vistas W^X, ejecución en worker del pool, herencia de handles con `HANDLE_LIST`, Donut y Mimikatz como payloads, RC4, y la idea general del sleep obfuscation (Ekko/Foliage son el estado del arte; aquí la variante diferencial es el **unmap de la vista** en vez del protect, medida con 0 protects).

### 10.1 Mapa rápido: qué ve cada sensor al cierre del tramo

Para dejar el tramo ordenado, esta es la foto de visibilidad del artefacto al terminar F13 (la medición por sensor con el laboratorio llegaría después):

| Artefacto del ciclo | Qué sensor lo ve |
|---|---|
| Sección pagefile con vista RX (privada o mapeada) | Clasificador de memoria (S3), ETW kernel (S7) y — como se mediría después — ETW-TI (S6) |
| Payload en claro en la vista RX **durante la tarea** | Escáner de memoria / AMS, forense post-mortem |
| Caller del payload en memoria unbacked (la pila) | Walk de pila (S4): **techo** |
| Todos los syscalls del ciclo | Instrumentation callback (S5): **techo**, mitigado por el shim si encadena |
| Clave RC4 en `argv` | Sysmon EID 1 / WMI CommandLine (higiene: cubierto después con `--keyfile`) |
| Poll del thread pool / tempo del ciclo | No hay evento directo; patrón temporal para un correlador (S9) |
| Cargas de imagen del PE interno (ole32, ucrtbase…) | ETW Image Load (S7), Sysmon EID 7 |
| `ExitProcess` del payload Donut | Evento de proceso (visible), documentado como limitación del payload |

La lectura honesta de la tabla: el tramo **movió** el artefacto (de región privada a sección mapeada, de hilo propio a worker), y midió lo que eso vale ante el correlador propio (3/4 → ≤1/4). Pero los planos de kernel (S6/S7/S8) y la pila (S4) siguen ahí, y el laboratorio con sensores reales —y el consumidor ETW-TI propio— es la fase siguiente.

### 10.2 Cinco lecciones de ingeniería del tramo

1. **Medir antes de implementar no es burocracia.** `Q11.1` desmintió que la vista RWX fuese rechazada; `Q11.3` localizó el worker factory real (`TppWorkerThread`); `Q11.2` fijó la herencia de handles con su fixture de fallo (err 87 sin `OBJ_INHERIT`). Cada Q cerrada evitó suposiciones caras.
2. **Calibrar contra el sistema real, no contra el plan.** R4 quedó en N=2 porque el pipeline hace 2 mutaciones, no 3; el baseline fue 3/4 porque el ThreadStart real vive en la imagen. Los planes se equivocan; las mediciones se publican.
3. **Fail-loud (casi) siempre gana.** El tope de 16 MB, el `err=87` de `HANDLE_LIST`, el `STATUS_INVALID_HANDLE` del fix del flaky: fallar temprano y ruidoso es lo que convirtió bugs fantasma en garantías estructurales.
4. **Un fix sin regresión no está terminado.** El fix del hilo huérfano vino con `T51.1b` (snapshot de hilos antes/después de calibrar). El fix de alineación, con su check. La lección del flaky: si no puedes reproducirlo bajo demanda, reproduce la **garantía** que lo impide.
5. **La evidencia que documenta un fallo vale doble.** El `St=0xC0DE0002` del doble CRC, el "rechazo esperado" junto a un `err=0`, la nota de E12.4 ("Defender estaba OFF")… son capturas que no lucen y que enseñan. En un repositorio de investigación, eso es el producto.

## 11. Cómo reproducirlo

Todo local, nada sale del equipo. Windows 11 x64 + Build Tools con `ml64`.

```text
tools\build.cmd                  :: bin\Kagemusha.exe + tests (stealth)
tools\build_cet.cmd              :: variante /CETCOMPAT

bin\Kagemusha.exe --correlate    :: R1-R4 sobre el ciclo clasico (3/4 real)
bin\Kagemusha.exe --sectionmap   :: staging intra, hilo propio (0 protects, 1 hilo)
bin\Kagemusha.exe --tpexec       :: staging intra, worker TP (0 protects, 0 hilos)
bin\Kagemusha.exe --staged-worker <handle>   :: P2 del ciclo en dos procesos
bin\Kagemusha.exe --cbsentinel   :: sondas de integridad del IC (exit codes)
bin\Kagemusha.exe --msgbox       :: payload autocontenido de 69 bytes
bin\Kagemusha.exe --bigblob 1    :: 1 MB a ~27 MB/s (16 MB tope fail-loud)
bin\Kagemusha.exe --exec-file <sc.bin>       :: shellcode PIC
bin\Kagemusha.exe --sleepobf 1   :: sueno medido por el inspector
bin\Kagemusha.exe --full <sc> <clave> [shim] :: full-stack encadenado
bin\Kagemusha_tests.exe          :: suite completa (T0..T58+)
powershell -File tools\verify.ps1            :: 0 instrucciones syscall
```

Los transcripts cdb están en `docs\evidencias\e11_*.txt`, `e12_*.txt`, `e13_*.txt`; los informes por experimento, en `docs\research\experimento-e1{1,2,3}-*.md`.

## 12. Conclusiones

1. **El "dónde" cambió por completo.** Ejecutar desde una sección pagefile con vistas W^X y en un worker que ya existía convierte el ciclo en **0 protects / 0 hilos** medidos por ledger, y mueve la región del terreno "privada y anónima" al terreno "mapeada". A cambio, la sección **nace ERW** y el plaintext sigue existiendo durante la tarea: técnica mejor, no magia.
2. **Las reglas ahora se miden, no se opinan.** El correlador convierte la conducta en predicados con tests (T55 10/10), se calibra contra el pipeline real (R4=2) y publica un baseline **3/4** con su regla abierta explicada. El delta 3/4 → ≤1/4 del staging es cuantificable y reproducible.
3. **Ejecutar "de verdad" (Mimikatz) no cambió el resultado contra Defender — lo aclaró.** Con RTP/Behavior/IOAV encendidos: sin detecciones nuevas, y con el porqué declarado (sin gatillos: in-process, PE cifrado, sin LSASS). El caso duro se deja **sin medir** y se dice.
4. **El full-stack existe y está encadenado de verdad.** Tres oráculos independientes (ledger 0/0, cdb por capas con Mimikatz, Ghidra 161 057/0 SYSCALL) sobre la misma secuencia. La limitación de Donut (`ExitProcess`) se documenta como lo que es: del payload, no de la técnica.
5. **Los bugs propios son parte del resultado.** El flaky T56–T58 —tres tests fuera de la suite durante semanas por un hilo huérfano creado por nuestra propia calibración— es el mejor ejemplo del método: bisecar, capturar, encontrar la causa raíz, arreglarla con garantía estructural y blindarla con una regresión.

> Aprender a romper para poder defender.

## Referencias

- Código y documentación del proyecto: `Kagemusha` — `src/core/staging.c`, `src/core/correlator.c`, `src/core/cbshim.c`, `src/asm/`, `tests/run_tests.c` (T54–T59) y los informes `docs/research/experimento-e11-*.md`, `experimento-e12-*.md`, `experimento-e13-*.md`.
- Evidencias: `docs/evidencias/e11_*.txt`, `e12_*.txt`, `e13_*.txt`, `e14_l7_flaky.txt`.
- Microsoft Learn — *NtCreateSection* / *NtMapViewOfSection*, *NtSetInformationWorkerFactory*, *Thread Pools*, *ProcessInstrumentationCallback*.
- TheWover — *Donut*; gentilkiwi — *Mimikatz*.
- Estado del arte del sleep obfuscation: *Ekko* y *Foliage* (referencias de la literatura pública).
- Entradas relacionadas de la serie: [Visibilidad y evasión](/blog/kagemusha-visibilidad-evasion.html), [F10 — Contra-instrumentación](/blog/kagemusha-fase-10-contrainstrumentacion-callback.html), [Metodología de verificación](/blog/kagemusha-metodologia-verificacion.html) y [Por qué la evasión es en capas](/blog/kagemusha-articulo-por-que-evasion-capas.html).
