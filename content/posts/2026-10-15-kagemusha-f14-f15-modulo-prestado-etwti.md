---
title: "Kagemusha F14–F15 — El módulo prestado: ejecutar desde una DLL firmada y lo que ve el kernel"
date: 2026-10-15
tags: kagemusha, edr, evasion, etw-ti, module stomping, windows internals, pe-sieve, research
serie: Kagemusha
orden: 18
summary: F14–F15 del proyecto Kagemusha. Ejecución de Mimikatz desde la .text de una DLL firmada (module stomping) con veredicto medido: 0 eventos ETW-TI del ciclo frente a 87.898 del sistema; stomp efímero arbitrado con pe-sieve (0 patches, 0 implantados); frames CET-safe para el stack walk; ciclo full2; y un consumidor ETW-TI propio con TDH y atribución por PID que convierte el plano S6 de techo ciego a señal medida por-operación (matriz v3). Cierre: 610/0 stealth · 562/0 CET.
---

# Kagemusha F14–F15 — El módulo prestado: ejecutar desde una DLL firmada y lo que ve el kernel

Hay una pregunta que persigue a toda técnica de ejecución evasiva y que casi nunca se responde con datos: **¿qué ve el kernel?** No "qué ve el antivirus", ni "qué opina el vendedor del EDR": qué registra *de verdad* el sistema operativo cuando tu payload corre desde una imagen firmada, duerme por timers del thread pool o sobrescribe la `.text` de una DLL de Microsoft.

Las dos fases anteriores dejaron la capa de ejecución en un buen punto: staging en sección con vistas W^X, 0 protects, 0 hilos nuevos, full-stack medido con tres oráculos. Pero quedaban tres preguntas grandes en el aire:

1. **¿Se puede ejecutar desde una imagen legítima** (no una región propia), de forma que un clasificador de memoria vea `MEM_IMAGE` y no "memoria anónima sospechosa"? — **F14, línea L2: module stomping medido.**
2. **¿Qué sensores ven qué** cuando el laboratorio entero (Sysmon, WHIDS, Defender, ETW Kernel-Memory) mira el ciclo? — **F14, baseline E14.0.**
3. **¿Se puede medir ETW-TI —el sensor de kernel que hasta ahora era un techo ciego— desde user-mode?** — **F15, con un consumidor propio.**

Este artículo cuenta cómo el proyecto respondió a las tres, con dos resultados que merecen titular: ejecutar Mimikatz desde la `.text` de `msi.dll` produjo **0 eventos ETW-TI del ciclo** entre 87 898 del sistema… y aun así el veredicto final **no** es "invisible", porque un árbitro externo (`pe-sieve`) encontró las dos señales residuales — que no eran del loader, sino de Donut. Y de esa lección nace la fase siguiente.

Como siempre en esta serie: números con evidencia, errores propios publicados y techos bien marcados.

## Resumen ejecutivo (para quien tiene prisa)

- **Baseline del lab (E14.0):** con el ciclo `--full` corriendo con todo activo — Defender 0 amenazas nuevas, Sysmon 6 eventos EID 1 (3 con la clave RC4 en la línea de comandos), **198 cargas de imagen** (66 DLLs por run), **2 reglas WHIDS** (`HeuristicSamlibDll`, `HeuristicVaultcliDll`), y ETW Kernel-Memory reducido a contadores. El baseline define exactamente qué había que bajar.
- **Sleep asíncrono (E14.2):** el sueño por timers del thread pool da **duty de vista ejecutable 0.00 %** (oráculo externo: 0/83 muestras), **0 protects, 0 hilos** — y validación de kernel: **exactamente 1 evento ETW-TI por despertar** (`id=8`, tamaño 1 MB, self-map).
- **Stomp (E14.4):** **Mimikatz completo (1.39 MB) ejecutándose desde la `.text` de `msi.dll`** (2.5 MB de section): `MEM_IMAGE`, sin regiones ejecutables propias nuevas, **0 eventos ETW-TI del ciclo** frente a 87 898 del sistema. Veredicto cdb: RIP en `msi.text`, callstack por `TppWorkerThread`, y el shim de F10 reenviando 12/12 syscalls sin un drop.
- **Stomp efímero + árbitro externo (E14.4c):** `.text` restaurada a disco al terminar el trabajo. `pe-sieve` sobre el proceso vivo: **`msi.dll` 0 patches, 0 implantados**; las únicas señales (`modified.total=2`) son el bypass de **Donut** (`ntdll!EtwEventWrite` + 3 en `amsi.dll`), no el loader.
- **La variante "sec" (E14.4b) murió con dignidad medida:** quitar la firma a una copia de la DLL **no** desbloquea las secciones `SEC_IMAGE` escribibles — el bloqueo es **política del sistema** (imágenes + VBS/HVCI), no el certificado (`0xC0000022` en las tres variantes).
- **Frames CET-safe (E14.5):** el stack walk da **100 % con nombre** (6/6 frames de módulos reales) y pasa Shadow Stack — donde el spoofing clásico moría con `#CP` (hallazgo de E4c).
- **F15 — ETW-TI medido:** spike verificado en la build 26200 (**38 683 eventos** capturados) y **consumidor propio** (C + ASM, TDH→NDJSON, self-detour de `ControlTraceW`, atribución por PID): el tráfico del ciclo `--full` son **exactamente 2 vistas ejecutables por run** (1.33 MB + 1.31 MB, la segunda como `EXECUTE_WRITECOPY`), y los internals del payload: **0 eventos**. El plano S6 pasa de "techo ciego" a **señal medida por-operación** (matriz v3).
- **Suite del proyecto:** de 507/465 al empezar F14 a **602/561** con F14 cerrada y **610/562** hoy (con la semilla de F16).
- **Lo que viene (F16):** un **loader de PE propio sin Donut** (`KageMapPe`) para eliminar las dos señales residuales que el árbitro externo encontró.

## 1. Dónde quedamos

La entrada anterior ([F11–F13](/blog/kagemusha-f11-f13-staging-correlacion-mimikatz-fullstack.html)) cerró con una foto clara: el ciclo full-stack ejecutaba desde una sección pagefile con vistas W^X, 0 protects y 0 hilos, y el correlador propio cuantificaba la ganancia (baseline 3/4 reglas → staged ≤1/4). Pero dos artefactos seguían en pie:

- **La región ejecutable seguía siendo "no-imagen".** Pagefile con vista RX es mejor que `MEM_PRIVATE`, pero un clasificador de memoria sigue viendo una región ejecutable que ningún módulo respalda.
- **Nadie había medido el ciclo contra los sensores reales al mismo tiempo.** El proyecto sabía de fases anteriores que Sysmon es ciego a los protects locales, y que ETW-TI era "techo no medido". F14 se escribió como **plan de ejecución máxima** con siete líneas (L1–L7) priorizadas por impacto y coste, y F15 como la fase que **abre el sensor de kernel**.

El plan F14 (en `docs/plan-fase14-ejecucion-maxima.md`) definía el techo irrenunciable con la misma frase de siempre: *con ETW-TI + callbacks de kernel + instrumentation callback, la invisibilidad absoluta es imposible; el objetivo es que lo que quede sea mínimo, breve y consistente con conducta benigna*. Las líneas eran: L7 (estabilidad de la suite), L3 (RE del ETW de usuario), L1 (memoria dormida ~100 %), L5 (higiene), L6 (shim automático), L2 (ejecución desde imagen) y L4 (frames CET-safe para el stack walk). Este artículo las recorre en el orden en que se cerraron.

## 2. E14.0 — El baseline: el laboratorio como marcador

Antes de optimizar nada, había que saber **qué marcaba cada sensor** con el ciclo actual. El runner `run_full_cycle.ps1` lanza el `--full` ×3 con el laboratorio completo (Sysmon, WHIDS, Defender, ETW Kernel-Memory) y consolida el resultado. Con el ciclo corriendo 6.1 s y exit 0:

| Sensor | Lo que registró del ciclo |
|---|---|
| **Defender** | 11 amenazas antes → **11 después** (0 nuevas) |
| **Sysmon EID 1** (proceso) | **6 eventos**: 3 con la **clave RC4 en la línea de comandos** + 3 de `conhost` (el hijo que el payload arrastra) |
| **Sysmon EID 7** (imagen) | **198 eventos** = **66 DLLs por run** (samlib, vaultcli, amsi, mscoree, cripto/red…) |
| **Sysmon EID 5** | 3 |
| **Sysmon EID 10** (acceso a proceso) | **146, todos de terceros** (MsMpEng, Explorer, lsass…): ninguno del ciclo |
| **Sysmon EID 8** (CreateRemoteThread) | 0 |
| **Sysmon VirtualAlloc/Protect** | **Ninguno** — Sysmon es ciego al mecanismo local (hallazgo histórico de F9, reconfirmado) |
| **WHIDS** (reglas Gene) | **2 reglas sobre Kagemusha**: `HeuristicSamlibDll` y `HeuristicVaultcliDll` (criticidad 6, 15 entradas) |
| **ETW Kernel-Memory** | **12 filas** del ciclo (4 por run, EID 8/Task 6) — solo contadores agregados, sin Base/Protect: el techo de F9 confirmado |

Lectura del baseline, y esto es lo importante: el marcador dice exactamente dónde están las señales accionables. **La clave en `argv`** (L5), **la firma de cargas de imagen del PE interno** (L2: las DLLs que carga el payload, samlib/vaultcli/amsi) y **la forma del ciclo de memoria** (L1/L2 contra sensores de kernel). Todo lo demás o es ciego (Sysmon a los protects) o es de terceros (EID 10).

## 3. E14.1 — RE e inventario: quién firma qué

Antes de tocar la ejecución, L3 hizo inventario y arqueología.

### 3.1 Inventario ETW sin admin (T62)

Con `TdhEnumerateProviders` desde user-mode y sin privilegios: **1 111 providers** registrados (el `logman` del sistema ve 1 114 líneas). Confirmados los tres que importan para el modelo: **AMSI**, **Threat-Intelligence** (`{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) y **Kernel-Memory**. T62 (8 checks) en verde, suite 515/473.

Conclusión de la línea A7: **el ciclo no emite ETW de usuario propio**; la superficie de "providers" es inventario, no señal. (La AMSI que Donut puentea es la del PE interno, y eso lo encontramos después con el árbitro externo.)

### 3.2 La "firma de imagen" del payload (RE estática)

¿De dónde salen esos 66 ImageLoad por run? Dumpbin y `strings` sobre Mimikatz 2.2.0 (1 355 264 bytes) dan la respuesta:

- **IAT de 30 módulos** (SAMLIB, Secur32/`LsaOpenPolicy`, CRYPT32, DNSAPI…), más delay-load de `bcrypt`/`ncrypt`.
- **`amsi.dll`: 0 apariciones directas** en el binario → llega **en cadena vía `shell32.dll`** (una de las cargas que disparaba EID 7).
- **`vaultcli`: carga dinámica** (un string UTF-16 + `VaultOpenVault`), sin entrada en IAT.
- `mscoree`: **sin atribuir** (pendiente menor declarado).

Traducción: la firma EID 7 es del **payload** (el PE interno), no del staging. Si quieres bajar esas cargas, tienes que cambiar **qué** ejecutas o **cómo** lo ejecutas — que es exactamente la motivación de L2 y, más adelante, de F16.

### 3.3 Telemetría real de Mimikatz (y el muro de LSASS)

La prueba más valiosa de E14.1 fue una sesión **real** (consola no elevada) con `version`, `token::whoami`, `privilege::debug`, `kerberos::list`, `crypto::certificates` y `sekurlsa::logonpasswords`. Resultados crudos:

- `privilege::debug` → `0xC0000061` (privilegio no disponible sin elevar).
- `sekurlsa::logonpasswords` **murió en `acquireLSA ; Handle on memory (0x5)`**: `ACCESS_DENIED` al abrir LSASS, sin `SeDebug`.
- En la ventana de Sysmon: **EID 10 ×11, todos Defender↔LSASS/RPC; 0 atribuibles a Mimikatz** — porque los *open* denegados **no generan** EID 10. Defender: 0 detecciones nuevas.
- `version` reveló **build 26200 con VBS activo y Credential Guard probable** (LSA aislada).

Y la guinda de ingeniería inversa: con Ghidra se decompiló `kuhl_m_sekurlsa_acquireLSA` (el punto exacto donde Mimikatz intenta abrir LSASS) y se extrajo la firma de la llamada: `OpenProcess(0x1010 | 0x410, ...)`. Es decir: la firma conductual exacta — **imagen no firmada + handle a LSASS con esos derechos** — es un **techo conductual**: la única mitigación desde user-mode es **no tocar LSASS**, o usar rutas alternativas (`kerberos::list`, `lsadump`, `dpapi`) que esta sesión midió con **0 señal**.

Este hallazgo explica el resto de la fase: la línea "payloads que no tocan gatillos" no es pereza, es la lección medida de E14.1.

## 4. E14.2 — L1: dormir sin vista ejecutable (y lo que ve el kernel)

La idea de L1 es simple de enunciar: **durante el sueño, que no exista vista ejecutable ni payload en claro**. La implementación usa timers del thread pool en vez de `Sleep` bloqueante:

```text
CreateThreadpoolTimer (one-shot, reprogramado en cada ciclo)
  por despertar:
    RC4-decrypt sobre la vista RW
    NtMapViewOfSection -> vista RX temporal
    ejecutar la tarea DESDE la vista (un stub verificable)
    unmap de la vista RX
    RC4-encrypt de vuelta en la vista RW
```

Propiedades medidas: **0 `NtCreateThreadEx` y 0 `NtProtectVirtualMemory`** en todo el ciclo (el "protect" se sustituye por map/unmap, que no toca las páginas existentes), y jitter configurable (LCG ±J %) con sonda de intervalos por **QPC** (la precisión del reloj importa: `GetTickCount64` a 15.6 ms distorsionaba el coeficiente de variación).

**T60 (14 checks)** mide el duty con un oráculo **externo** —otro hilo que pasea las regiones con `VirtualQuery` cada ~2 ms— y el resultado es el que buscábamos: **duty de vista ejecutable 0.00 %** (0 de 83 muestras en stealth, 0 de 84 en CET), 6/6 ciclos completados, tarea con retorno 42, patrón restaurado tras el cierre. Ledger: **protects=0, threads=0, mapeos≥6**. En CLI (`--sleepasync 3 300`): 938 ms, rc=42, ledger 0/0/3.

### 4.1 La validación de kernel: un map-evt por despertar

Aquí es donde la fase empieza a conectar con F15. Con el consumidor ETW-TI corriendo, 6 ciclos de sueño produjeron **exactamente 6 eventos `id=8`** (map de vista ejecutable):

- `ProtectionMask=0x20` (EXECUTE_READ), `ViewSize=0x100000` (1 MB), `CallingProcessId == TargetProcessId == Kagemusha`.
- **Mismo `BaseAddress` y mismo `TID`** en todos: la dirección se reutiliza (es una vista temporal), y el **emisor es el worker del pool**, no un hilo efímero.
- Deltas por QPC de **~1.007 s** entre eventos: el "metrónomo" del sueño visto desde el kernel, sin jitter en esa corrida (el jitter es configurable).

Contexto de ruido: el sistema emitió **42 518 eventos TI en 19 s** (~2 200/s de fondo) — la señal del ciclo es un **0.014 %** de esa tormenta. Y el trade-off declarado: menos duty ejecutable **implica** un evento de mapeo por despertar, y la sección sigue naciendo con protección máxima RWX (la variante "dos secciones" para eliminarlo quedó pendiente). Dormir mejor no significa no ser visto: significa **ver la forma exacta** en que te ven.

## 5. E14.3 — L5 (higiene) y L6 (shim automático)

### 5.1 L5: quitar la señal "gratis" del baseline

El baseline de E14.0 tenía una señal que no hacía falta pagar: **la clave RC4 viajaba en `argv`** (visible para Sysmon EID 1 y WMI). La corrección (`--keyfile`) acepta `@fichero` en `--full`, `--exec-file`, `--exec-blob` y `--pack-file`: la clave vive en un fichero (32 hex, tolerante a espacios) y **desaparece de la línea de comandos**.

Dos higienes más medidas por **T64** (11 checks):

- **Espera del thread pool sin poll:** la espera por evento manual (`SetEvent` al drenar) con respaldo de poll acotado. Latencia medida **≤50 ms** (T64.6).
- **Jitter:** el CV de intervalos quedó en **0.298 (stealth) / 0.256 (CET)** con n=16 — y se robusteció después (n≥20, CV 0.28–0.40) para que el test no dependa de una corrida afortunada.

### 5.2 L6: que el shim se monte solo

El shim de F10 sabía encadenar un callback ajeno, pero instalarlo era tarea manual (con el puntero descubierto a mano). **`KageCbShimAuto`** lo convierte en una rutina: probe por firma → **filtro de falsos positivos** sobre módulos del sistema (ntdll/kernel32/kernelbase/win32u) → **normalización** del hit a la dirección de entrada (`hit - 0x8`, recordando el prólogo del harness) → install → liveness → reinstall si hay guerra; y si no encuentra candidato, instala un **noop propio** (modo observador sin reenvío).

**T65** (12 checks) lo valida contra un EDR-sim del formato exacto: `hits=2` con `hit[0] = sim+8`, normalización exacta, forward al callback ajeno, drop con filtro total, control y uninstall limpio.

Dos límites honestos del modo `auto`: sin query del slot (hallazgo E10.1), la dirección de entrada solo se recupera **por heurística de prólogo** — un EDR con otro prólogo no se detecta; y las firmas pueden dar falsos positivos **dentro de la propia imagen** de Kagemusha (riesgo documentado del modo). Es la diferencia entre "hay una capacidad automática" y "hay un piloto automático perfecto": aquí hay capacidad, medida, con el margen declarado.

## 6. E14.4 — L2: el módulo prestado (module stomping medido)

Esta es la línea estrella de la fase, y la que da título al artículo. La pregunta: ¿se puede ejecutar el payload desde la **`.text` de una DLL firmada** que el sistema considera legítima, en vez de desde una región propia?

### 6.1 El diseño

`--stomp <dll> [payload.bin] [shim|auto]` hace exactamente esto:

```text
LoadLibraryW(dll firmada)        -> loader normal; la DLL queda como MEM_IMAGE
localizar la seccion ejecutable mas grande (parseo PE propio)
guardar los bytes originales     -> (para restaurar)
NtProtectVirtualMemory           -> ventana de escritura sobre .text
escribir el payload
NtProtectVirtualMemory           -> RX
ejecutar en un worker del TP preexistente
```

La región resultante se verifica en el test con `NtQueryVirtualMemory`: **`Type=MEM_IMAGE`, `Protect=0x20`** — a ojos de un clasificador de VAD, código de una imagen cargada.

¿Y por qué eso importa tanto? Porque la memoria de un proceso se clasifica por **quién la respalda**, no por lo que contiene. Una región privada ejecutable (el pipeline de F9) o una vista pagefile (el staging de F11) pertenecen a la categoría "memoria que nadie reclama": el rango clásico de los inyectores. Una región `MEM_IMAGE`, en cambio, está respaldada por un **fichero en disco** y aparece en los mapas de módulos como código legítimo. Un scanner que filtre "ejecutable y sin módulo asociado" **no la ve**. Ese es el intercambio exacto de la técnica: cambias "región anónima" por "imagen modificada". Y como toda modificación deja rastro (los bytes ya no coinciden con el disco), la defensa que sí la ve es la que **compara memoria contra fichero** o busca signatures implantadas — exactamente el trabajo que hace un escáner tipo pe-sieve. Por eso el stomp no termina en "ejecutar desde la imagen": termina en **restaurar la imagen** cuando el trabajo ha terminado (§8), que es la versión que deja el módulo como estaba en reposo.

### 6.2 Los hallazgos del camino (todas las puertas que se cerraron)

- **H1 — SEC_IMAGE escribible está bloqueado.** Crear una sección `SEC_IMAGE` escribible sobre un binario **firmado** de `System32` devuelve `STATUS_ACCESS_DENIED`: es una mitigación de integridad de imágenes de Windows. La variante "SEC_IMAGE + vistas" del plan **no era viable**; se usó el "loader completo" (que el plan también contemplaba).
- **H2 — El gate de TLS.** Las imágenes con directorio TLS (`dbghelp` con TLS=40, `d3d10warp`, `WindowsCodecs`) hacen que **cualquier hilo nuevo** dispare sus callbacks TLS contra la `.text` machacada: crash en `dbghelp!_dyn_tls_init`. La solución es doble: elegir candidatas **sin TLS** (`msi.dll` con `.text` de 2 535 075 bytes, `comctl32`, `msoert2`, `edputil`, `srchadmin`, `dbgcore` de 80–220 KB) y ejecutar en un **worker preexistente** (sin paso por `LdrpInitializeThread`).
- **H3 — El hilo de Donut arranca en el stub.** Restaurar la `.text` antes de que ese hilo arranque lo deja ejecutando el código restaurado de la imagen → AV (`msi!icust_IID_Lookup`). Con payload real, el modo **no restaura** (el proceso es efímero). Esta limitación se convertiría en la motivación del stomp efímero (§8).
- **H4 — Bug propio:** el blob se cifraba dos veces (doble RC4). Corregido: el `.bin` va en claro (el cifrado es del transporte, no del stomp).

### 6.3 T61 y Mimikatz desde `msi.dll`

**T61 (9 checks)** con `msi.dll`: stub ejecutado desde la imagen con retorno 42, **0 regiones ejecutables no-imagen nuevas**, y el mapa restaurado tras el release. Suite: **565/0 · 524/0**.

Y el que manda: **Mimikatz 2.2.0 completo (1 386 571 bytes) corriendo desde la `.text` de `msi.dll`** — banner, `privilege::debug` (`0xC0000061`, sin elevar), `token::whoami` OK y `exit` (el `-1073741674` es el `ExitProcess` del propio PE, documentado desde F13). Coste declarado de la técnica: **2 protects** sobre la `.text` de una imagen (topología mejor, no gratis). Un matiz de errata que dejamos dicho en §11: el protect de escritura pide **RWX**, no RW como decía el informe inicial — solo lo distingue un hook `S1` de `NtProtectVirtualMemory`.

### 6.4 El veredicto ETW-TI: cero eventos

Con el consumidor de F15 mirando, el ciclo completo de stomp (`--stomp msi.dll mk.bin`) produjo:

```text
0 eventos TI del ciclo, entre 87.898 eventos del sistema en 22 s (~4.000/s)
```

Ni un map de vista anónima (no hay sección: no hay map), ni un PROTECT reportado. Frente al `--full` (2 mapviews ejecutables por run), **la ejecución desde imagen firmada es invisible a ETW-TI en esta medición**. Los residuos: el protect en sí (que solo ve un hook `S1` en user-mode) y el **ImageLoad** de la candidata (EID 7, ya en el baseline de E14.0). La lectura no es "somos invisibles": es que **el staging era la señal** y mover la ejecución a una imagen la elimina del plano que el kernel reporta.

### 6.5 Compatibilidad con el shim y verificación en el depurador

Tres checks (T61.9–11) demuestran que stomp + shim conviven: ejecución desde imagen (ret=42), liveness y uninstall. Y la evidencia con `cdb` mientras el ciclo corre es de las que gustan:

- Breakpoint en `msi+0x1000`: los bytes de `msi.text` **coinciden con `mk2.bin`** (el primer byte es el `0xCC` del propio breakpoint).
- Callstack real: `RIP = msi.text → Kagemusha!KageStageTpCallback → TppWorkpExecuteCallback → TppWorkerThread → BaseThreadInitThunk` — el payload ejecuta desde la imagen, en un worker del pool, con la cadena de llamadas que esperábamos.
- Contadores del shim leídos **en vivo**: `g_CbFwdCount=12, g_CbDropCount=0` — el callback ajeno lo vio todo, sin un solo drop.

## 7. E14.4b — La variante "sec": una hipótesis que murió con datos

La hipótesis era razonable: si `SEC_IMAGE` escribible se bloquea **por la firma** del binario, quitar la firma debería desbloquearla. El método: copiar la DLL a `%TEMP%`, **anular el Certificate Table** (`DataDirectory[4]` a cero, verificado leyendo el fichero de vuelta) y crear la sección.

**T66** cerró la puerta con tres mediciones:

| Variante | Resultado |
|---|---|
| Firmada original + `SEC_IMAGE` RWX | `0xC0000022` (ACCESS_DENIED) |
| Copia **sin firma** + `SEC_IMAGE` RWX | `0xC0000022` |
| Copia sin firma + `SEC_IMAGE` **RW** | `0xC0000022` |

Conclusión: **el bloqueo es política del sistema** (imágenes + VBS/HVCI en la build 26200), **no el certificado**. La capacidad quedó como código latente (`KageStompPrepareSec`) y el CLI devuelve el denegado controlado con mensaje; el test verifica además que **no queda copia temporal residual**. Suite: **572/0 · 531/0**. (Otra errata anotada: el header de `stomp.h` quedó describiendo esta variante como "RWX"; el código real usa RW con doble vista.)

## 8. E14.4c — El stomp efímero y el árbitro externo

La H3 (restaurar la `.text` mataba al hilo de Donut) tenía solución: **no restaurar hasta que el payload haya arrancado**, y ejecutar en modo *fire-and-forget* para que el REPL no viva dentro del callback. Nace `--stompeph`:

```text
ejecutar (fire-and-forget en worker TP)
Sleep(1500)            -> dejar arrancar al PE
KageStompRestore       -> protect -> copiar bytes originales -> protect RX
ventana de escaneo     -> el proceso queda vivo y limpio
```

**T67 (10 checks)** usa un oráculo precioso: **memoria == disco**, leyendo los bytes del **fichero** en `PointerToRawData`. Antes de escribir: iguales. Tras escribir: distintos. Tras ejecutar y restaurar: **iguales otra vez**. El ledger del restore: 2 protects. Suite: **582/0**. Y en vivo, con `cdb`: `lm m msi` muestra en la `.text` el relleno original (`cc` ×16), es decir, el stub **ya no está**.

### 8.1 El árbitro externo: pe-sieve

Hasta aquí, Kagemusha se medía con sus propias herramientas. Para el stomp efímero se llamó a un **árbitro externo**: `pe-sieve` v0.4.1.1 escaneando el proceso vivo (con REPL y shim activos) durante la ventana:

```text
Total scanned: 64 modulos
msi.dll:       0 patches · 0 implantados · 0 IAT hooked · 0 headers modificados
modified.total: 2 -> ntdll (1 patch: EtwEventWrite) + amsi (3: AmsiScanBuffer/OpenSession)
fwd=54575 drops=0 (shim en vivo)
```

Lectura, que es la mejor lección de la fase: **la `.text` del módulo prestado quedó impecable**; las únicas señales del proceso son **el bypass de Donut** (`-b 3`: parchea `EtwEventWrite` y AMSI para que el PE interno no sea escaneado). No son señales del *loader* de Kagemusha: son la **firma del paquete** que mete dentro. Coste del efímero: **4 protects por ciclo** (2 sucios + 2 de restauración), pagados una vez por tarea.

Y de esa frase nace la siguiente fase: si las señales residuales son de Donut, el camino es **quitar a Donut de la ecuación**.

## 9. E14.5 — L4: frames CET-safe (la pila que se puede leer sin mentir)

El techo S4 es viejo conocido: el payload ejecuta en memoria que no respalda ningún módulo, y un **stack walk** lo delata ("caller unbacked"). El stack spoofing clásico —fabricar frames falsos con `ret`— ya había demostrado en E4c que **muere bajo CET**: cualquier `ret` a una dirección que no esté en el Shadow Stack provoca `#CP`. La línea L4 buscaba una versión que **sobreviva a CET** y que, además, pase un walk con nombres.

Para entender por qué el spoofing clásico muere, hay que recordar cómo funciona el Shadow Stack: cada `call` legítimo **duplica** la dirección de retorno en una pila paralela que el código normal no puede tocar; cada `ret` compara la dirección de la pila normal contra la de la sombra y, si no coinciden, salta el `#CP` y el proceso muere (`0xC0000409`). Fabricar frames falsos y "volver" a ellos con `ret` es, literalmente, pedirle a la CPU que compare contra una sombra que no está: detección garantizada. La solución no puede ser mentir más: tiene que ser **mentir sin retornar**.

### 9.1 El diseño: frames que nunca se retornan

La idea (`KageSpoofInvoke`/`KageSpoofReturn` en ASM, `KageSpoofCall` en C): montar sobre la **pila normal** una cadena de direcciones de retorno que apunten a **funciones reales con unwind info** de módulos reales:

```text
frame falso 1: ntdll!RtlVirtualUnwind+8
frame falso 2: KERNELBASE!VirtualQuery+8
frame falso 3: Kagemusha+8
... (el destino: la .text prestada)
```

La transferencia al destino se hace con un **`call` legítimo** (una única entrada en el Shadow Stack, con su `ret` balanceado cuando el stub termina). Y los frames falsos **nunca se retornan**: `KageSpoofReturn` restaura `rsp` a su valor original y hace **`jmp`** al retorno real. Es decir: la pila "miente" solo en las direcciones intermedias, pero el flujo de control nunca se apoya en esa mentira — por eso CET no protesta.

### 9.2 T63: walk 100 % con nombre, y el control negativo

**T63 (12 checks)** mide el resultado con un walk propio:

- El spoof ejecuta (ret=42).
- El walk devuelve **100 % de frames con nombre: 6/6** — `msi.dll → exe (×3) → KERNELBASE.dll → ntdll.dll`, con los frames plantados apareciendo **en la cadena exacta** que se construyó.
- **Control negativo:** cuando el destino vive en una región anónima, el spoof **también ejecuta**, pero `frame[0]` sale unbacked — el techo S4 residual, ahí donde L2 no llega.
- **Gate CET:** todo lo anterior pasa en `bin_cet` (`/CETCOMPAT` con Shadow Stack activo), el escenario donde el spoofing clásico terminaba en `#CP`.

Suite: **594/0 · 553/0**. Y la lectura estructural de la fase, que conviene subrayar: **L2 + L4 son la unidad real** — el walk solo da 100 % con nombre si el destino vive dentro de una imagen; no es spoofing de pila "suelto", es la combinación *ejecutar en módulo prestado + pila con frames verosímiles*.

## 10. E14.6 / E14.7 — full2 y el cierre de la fase

`--full2 <dll> <payload> [shim|auto] [seg]` es la integración final: **L2 (stomp) + L4 (frames CET-safe en el worker del TP) + F10 (shim) + restauración en reposo**. Técnicamente comparte manejador con `--stompeph` (una distinción histórica: el modo efímero nació antes de L4 y luego heredó los frames), y el worker usa `KageSpoofCall`.

**T68** lo mide con tres ciclos en el mismo proceso:

- El stub ejecuta vía frames L4 tres veces (ret=42 ×3).
- La `.text` queda restaurada **== disco** tras cada ciclo (memcmp contra el fichero).
- El shim acumula forwards, **0 drops**, liveness tras los tres ciclos y uninstall limpio.

El cierre E14.7 dejó el **README de F14** (`docs/fase14/README.md`) con la tabla de resultados por línea, el estado del modelo de amenaza tras la fase (S1–S9 + el árbitro pe-sieve), la reproducción y lo que queda: **stub propio sin Donut (candidato F16)**, **kagesense** (driver propio para S8 y para eliminar los protects del stomp a nivel PTE) y el BEOTM en VM. Suite al cierre: **602/0 · 561/0**.

### 10.1 Balance de las siete líneas de F14

| Línea | Resultado clave medido |
|---|---|
| **L7** estabilidad de suite | Causa raíz del flaky (hilo huérfano del calibrador) + fix estructural + regresión T51.1b: 507/465 |
| **L3** RE del ETW de usuario | Inventario (1 111 providers, T62) + firma de imagen del PE interno + telemetría real de Mimikatz + RE de `acquireLSA`: el techo de LSASS es conductual |
| **L1** memoria dormida | Duty de vista ejecutable **0.00 %**, 0 protects, 0 hilos; validado en kernel: 1 map-evt por despertar |
| **L5** higiene | Clave fuera de `argv` (`--keyfile`), espera por evento (≤50 ms), jitter (CV ~0.27–0.40) |
| **L6** shim automático | Probe + filtro de FPs + normalización + liveness/reinstall: T65 (12 checks) |
| **L2** ejecución desde imagen | Mimikatz desde `msi.dll`: `MEM_IMAGE`, 0 regiones nuevas, **0 eventos TI**; efímero con pe-sieve: 0 patches; variante "sec": política del sistema, no firma |
| **L4** frames CET-safe | Walk 100 % con nombre (6/6) + Shadow Stack satisfecho; control negativo desde memoria anónima |

## 11. F15 — Medir el kernel: ETW-TI desde user-mode

Hasta aquí, "ETW-TI" había sido una caja negra heredada: se sabía (F9) que **no es habilitable desde user-mode** y estaba clasificado como techo. F15 lo demuestra medible. En dos pasos: un spike con herramienta ajena auditada, y un consumidor propio.

### 11.1 El spike: la técnica existe y funciona en esta build

El montaje: un **AutoLogger propio** (`mount_etwti.ps1`, reimplementación en el repo) — la clave `0MyThreatIntelTrace` (el "0" la ordena primero), provider `Microsoft-Windows-Threat-Intelligence` a nivel 4 con máscara completa de keywords, requiere reinicio— más un **consumidor de research de Prelude** (licencia propietaria: se usó **solo como herramienta**, auditado antes —origen verificado, código 100 % revisado, sin red ni persistencia, Defender limpio, SHA256 registrado— y **no se versionó ni derivó**).

Resultado en la build 26200: **técnica verificada** — **38 683 eventos en ~74 s** (5.24 MB), todos del GUID de Threat-Intelligence. Dos lecciones operativas: el runner subcontó en caliente (16 eventos: artefacto de lectura asíncrona, corregido con drenaje), y **la atribución era imposible** — el consumidor de research solo imprime el GUID, y el sistema emite ~500 eventos/s de fondo (JITs, Defender, COM, navegador). Sin atribución, no hay medición: había que construir el consumidor propio.

#### 11.1.1 El montaje por dentro (y por qué el "0" importa)

Merece la pena bajar un nivel, porque el montaje es la mitad del trabajo. Un **AutoLogger** es una sesión de traza que Windows arranca **en el boot**, antes de que ningún usuario haga nada — la forma de capturar eventos de kernel que no puedes habilitar en caliente sin PPL. El script propio crea la clave:

```text
HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\0MyThreatIntelTrace
  GUID del provider: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}  (Threat-Intelligence)
  nivel 4, MatchAnyKeyword 0x000005FFFFFFFFFF, Start = 1
```

El detalle del prefijo **"0"** no es cosmético: las sesiones se ordenan alfabéticamente y el truco conocido de los consumidores de SecurityTrace es que **tu sesión arranque la primera**, para que un consumidor pueda localizarla de forma determinista (de ahí también la heurística del `LoggerId` del consumidor propio). El montaje **requiere reinicio**; `unmount_etwti.ps1` y `cleanup_etwti.ps1` lo deshacen por completo. Y el spike usó un consumidor de investigación **auditado antes de ejecutarlo** (origen verificado, código revisado al 100 %, sin red, escaneo de Defender limpio, SHA256 registrado) que **no se versionó ni se derivó**: la técnica es pública (blog de Prelude / McGarr); el binario de terceros solo sirvió como vara de medir para validar el concepto. La fase 2 —el consumidor propio— es donde el proyecto pone su implementación: C + ASM propios, TDH propio y atribución propia.

### 11.2 El consumidor propio (C + ASM)

`tools/etw/kage_ti/` implementa todo lo necesario, sin dependencias propietarias:

- **Carga de propiedades** de la sesión desde el registro y **descubrimiento empírico del `LoggerId`**: itera `ControlTraceW(QUERY)` sobre ids hasta encontrar el que devuelve `ACCESS_DENIED` (la sesión PPL) — una suposición del entorno, documentada como tal.
- **Self-detour de `sechost!ControlTraceW`** (14 bytes: `jmp [rip+0]` + trampoline con los bytes originales): si la llamada no es una query, va al trampoline; si **es** una query, el consumidor **responde en user-mode** con las propiedades cacheadas y devuelve `ERROR_SUCCESS` — sin el chequeo PPL del kernel. El concepto es público (blog de McGarr); la implementación es propia; la atribución queda en el código.
- **TDH→NDJSON**: `OpenTraceW`/`ProcessTrace` en realtime y `TdhGetEventInformation` para volcar cada evento con `qpc/pid/tid/id/name` y todas las propiedades. Nada de "imprime el GUID": eventos parseados.
- **Filtro por PID vía pidfile**: el runner escribe el PID **al lanzar** cada proceso y el consumidor lo sondea cada 250 ms. Detalle clave: **los lotes del AutoLogger llegan ~1 s tarde**, así que filtrar por nombre a posteriori no encuentra al proceso (ya murió); el pidfile en caliente sí.

### 11.3 Las mediciones: el ciclo visto por el kernel

Con el consumidor propio y el ciclo `--full` ×3:

```text
6 eventos TI = EXACTAMENTE 2 por run
  vista A: ProtectionMask=0x20 (EXECUTE_READ)        ViewSize=0x153000 (~1.33 MB)
  vista B: ProtectionMask=0x80 (EXECUTE_WRITECOPY)   ViewSize=0x14F000 (~1.31 MB)
  CallingProcessId == TargetProcessId (self-map)
```

Tres lecturas de peso:

1. **El staging es la señal.** Las dos vistas del ciclo son las que mapea F11 (la de ejecución y la de escritura). El ledger las llamaba "0 protects invisibles"; para ETW-TI son **dos mapeos ejecutables con nombre, tamaño y protección**.
2. **Dato nuevo sobre la sección:** la vista de escritura aparece como **`EXECUTE_WRITECOPY`** — porque la sección se crea con protección máxima RWX. Es la confirmación desde el kernel del matiz que veníamos declarando.
3. **Cero eventos de alloc/protect del payload dentro de la ventana:** el tráfico S6 del ciclo **es exactamente el staging**. El resto del pipeline (escritura, RC4, sueño) no emite eventos TI medibles aquí.

Consecuencia metodológica: la latencia de lotes (~1 s) obliga a medir **por ventanas**, no por instantes, y a atribuir por PID en caliente.

### 11.4 Matriz v3: S6 deja de ser un techo ciego

La actualización de la matriz de señal (`matriz-m-v3.md`) añade la columna **TI** y reclasifica:

- **S6 (ETW-TI): techo ciego → señal medida por-operación.** Con las vistas ejecutables del staging identificadas, la mitigación pasa a ser ingeniería concreta (reducir el duty, mover la ejecución a imagen) en vez de "no se puede".
- **Sysmon, WHIDS y Defender siguen ciegos al núcleo de memoria**; el kernel, no.
- S7 (Kernel-Memory) queda en contadores (spike por-operación pendiente); S8 (callbacks de kernel) sigue inobservable — la vía es el driver propio **kagesense**, ya en el horizonte.

Y el cierre conceptual de F14+F15 cabe en una frase: **las técnicas de ejecución de esta fase se midieron contra el sensor que antes no se podía leer.** El stomp da 0 eventos; el staging da 2 por run; el sueño da 1 por despertar. A partir de aquí, "evadir" ya no es una opinión: es un presupuesto de eventos.

## 12. Revisiones del tramo y erratas propias

F14 pasó por **dos rondas de revisión completa con GLM 5.3** (una parcial y otra con 5 subagentes sobre el 100 % del código). Lo aplicado que más importa para este material: validación de blob antes de usar longitudes (over-read con blob corrupto), drenaje del thread pool con `WaitForThreadpoolWorkCallbacks` (la carrera que luego usó todo F14), init-once con CAS, colisión de hash SSN ruidosa (`KAGE_ERR_COLLISION`), espera `INFINITE` tras `TerminateThread` (UAF), rechazo explícito de `seg>0` en modos síncronos, sonda de alineación del IC (`rsp % 16 == 8`), retirada de la lectura `[r10-10h]` del callback de ejemplo, parcheo ETW por fases y honesto, y una limpieza de falsos PASS en la suite (`T38.18` tautológico reescrito, guards `P4.0/P5.0/P14.0`, helper de lanzamiento de hijos). Pendientes declarados: singletons no reentrantes del staging, spin de instrumentación, umbral ambiental de T62 y el `TerminateThread` del camino de timeout.

Y las **erratas doc-vs-código** que la revisión destapó en el material de estas fases (las publicamos porque son parte del método):

- `stomp.h` quedó describiendo la variante "sec" como `SEC_IMAGE` RWX cuando el código real usa RW con doble vista (el informe sí está correcto).
- **Los "protect RW" del stomp son en realidad RWX**: la ventana de escritura pide `PAGE_EXECUTE_READWRITE` sobre la `.text` (el coste en protects es el mismo y ETW-TI no lo reporta —medido—, pero un hook `S1` de `NtProtectVirtualMemory` ve una petición RWX sobre imagen; matiz relevante).
- La evidencia CLI del shim automático (L6) resultó ser un **fallo de apertura de fichero registrado con exit 0** (inconsistente con el código): la cobertura real del modo es **T65**, que sí está respaldado.
- `--stompeph` y `--full2` comparten manejador: el "stomp efímero" medido con pe-sieve corría la versión **pre-L4**; hoy ejecuta con frames CET-safe.
- **T69 depende de `pe_hello.exe`**, que no se provisiona en builds frescos: los 610/562 actuales no se reproducen en un clon limpio (~603/562, con el test saltando). Deuda de empaquetado documentada.
- Sin jitter, los despertares del sueño comparten `BaseAddress`/`TID` y periodo exacto (~1.007 s medido por el kernel): firma temporal que el CLI permite difuminar con jitter.
- La espera fija de 1.5 s antes del restore del efímero es empírica y frágil si el payload arranca más lento.
- El consumidor TI descubre su `LoggerId` por heurística ("primera query denegada"): razonado en el código, frágil fuera de este laboratorio.

## 13. Límites y techos tras F14/F15

| Límite / techo | Estado |
|---|---|
| **LSASS con `SeDebug`** | No medido (volcar credenciales del equipo). La firma conductual `OpenProcess(lsass, 0x1010/0x410)` desde imagen no firmada sigue siendo **techo conductual**; con VBS/Credential Guard en 26200 ni siquiera garantiza éxito |
| **S4 residual** | Frames L4 dan walk 100 % con nombre **solo si el destino vive en imagen**; desde región anónima, `frame[0]` sigue unbacked (control negativo de T63) |
| **S5 (IC del EDR)** | Ve todos los syscalls; el shim reduce fricción (fwd 54 575 / drops 0 en el escaneo), no ceguera — y la fusión kernel-vs-callback del techo de F10 sigue vigente |
| **S6 (ETW-TI)** | **Medido**, no eliminado: 2 map-evt/run en el staging, 0 en stomp, 1/despertar en el sueño. Ruido de fondo ~500 ev/s (hasta 2 200–4 000 en ventanas), lotes ~1 s tarde, sin stack del llamador en el NDJSON |
| **S7 / S8** | Kernel-Memory en contadores (spike por-operación pendiente); callbacks de kernel: inobservables hasta `kagesense` |
| **IBT** | No abordado explícitamente (se trabaja con SHSTK; los frames falsos nunca se ejecutan — no llevan `endbr64` — pero no hay prueba IBT dedicada) |
| **Caveats del "sec"** | Muerto en 26200 por política; la implementación latente deja copia en `%TEMP%` (borrada al liberar) y expondría una vista RW/RX de imagen no cargada por el LDR |
| **Residuos del stomp** | 2/4 protects visibles a hooks `S1`; ImageLoad de la candidata (EID 7); imagen modificada **mientras** corre (el efímero limpia solo en reposo); `ExitProcess` del PE mata al huésped |
| **Lo que F14 no resuelve** | Los internals del payload (los 4 patches del bypass de Donut — motivación de F16), el `conhost` hijo, AMSI/A7, la correlación S9 (las 2 reglas WHIDS siguen) y la firma de imagen del PE interno (`mscoree` sin atribuir) |

## 14. F16 (semilla): quitar a Donut de la ecuación

El árbitro externo dejó una conclusión incómoda y clara: **las señales residuales del stomp efímero eran de Donut, no del loader**. Así que la semilla de F16 es un **loader de PE propio**: `KageMapPe` — mapeo de cabeceras y secciones, **relocs DIR64**, imports por nombre, `RtlAddFunctionTable` (pdata para el unwind), y un detalle operativo fino: **interceptor de `ExitProcess` en la IAT** sustituido por `NtTerminateThread` (muere solo el hilo, no el host). Su motivación documental es el **RE del loader de Donut con Ghidra** (stub GET-BASE → instancia embebida → resolución por hash → `call rax`).

Estado actual (semilla, no fase cerrada): modo `--map <pe> [anon|image] [seg]`, **T69 7/7** con un PE de 140 KB ejecutado en ambos destinos (exit 7 interceptado), y **Mimikatz 1.35 MB en claro con REPL limpio** gracias a un neutralizador de `CommandLine` en el PEB (el CRT de ucrt lee el PEB directamente; con línea vacía caía al `ImagePathName`). La matriz final con pe-sieve queda así:

```text
PE-in-image con Mimikatz real : 1 sospechoso  (msi modificada, 46.183 patches, 0 IAT/hdr/implantados)
Donut + efimero               : 2 sospechosos (bypass ntdll + amsi)
```

La decisión por escenario queda medida: para defensas de "reposo/escáner", el efímero; para sensores de memoria, el PE-in-image. La integración en `full2` y un stub sin bypass cierran F16 — que aún no ha empezado como fase.

## 15. Cómo reproducirlo

Todo local. Requisitos: Windows 11 x64, Build Tools con `ml64`, `cdb` con símbolos, ETW-TI montado con reboot (para las capturas de kernel), y `pe-sieve` para el arbitraje externo.

```text
tools\build.cmd / tools\build_cet.cmd        :: builds duales
bin\Kagemusha.exe --sleepasync 3 300         :: L1: duty 0 %, 0 protects, 0 hilos
bin\Kagemusha.exe --full <sc> @clave.txt shim auto   :: L5+L6+staging+sueño
bin\Kagemusha.exe --stomp msi.dll mk.bin shim        :: L2: ejecucion desde imagen firmada
bin\Kagemusha.exe --stompeph msi.dll mk.bin shim 120 :: efimero + ventana de escaneo
bin\Kagemusha.exe --full2 msi.dll mk.bin shim        :: L2+L4+F10+restore (T68)
bin\Kagemusha.exe --map pe_hello.exe image           :: semilla F16 (loader propio)
bin\Kagemusha_tests.exe                              :: suite completa (610 stealth / 562 CET)
powershell -File tools\verify.ps1                    :: 0 instrucciones syscall propias

# ETW-TI (admin + reboot para el AutoLogger)
powershell -File tools\etw\mount_etwti.ps1
powershell -File tools\etw\run_ti_capture.ps1 -StompShim
powershell -File tools\etw\cleanup_etwti.ps1

# Arbitro externo (pe-sieve) durante la ventana de --stompeph
```

Evidencias: `docs\evidencias\e14_*.txt` y `e15_*.txt` (incluye `e15_ti_ciclo.ndjson` con los eventos parseados del ciclo); informes: `docs\research\experimento-e14-*.md`, `experimento-e15-etwti.md`, `matriz-m-v2.md`, `matriz-m-v3.md`; cierre de fase: `docs\fase14\README.md`.

## 16. Conclusiones

1. **El módulo prestado funciona y se midió hasta el fondo.** Mimikatz corriendo desde la `.text` de `msi.dll`: `MEM_IMAGE`, sin regiones propias nuevas, RIP verificado en el depurador, 2 protects de coste y **0 eventos ETW-TI del ciclo** entre 87 898 del sistema. La hipótesis "el staging era la señal de kernel" quedó confirmada: moviendo la ejecución a una imagen, esa señal desaparece.
2. **El árbitro externo cambió la conversación.** `pe-sieve` encontró 0 patches en `msi.dll` y 2 señales ajenas al loader (el bypass de Donut). Sin árbitro externo, el veredicto habría sido "limpio"; con él, es "limpio **menos** lo que trajo el paquete" — y eso define la fase siguiente.
3. **ETW-TI dejó de ser un techo ciego.** Con AutoLogger + consumidor propio (TDH, self-detour de `ControlTraceW`, atribución por PID), el plano S6 pasó a **señal medida por-operación**: 2 vistas/run del staging con tamaño y protección, 0 del stomp, 1 por despertar del sueño. La matriz v3 lo formaliza.
4. **La pila CET-safe es real.** Frames de módulos reales que nunca se retornan + `call` legítimo: walk 100 % con nombre y Shadow Stack satisfecho, donde el spoofing clásico rompía con `#CP`. Y con el control negativo bien claro: solo funciona si el destino vive en una imagen.
5. **Los techos que quedan no se maquillan:** LSASS (conducta), S4 desde memoria anónima, S5 con fusión de kernel, S7/S8 hasta `kagesense`. F14/F15 no los eliminan; los **reducen a una lista corta y medida** — que es exactamente el objetivo declarado del proyecto.

> Aprender a romper para poder defender.

## Referencias

- Código y documentación: `Kagemusha` — `src/core/stomp.c`, `src/core/staging.c`, `src/main.c` (`--sleepasync`, `--stomp`, `--stompeph`, `--full2`, `--map`), `src/asm/syscalls.asm` (frames L4), `tools/etw/kage_ti/` (consumidor propio), `tests/run_tests.c` (T60–T69).
- Informes: `docs/research/experimento-e14-*.md`, `experimento-e15-etwti.md`, `matriz-m-v2.md`, `matriz-m-v3.md`, `revision-f14-*.md`; cierre: `docs/fase14/README.md`.
- Microsoft Learn — *Threat-Intelligence ETW provider*, *Shadow Stack / CET*, *Thread Pool Timers*, *SEC_IMAGE / image integrity*.
- Técnica de montaje ETW-TI desde user-mode: blog de seguridad de Prelude / artículo de Connor McGarr (atribuido en el código); consumidor de research de `preludeorg` usado solo como herramienta auditada.
- **pe-sieve** (hasherezade) como árbitro externo de módulos implantados y patches.
- TheWover / homjxi0e — *Donut*; gentilkiwi — *Mimikatz*.
- Entradas relacionadas: [F10 — Contra-instrumentación](/blog/kagemusha-fase-10-contrainstrumentacion-callback.html), [F11–F13 — Del staging al full-stack](/blog/kagemusha-f11-f13-staging-correlacion-mimikatz-fullstack.html), [Metodología de verificación](/blog/kagemusha-metodologia-verificacion.html) y [Por qué la evasión es en capas](/blog/kagemusha-articulo-por-que-evasion-capas.html).