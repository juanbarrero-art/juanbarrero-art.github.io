---
title: "Kagemusha — Fase 7 y baterías de verificación (T19–T22): ledger, CLI y CET"
date: 2026-10-05
tags: windows internals, red team, syscalls, investigacion, cet
serie: Kagemusha
summary: El proyecto pasa a modo industrial. Baterías extendida, pesada y global (pruebas diferenciales contra ntdll, soak de 500k llamadas, multi-proceso), ledger de syscalls y CLI, y la prueba clave de compatibilidad con CET / Shadow Stack.
---

# Kagemusha — Fase 7 y baterías de verificación (T19–T22)

El proyecto dejó de ser "una implementación que funciona" para volverse un **sistema medido a
escala**. Esta entrada documenta el salto: **cuatro baterías nuevas de verificación** (T19–T22),
el **ledger de syscalls** y los **modos CLI** de la Fase 7, y —probablemente lo más interesante—
la demostración de que el trampolín indirecto es **compatible con CET / Shadow Stack**.

> Resultado de la build de referencia: **166 PASS / 0 FAIL** y **0 instrucciones `syscall`** en
> el módulo. Y todo, como siempre, verificado con oráculos independientes.

![Diagrama: baterias de verificacion T19-T23](../assets/diag-batteries.svg)

---

## T19 — Batería extendida: la prueba diferencial

La forma **más fuerte** de verificar una indirect syscall no es "no crashea", sino **comparar**
su resultado con el de la función **nativa de `ntdll`**. Eso es una **prueba diferencial**:

```text
NtQueryInformationProcess_I(args)   ==   ntdll!NtQueryInformationProcess(args)
NtQuerySystemInformation_I(args)    ==   ntdll!NtQuerySystemInformation(args)
NtClose_I(handle)                   ==   ntdll!NtClose(handle)
```

Mismos argumentos, mismo `NTSTATUS`, mismos efectos en los argumentos de salida. Si el indirecto
fuera "casi correcto", aquí se vería. La batería T19 incluye también:

- **Preservación de argumentos:** `PebBaseAddress` coincide con el valor de `ntdll` **y** con
  `gs:[0x60]` (el PEB real) → prueba de que el 3.er argumento llega bien.
- **Argumento de salida:** `NtProtectVirtualMemory` devuelve `OldProt == PAGE_READWRITE` → el
  5.º argumento (puntero, en la pila) se escribe correctamente.
- **Sin fugas de handles** (1000 ciclos open/close), **estrés** (20 000 `NtYieldExecution_I`),
  **hook `FF 25`** detectado con FreshyCalls inmune, y **fuzz de 300 PE**.

> La prueba diferencial es la que convierte "creo que es correcto" en "es **idéntico** a la API
> real". Es el patrón metodológico de todo el proyecto.

---

## T20 — Batería pesada: volumen, estrés y auto-hospedaje

Aquí llevamos el sistema al límite:

| Prueba | Magnitud |
| --- | --- |
| Soak de syscalls | **500 000** `NtYieldExecution_I` |
| Catálogo completo en | **4 hilos** |
| Close sobre objetos | evento, mutex, archivo, semáforo |
| Handles sin fuga | 200 open/close |
| Rendimiento | ~0.08 µs/llamada |
| PE **sintético** | se construye un PE mínimo y el parser lo resuelve |

### El hallazgo que vale oro: auto-hospedaje

El experimento más revelador **hookea los 8 stubs del catálogo** para probar la resiliencia.
Al hacerlo, aparece un problema **elegante**:

> `VirtualProtect()` de la API de Windows **se cuelga**, porque internamente usa
> `NtProtectVirtualMemory`, que es **uno de los stubs que acabamos de hookear**.

La solución es de esas que dan sentido a todo el proyecto: para **instalar y restaurar** los
hooks, el sistema usa **su propio `NtProtectVirtualMemory_I`**, que ejecuta por el gadget
`syscall;ret` y por tanto **no depende** del stub hookeado. Es decir, el sistema **se usa a sí
mismo** para operar sobre `ntdll` — un caso práctico de **auto-hospedaje** (*self-hosting*).

---

## T21 — Batería global: multi-proceso, otros módulos y rendimiento

Salimos del proceso y de `ntdll`:

- **Multi-proceso:** 4 procesos `Kagemusha.exe` independientes ejecutan el sistema completo →
  confirma que no hay estado global compartido oculto.
- **Parser cross-module:** el mismo parser resuelve exports en **kernel32** y **kernelbase**,
  comparando con `GetProcAddress`. Hallazgo: **kernel32 exporta un `Nt*`** que **no** es un stub
  de syscall (los stubs viven en `ntdll`); el parser genérico los distingue.
- **Anti-hook sobre toda la tabla:** se valida que **484/484** stubs reales (baseline) no están
  hookeados.
- **Rendimiento:** 200 000 llamadas → indirecto **0.014 s** vs nativo **0.013 s**. Prácticamente
  idénticos, como es de esperar: al final, el kernel ejecuta el mismo `syscall;ret`.

---

## T22 — CET / Shadow Stack: ¿rompe el trampolín las mitigaciones?

Esta es, para mí, la prueba más interesante del lote. **CET** (Control-flow Enforcement
Technology) incluye el **Shadow Stack**: una pila paralela, protegida por hardware, que guarda
las direcciones de retorno. Su objetivo es **impedir que un `ret` vuelva a donde no debe**
(una técnica clásica de explotación: *ROP*).

La pregunta era directa: **¿nuestro trampolín (`jmp` a un gadget con `ret`) rompe el shadow
stack?** La respuesta, medida:

```text
wrapper C  --call-->  stub ASM  --jmp-->  gadget ntdll (syscall; ret)  --ret-->  wrapper
                      (no push)            (consume la entrada)
```

- El `call` del wrapper empuja **una** entrada al shadow stack.
- El stub hace `jmp` (*tail call*): **no empuja nada**.
- El `ret` del gadget **consume exactamente esa entrada** → coinciden.

Resultado: el shadow stack **no se desalinea**, así que la técnica es **CET-safe por diseño**.
Y se probó en vivo: el proceso corría con `EnableUserShadowStack = 1` y **1000 syscalls
indirectos funcionaron**; además el binario se marcó `/CETCOMPAT`.

> Nota honesta: el modo `STRICT_MODE` no se pudo activar en este entorno (el SO rechaza la
> creación con `ERROR_INVALID_PARAMETER`); se documenta como **límite del entorno**, no del
> sistema. Igual que siempre: se mide y se declara.

![Diagrama: CET-safe por diseno](../assets/diag-cet.svg)

---

## Fase 7 — Ledger de syscalls y CLI (¡en curso, ya utilizable!)

La Fase 7 añade **herramientas de investigación**:

### Ledger de syscalls (E1)

`src/core/ledger.c` implementa un **ring buffer (256)** donde cada entrada registra: `slot`, `SSN`,
`gadget`, `NTSTATUS` y timestamp. Está **deshabilitado por defecto** (coste mínimo) y es
**thread-safe** (operaciones atómicas con interlocked). Es la "caja negra" del sistema.

### Modos CLI (I2)

`Kagemusha.exe` ahora tiene modos de línea de comandos:

```text
--dump   → tabla slot / syscall / SSN / gadget
--trace  → ejecuta llamadas y vuelca el ledger
--json   → la tabla en JSON
(sin args) → selftest M0-M5
```

Ejemplo de `--trace`:

```text
[INF] [0] NtClose                  SSN=0x00F gadget=00007FFC48540FA2 status=0xC0000008
[INF] [1] NtQuerySystemInformation SSN=0x036 gadget=00007FFC48541482 status=0x00000000
[INF] [2] NtQueryInformationProcess SSN=0x019 gadget=00007FFC485410E2 status=0x00000000
```

**Pendiente:** la extensión de debugger **`!kage`** (I1) para volcar tabla y ledger desde `cdb`.

---

## Endurecimiento tras una revisión de código

Una revisión interna añadió pruebas y blindó dos puntos débiles:

- **A1 — parser PE:** ahora se validan las **RVAs del *export directory* contra `SizeOfImage`**
  (evita lecturas fuera de rango con un PE malformado) y se añadió **fuzz con un export directory
  malicioso** (G8).
- **A2 — wrappers:** **guardia de inicialización**: si no se llamó a `KageInitialize`, el wrapper
  devuelve `KAGE_STATUS_NOT_INITIALIZED` y **nunca** hace `jmp` a `NULL`.
- **Tests nuevos:** **T0** (uso sin init) y **T24** (wrap-around del ledger, errores del resolver,
  parser malicioso, `KageSlotName` fuera de rango).

Este endurecimiento subió la suite a **166 PASS / 0 FAIL**. Es el patrón de la serie: cada
revisión no solo arregla, **añade pruebas que impiden que el fallo vuelva**.

---

## Resultados consolidados

| Métrica | Valor |
| --- | --- |
| Suite completa | **166 PASS / 0 FAIL** |
| Instrucciones `syscall` en el módulo | **0** |
| SSN coincidentes con el stub real | **488/488** |
| Stubs baseline hookeados | **484/484** limpios (o 0 hookeados) |
| Rendimiento (200k) | indirecto ≈ nativo |
| CET / Shadow Stack | **compatible** |

## Qué aprendimos

- **La prueba diferencial es el estándar de oro.** Comparar con la función nativa, mismos args.
- **El auto-hospedaje emerge solo.** Hookear todo reveló que el sistema puede operar sobre
  `ntdll` usando su propio indirecto.
- **Multi-proceso y rendimiento importan.** Un sistema sin estado oculto y sin penalización de
  velocidad es un sistema usable.
- **CET no es un enemigo.** El `jmp` (*tail call*) es, además de correcto, **seguro**.
- **Documentar límites es parte del resultado.** `STRICT_MODE` no aplica aquí; se dice.

## Cómo sigue la serie

1. [Guía de syscalls](/blog/guia-syscalls-windows.html)
2. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html)
3. [Fases 0 a 3: del toolchain al gadget](/blog/kagemusha-fases-0-3.html)
4. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html)
5. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html)
6. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html)
7. **Fase 7 y baterías (T19–T22): ledger, CLI y CET** (esta entrada)

---

## Bibliografía y referencias

- Microsoft Learn — *Control-flow Enforcement Technology (CET)* y *Shadow Stack*.
- Microsoft Learn — *Process mitigation policies* (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`).
- Russinovich, Solomon, Ionescu — *Windows Internals, 7.ª ed.*.
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`); jthuraisamy — *SysWhispers*.
- Fuentes primarias: `docs/research/experimentos-extendidos.md`, `experimentos-pesados.md`,
  `experimentos-globales.md`, `experimento-cet.md`; `src/core/ledger.c`.

> Aprender a romper para poder defender.
