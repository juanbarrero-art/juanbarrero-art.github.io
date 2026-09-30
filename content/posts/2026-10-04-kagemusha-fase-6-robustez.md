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

- **Fase 7 (I+D propia):** ya hechos el ***ledger*** de syscalls y los **modos CLI**
  (`--dump`/`--trace`/`--json`); queda la extensión de debugger `!kage`. Ver la
  [entrada de la Fase 7 y baterías](/blog/kagemusha-fase-7-baterias-cet.html).
- **Fase 8 (visibilidad):** el informe publicable y —lo más interesante— el **análisis de
  detección**: qué *ve* realmente un EDR con el indirect puro (stack walk, telemetría, ETW). Sin
  esconder nada: midiendo.

## Cierre (por ahora)

Con M0–M6 (y ya las baterías T0–T24) verificados, **166 PASS / 0 FAIL** y **0 instrucciones `syscall`** en el módulo, la
tesis está confirmada **y es falsable**: cada afirmación tiene su oráculo y su transcript. Lo
que queda (el `!kage`, el análisis de detección) es donde el proyecto deja de ser "una
implementación más" y empieza a aportar **conocimiento medido**.

## Cómo simular un hook sin un EDR real

No hace falta un EDR para probar la resiliencia. En el propio laboratorio:

1. Localizamos el stub de `NtClose` en `ntdll`.
2. Con `VirtualProtect` lo hacemos escribible.
3. Escribimos un **prólogo de hook** (`E9 00 00 00 00`): un `jmp` relativo a "ninguna parte".
4. Restauramos la protección.

Como `ntdll` es una sección de memoria compartida con **Copy-On-Write**, escribir en el stub de
nuestro proceso crea una **copia privada**: no afectamos al resto del sistema, así que el
experimento es seguro. Después, `KageIsStubHooked` debe responder `TRUE`.

> Este es el mismo efecto que produce un EDR de user-mode, pero **bajo nuestro control** y
> reproducible. Nada de "magia": un `jmp` al inicio del stub.

---

## Por qué FreshyCalls es inmune (explicado)

La clave está en **qué lee** cada técnica:

- **Hell's Gate / Halo's Gate** leen los **bytes del stub** (`mov eax, SSN`). Si esos bytes están
  modificados por un hook, leen **basura** → SSN incorrecto → comportamiento errático.
- **FreshyCalls** lee el **orden de los exports por dirección virtual**. Esa información **no
  depende de los bytes del stub**: modificar el prólogo no cambia la dirección del export ni el
  orden.

Por eso, con el stub hookeado, FreshyCalls devuelve **el mismo SSN**. Y como el gadget se busca
**fuera** del stub hookeado (en el pool), la ejecución indirecta sigue funcionando: se salta al
`syscall;ret` limpio de `ntdll` y **nunca se ejecuta el `jmp` del hook**.

---

## Endurecer el parser PE

Un sistema que lee cabeceras PE (para encontrar exports) puede **reventar** con un PE malformado:
si `e_lfanew` (el offset que apunta a la cabecera NT) es enorme, leer "allí" provoca una
**lectura fuera de rango**. Por eso el parser:

- Rechaza `e_lfanew` fuera de `[0x40, 0x1000]` **antes** de tocar las cabeceras NT.
- Valida tamaños y límites antes de recorrer arrays.

El experimento de **fuzz** le da **9 PEs malformados** (con `e_lfanew` extremo) y comprueba que
el parser devuelve `NULL`/error **sin crashear**. Endurecer la entrada es tan importante como la
lógica principal.

---

## Concurrencia e idempotencia

Dos pruebas que suelen olvidarse:

- **Concurrencia:** 4 hilos × 1000 syscalls cada uno, sin fallos. Sirve para detectar condiciones
  de carrera en el uso de las tablas.
- **Init idempotente:** llamar a `KageInitialize()` 100 veces deja las tablas **estables** (mismos
  valores). Un init que "se pisa" a sí mismo sería un bug latente.

---

## El límite real: 488 de 490

El hallazgo más importante no es un éxito, sino un **límite documentado**. En la build de
referencia:

- **490** exports `Nt*`.
- **488** tienen el prólogo de stub de syscall (`4C 8B D1 B8`).
- **2** no lo tienen (`NtGetTickCount`, `NtQuerySystemTime` → `jmp Rtl*`).

FreshyCalls los **cuenta** al ordenar por VA. En esta build, el índice coincide con el SSN real
para **los 488 stubs** (0 discrepancias), incluido todo nuestro catálogo. Pero **es un límite a
vigilar**: si otra build cambia cuántos exports "no-stub" hay, el índice podría desplazarse.
Documentarlo es la diferencia entre "creo que es fiable" y "sé exactamente cuándo podría fallar".

---

## Qué NO concluir (rigor)

- **"Es indetectable".** No: se evitan hooks de user-mode, pero el kernel, ETW y los callbacks
  siguen ahí. La Fase 8 mide esa visibilidad.
- **"Funciona en cualquier Windows".** Los SSN se resuelven en runtime, pero hay que **probar en
  varias builds** (multi-build) para afirmarlo.
- **"Con 8 syscalls ya está todo probado".** El catálogo cubre aridades, pero cada build y cada
  configuración pueden exponer casos nuevos.

---

## Errores comunes (Fase 6)

- **Modificar el stub sin `VirtualProtect`**: la escritura falla (página de solo lectura).
- **Creer que el hook real es igual al simulado**: es una **emulación** controlada, útil y segura.
- **No manejar entradas adversas**: un PE malformado no debe tumbar el analizador.
- **Ignorar la concurrencia**: condiciones de carrera silenciosas son las más peligrosas.
- **Ocultar los límites**: un informe sin limitaciones no es un informe, es publicidad.

---

## 🧪 Experimenta tú — rompe tu propio sistema

*(Nivel 🔴, en VM. Con el proyecto compilado.)*

El experimento 5 de la batería es el más vistoso: **hookea** el stub de `NtClose` (en una copia
privada, segura) y luego llama a `NtClose_I`. Verás que **sigue funcionando**.

```text
bin\Kagemusha_tests.exe      :: la bateria T13-T17 incluye el hook simulado y su restauracion
```

Puedes seguir la idea en `cdb`:

```text
bp Kagemusha!KageIsStubHooked
g
; (al instalar el hook) -> TRUE
; (tras restaurar)       -> FALSE
```

**Qué deberías concluir:** aunque el stub esté modificado, FreshyCalls **no se inmuta** (no lo
lee) y el gadget se localiza **fuera** del stub hookeado. La técnica sobrevive a un hook de
user-mode.

> **Mini-reto:** instala un hook `FF 25` (jmp indirecto a un puntero) en lugar de `E9` y comprueba
> que `KageIsStubHooked` también lo detecta y que la ejecución indirecta sigue en pie (es el
> experimento de la batería extendida T19).

---

## Fondo: cómo hookea un EDR (y por qué nos afecta o no)

Existen varias formas de interceptar llamadas. Conocerlas explica por qué la técnica elegida
importa:

| Tipo de hook | Dónde | Efecto sobre nosotros |
| --- | --- | --- |
| **Inline (byte patching)** | Al inicio del stub `Nt*` (`E9`/`FF 25`) | **No** nos afecta: no ejecutamos el stub |
| **IAT hook** | En la *Import Address Table* del proceso | **No** nos afecta: no usamos la IAT |
| **Kernel callbacks** | En el kernel (procesos, hilos, imágenes) | **Sí** nos observa, pero no en user-mode |
| **ETW** | Trazas del kernel y componentes | **Sí**: es telemetría independiente |

La clave de la Fase 6 es la primera fila: si un EDR **reescribe el stub**, Hell's Gate / Halo's
Gate leerían bytes equivocados. Nosotros **no leemos el stub**, así que seguimos enteros.

> Un defensor serio no depende de **un** hook: combina callbacks y ETW. Por eso la serie **no**
> promete invisibilidad; mide la correlación.

---

## El hook no es "el enemigo": es un sensor

Conviene cambiar el marco mental. Un hook no es "algo malo que hay que evitar": es un **sensor**
que un defensor colocó. Los hooks de user-mode son **baratos y potentes**, pero **frágiles ante
código que no ejecuta el stub**. Y los sensores de kernel son **más robustos**, pero **más
costosos** y **más genéricos**.

Entender este intercambio es la mitad de la investigación defensiva. La serie **documenta ambos**
lados: cómo se evita el sensor de user-mode (Fase 6) y qué queda visible (Fase 8).

---

## Fondo: por qué el parser PE es un objetivo

Un analizador que confía ciegamente en un PE es un analizador **atacable**. Si un atacante puede
convencerte de que "el export A está en tal dirección", puede desviar tu resolución. Por eso el
endurecimiento **A1** valida las **RVAs del export directory contra `SizeOfImage`**: si una RVA
apunta fuera de la imagen, se rechaza.

El fuzz (9 PE malformados en T13–T17, y un **export directory malicioso** en el endurecimiento)
no busca "encontrar un bug por diversión": busca **garantizar** que el sistema no crashea ni se
desvía con basura. Un analizador fiable es aquel que **no se cree** la entrada.

---

## Los 12 experimentos, por grupos

Los experimentos no están sueltos; forman tres bloques con un propósito:

**Bloque 1 — Hook y resiliencia (1–7).** Instalar un `E9` en el stub, **detectarlo**, resolver el
SSN con el stub modificado, encontrar el gadget, **ejecutar** la syscall, **restaurar** y
**re-init** con el hook presente. Es el corazón de la fase: probar que un hook **no nos tumba**.

**Bloque 2 — Cobertura (8–9).** Resolver **todo** el catálogo `Nt*`: **488/488** stubs reales
coinciden con el SSN. Y detectar los **2** exports `Nt*` que **no** son stubs.

**Bloque 3 — Entradas adversas y concurrencia (10–12).** Fuzz del parser PE (9 malformados),
concurrencia (4 hilos × 1000 syscalls) e **init idempotente** (100 × `KageInitialize`).

---

## Detectar un hook: `E9` y `FF 25`

`KageIsStubHooked` reconoce los **prólogos** de hook habituales:

```text
E9 xx xx xx xx   ; jmp relativo a otra direccion
FF 25 ...        ; jmp qword ptr [rip+disp]  (indirecto)
```

El primer test usa `E9`; la **batería extendida (T19)** añade el caso **`FF 25`** (jmp indirecto),
comprobando que también se detecta y que FreshyCalls sigue inmune. Dos formas de hook, dos
pruebas: no basta con verificar la que te gusta.

---

## El fuzz del parser, con más veneno

La Fase 6 hace fuzz con **9 PE malformados** (`e_lfanew` extremo). El endurecimiento posterior
(**A1**) va más allá: un **export directory malicioso** (G8) que intenta que el parser lea una RVA
fuera de `SizeOfImage`. El parser **rechaza** y no crashea. Es la diferencia entre "aceptar
entrada" y "**validar** entrada".

---

## Endurecimiento (A1/A2) y tests nuevos (T0/T24)

La revisión de código añadió dos blindajes y dos tests:

- **A1 — parser PE:** valida las RVAs del export directory contra `SizeOfImage`.
- **A2 — wrappers:** guardia de init → `KAGE_STATUS_NOT_INITIALIZED` (nunca `jmp` a `NULL`).
- **T0:** usar el sistema **sin init**.
- **T24:** wrap-around del ledger, errores del resolver, parser malicioso, `KageSlotName` fuera
  de rango.

Con esto, la suite global subió a **166 PASS / 0 FAIL**. El patrón es claro: cada revisión
**añade pruebas** para que el fallo no pueda volver.

---

## Concurrencia e idempotencia, en corto

- **Concurrencia:** 4 hilos ejecutando syscalls a la vez → 0 fallos. Detecta condiciones de carrera
  en el uso de las tablas.
- **Idempotencia:** `KageInitialize()` 100 veces deja las tablas **estables**. Un init que "se pisa"
  a sí mismo sería un bug latente; aquí se descarta.

---

## Cómo se ve el hook en memoria (antes / después)

```text
ANTES (stub limpio):
  4C 8B D1        mov r10, rcx
  B8 0F 00 00 00  mov eax, 0Fh
  0F 05 C3        syscall ; ret

DESPUES (hook E9):
  E9 00 00 00 00  jmp +0            <-- el stub ya no ejecuta nada util
  00 00 00 00 00  (bytes desplazados)
  0F 05 C3        syscall ; ret     <-- "tapado" por el jmp
```

`KageIsStubHooked` mira el **primer byte**: si es `E9` o `FF`, hay hook. Y como nuestro sistema
**no ejecuta el stub** (salta al gadget), el `jmp` del hook nunca se corre.

---

## Por qué la defensa no depende de "un" hook

Si un defensa confiara **solo** en hooks de user-mode, cualquier técnica que no ejecute el stub la
sortearía. Por eso un EDR serio **combina** sensores:

- **Callbacks del kernel** (creación de proceso/hilo, carga de imagen): más robustos, más caros.
- **ETW:** telemetría independiente del user-mode.
- **Análisis de pila:** detectar *callers* no habituales para un `syscall`.

La Fase 6 demuestra **un** lado (el hook de user-mode no basta). La honestidad está en decir que
el otro lado existe y **medirlo** (Fase 8).

---

## Preguntas frecuentes (Fase 6)

**¿El hook simulado equivale a un EDR real?** No exactamente: es una **emulación** controlada y
segura del mismo efecto (un `jmp` al inicio del stub). Sirve para probar resiliencia sin un EDR.

**¿Por qué FreshyCalls es inmune aunque el stub esté hookeado?** Porque no lee los **bytes** del
stub: usa el **orden de exports por dirección**, que no cambia al parchear el prólogo.

**¿Qué pasa si hookean el gadget, no el stub?** El gadget se busca/valida en el pool; si un
candidato estuviera corrupto, se descarta (validación de bytes + rango). El diseño contempla
"gadget re-escrito" como riesgo a vigilar.

**¿Por qué importa el fuzz del parser?** Porque un analizador que confía en un PE malformado es
atacable. Validar `e_lfanew`/RVAs es tan importante como la lógica principal.

---

## Matriz de robustez (amenaza → prueba → resultado)

| Amenaza | Prueba | Resultado |
| --- | --- | --- |
| Hook inline `E9` | Instalar + ejecutar | ✅ sigue funcionando |
| Hook indirecto `FF 25` | T19 | ✅ detectado, FreshyCalls inmune |
| Stub de la propia función hookeado | Batería T20 (los 8) | ✅ auto-hospedaje |
| PE malformado | Fuzz (9 + export directory malicioso) | ✅ sin crash |
| Uso sin init | T0 | ✅ `KAGE_STATUS_NOT_INITIALIZED` |
| Concurrencia | 4 hilos × 1000 | ✅ 0 fallos |
| Re-init en uso | 100 × init | ✅ tablas estables |
| Exports `Nt*` que no son stubs | Cobertura total | ✅ 488/490 detectados |

Una matriz así es el **resumen ejecutivo** de la fase: cada fila, una amenaza; cada ✅, una prueba.

---

## Lecciones para defensores

- **No te fíes de un solo sensor.** El hook de user-mode es útil pero evitable; combina callbacks
  de kernel y ETW.
- **La correlación gana.** Una señal aislada (un `syscall` en `ntdll` con *caller* raro) no basta;
  el valor está en **cruzar** señales (pila + comportamiento + binario).
- **Los hooks son frágiles por diseño** ante código que no ejecuta el stub; saberlo te permite
  **priorizar** qué proteger con sensores más robustos.
- **Mide tu detección.** Un EDR no es "mejor" por tener más hooks, sino por **detectar** más con
  menos falsos positivos.

---

## Sesión anotada: instalar y quitar un hook

El experimento, paso a paso (conceptualmente):

```text
1. localizar el stub:        stub = export "NtClose" de ntdll
2. hacerlo escribible:       VirtualProtect(stub, 5, RW)
3. escribir el hook:         memcpy(stub, "\xE9\x00\x00\x00\x00", 5)
4. comprobar el sensor:      KageIsStubHooked(stub) == TRUE
5. ejecutar el indirecto:    NtClose_I(handle_valido) -> STATUS_SUCCESS
6. restaurar los bytes:      memcpy(stub, "\x4C\x8B\xD1\xB8...", 5)
7. comprobar de nuevo:       KageIsStubHooked(stub) == FALSE
```

Lo importante del experimento **no** es el resultado de un `NtClose` concreto: es que, entre los
pasos 4 y 5, el stub está **roto** y el sistema **funciona igual**. Eso prueba, de la forma más
directa posible, que la ejecución indirecta **no depende** del stub.

> Y el auto-hospedaje aparece si hookeas **todos** los stubs: `VirtualProtect` (que usa
> `NtProtectVirtualMemory`) se cuelga, así que el propio sistema se usa para manipular `ntdll`.

---

## Resumen ejecutivo de la Fase 6

- **Qué logramos:** demostrar que el sistema **resiste hooks** (inline `E9` y `FF 25`) y
  **entradas adversas**.
- **Cómo se prueba:** 12 experimentos (hook/resiliencia, cobertura total, fuzz, concurrencia) +
  `T0`/`T24` del endurecimiento.
- **Hallazgo:** de **490** exports `Nt*`, **488** son stubs reales y coinciden al 100%; 2 no lo son.
- **Qué falta:** herramientas (ledger/CLI, Fase 7) y análisis de detección (Fase 8).

## Checklist de robustez

- [ ] FreshyCalls **no lee** bytes del stub (inmune a hooks).
- [ ] Gadget siempre **validado** (bytes + rango + no-hook).
- [ ] Hook `E9` **y** `FF 25` detectados.
- [ ] Ejecución indirecta funciona con el stub **hookeado**.
- [ ] Parser PE **rechaza** entradas malformadas (sin crash).
- [ ] `init` idempotente y uso sin init **seguro** (`KAGE_STATUS_NOT_INITIALIZED`).
- [ ] Concurrencia sin fallos (4 hilos).

Si todas las casillas están marcadas, tienes un sistema **robusto por diseño**, no por suerte.

---

## Cómo verificar la Fase 6 en 5 minutos

```text
bin\Kagemusha_tests.exe     :: T13-T17 (hook simulado, cobertura, fuzz, concurrencia)
bin\Kagemusha.exe --trace   :: el ledger confirma que las llamadas llegan al kernel
```

Y, si quieres el momento "wow": observa en `cdb` el `KageIsStubHooked` pasar de `FALSE` a `TRUE`
al instalar el hook, y a `FALSE` al restaurar —mientras `NtClose_I` sigue devolviendo
`STATUS_SUCCESS` en medio del hook.

---

## Glosario de la Fase 6

| Término | Significado en esta fase |
| --- | --- |
| **Hook** | Desvío colocado en el código para observar/alterar llamadas |
| **Inline hook** | Parchear el inicio del stub (`E9`/`FF 25`) |
| **IAT hook** | Parchear la *Import Address Table* del proceso |
| **COW (Copy-On-Write)** | Al escribir en una página compartida, el SO crea una copia privada |
| **Callback de kernel** | Notificación del kernel a drivers (procesos, hilos, imágenes) |
| **ETW** | Sistema de trazas del sistema (telemetría independiente) |
| **Fuzz** | Alimentar con entradas adversas para buscar crashes |
| **Idempotente** | Que repetir una operación no cambie el resultado |
| **Auto-hospedaje** | Usar el propio sistema para operar sobre `ntdll` |

Con esto, la Fase 6 queda como el **escudo**: no promete invisibilidad, promete que el sistema
**no se rompe** cuando el mundo se pone hostil. Y lo demuestra con pruebas, no con titulares.

---

## Para profundizar en el repositorio

- `src/resolver/gadget.c`: `KageIsStubHooked` y la validación del gadget.
- `tests/run_tests.c` (T13–T17, T24): los 12 experimentos + endurecimiento.
- `docs/research/experimentos-fase6.md` y `experimentos-extendidos.md` (hook `FF 25`).
- `docs/evidencias/m5.txt`: cobertura **488/488**.
- `bin\Kagemusha_tests.exe`: la suite completa.

## Cierre de la fase

La Fase 6 no busca "ganar" a un EDR: busca **saber dónde estás parado**. Y lo hace **midiendo**, no
prometiendo: el sistema resiste hooks de user-mode (demostrado, con `E9` y `FF 25`), pero sigue
siendo visible al kernel (declarado, sin esconderlo). Esa honestidad es lo que convierte el
resultado en **investigación** y no en publicidad. El siguiente paso —herramientas y análisis de
detección— se apoya justo en esta base: ya sabes qué **no** te tumba y qué **sí** te ve.

---

## Nota final

La robustez no es un **estado**, es un **proceso**: cada revisión añadió pruebas (T0, T24, el
export directory malicioso `G8`) para que un fallo **no pudiera volver**. Un sistema "robusto" que
no se vuelve a probar cada vez no es robusto: tiene suerte. Y la suerte, en seguridad, no es una
estrategia. Probar, medir y documentar: ese es el trabajo. Y ese —**no romperse** cuando el mundo
se pone hostil— es el único resultado que un investigador serio puede prometer sin mentir.

---

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
7. [Fase 7 y baterías (T19–T22): ledger, CLI y CET](/blog/kagemusha-fase-7-baterias-cet.html)
