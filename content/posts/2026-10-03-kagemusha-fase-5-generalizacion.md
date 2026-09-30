---
title: "Kagemusha — Fase 5: generalización y aridad"
date: 2026-10-03
tags: windows internals, red team, syscalls, investigacion
serie: Kagemusha
summary: Un único template ASM (macro KAGE_STUB) que sirve para un catálogo de 8 syscalls de distinta aridad. Por qué el jmp final hace que la misma plantilla valga para 0 o 6 argumentos, y 15 experimentos que lo demuestran.
---

# Kagemusha — Fase 5: generalización y aridad

En la [Fase 4](/blog/kagemusha-fase-4-ejecucion-indirecta.html) hicimos **una** syscall
indirecta (`NtClose`). Pero un sistema con una sola syscall no sirve para nada. La Fase 5
responde a la pregunta incómoda: **¿la técnica escala?** Y añade un segundo reto: la
**aridad** (el número de argumentos), porque no es lo mismo una función sin argumentos que una
con seis.

## El objetivo

Ejecutar un **catálogo de 8 syscalls** con **un único template ASM**. Es decir: en vez de
escribir a mano cada stub, definir **una macro** y que cada syscall del catálogo se convierta
en un `PROC` a partir de la misma plantilla. Añadir una función nueva debería ser **una línea**.

## La implementación

### La macro `KAGE_STUB`

```asm
; Un unico template fuente, instanciado por cada slot del catalogo
KAGE_STUB MACRO name, slot
name PROC
    mov  r10, rcx
    mov  eax, DWORD PTR [g_SsnTable + slot*4]     ; SSN de este slot
    jmp  QWORD PTR [g_GadgetTable + slot*8]        ; gadget de este slot
name ENDP
ENDM
```

Cada syscall del catálogo genera un `PROC` que **solo cambia el `slot`** (el desplazamiento a
las tablas). El patrón es idéntico; lo que varía es de dónde lee el SSN y el gadget.

### El catálogo (8 syscalls)

Elegidas para cubrir **distintas aridades** y casos interesantes:

| Slot | Syscall | Aridad | Nota |
| --- | --- | --- | --- |
| 0 | `NtClose` | 1 | la de la Fase 4 |
| 1 | `NtQuerySystemInformation` | 4 | consulta de sistema |
| 2 | `NtQueryInformationProcess` | 5 | **arg 5 en la pila** |
| 3 | `NtAllocateVirtualMemory` | 6 | **args en la pila** |
| 4 | `NtFreeVirtualMemory` | 4 | round-trip con 3 |
| 5 | `NtProtectVirtualMemory` | 5 | round-trip con 3/4 |
| 6 | `NtQuerySystemTime` | 1 | export especial (ver hallazgo) |
| 7 | `NtYieldExecution` | 0 | **sin argumentos** |

### Los wrappers y las tablas

`src/core/core.c` define el catálogo (**el orden define los slots**) e `KageInitialize`
transaccional rellena `g_SsnTable` y `g_GadgetTable`. `src/wrappers/wrappers.c` expone 8
wrappers tipados: `NtClose_I`, `NtQuerySystemInformation_I`, … con el sufijo `_I`
(*indirect*) para no colisionar con los prototipos de `ntdll`.

## El corazón de la Fase 5: la aridad

![Diagrama: aridad y el jmp tail-call](../assets/diag-aridad.svg)

Aquí está la razón por la que un **solo** template sirve para cualquier número de argumentos.

En x64 Windows, los primeros **4 argumentos** van en registros (`RCX`, `RDX`, `R8`, `R9`), pero
del **5.º en adelante viajan en la pila del llamador**. Un trampolín "genérico" que recopilara y
reubicara esos argumentos sería frágil. En cambio, nuestro stub termina en **`jmp`** (un *tail
call*): **no toca la pila** y **preserva la dirección de retorno**.

Consecuencia: cuando el gadget de `ntdll` hace `ret`, la pila sigue **exactamente** como la
dejó el wrapper. Por tanto, los argumentos 5+ que viajen en la pila **llegan intactos al
kernel**, sin que el stub tenga que saber cuántos son.

> Esto es exactamente el patrón que usan las librerías de referencia (SysWhispers) y es la
> solución **mínima correcta**: no hay que adaptar el stub a la aridad.

## Pruebas y experimentos

El test **T12** ejecuta las 8 syscalls y valida los `NTSTATUS` (incluyendo casos negativos).
Pero para no quedarnos cortos, añadimos **15 experimentos dedicados** (T18). Algunos:

- Resolución del catálogo e igualdad de las 8 entradas de `g_SsnTable` con el resolver.
- El bloque ASM contiene **≥ 8 stubs**.
- **Aridad 0** (`NtYieldExecution`), **1** (`NtClose`), **4**, **5** y **6** — cada una ejecutada.
- **Round-trip** `NtProtectVirtualMemory` + `NtFreeVirtualMemory` sobre memoria real.
- Caso negativo: clase de información inválida → `STATUS_INVALID_INFO_CLASS`.

Los 15 en verde. La **aridad 5** (`NtQueryInformationProcess`) y la **6**
(`NtAllocateVirtualMemory`) confirman que los argumentos en la pila llegan bien.

## Hallazgo: un slot del catálogo no es un stub de syscall

Aquí salió algo interesante. `NtQuerySystemTime` **no** se exporta como un stub de syscall.
En su lugar es un `jmp` a otra función de `ntdll`:

```text
NtQuerySystemTime:  jmp ntdll!RtlQuerySystemTime   ; implementado en user-mode
NtGetTickCount:     jmp ...                        ; tampoco es syscall
```

Es decir: no tiene el prólogo `4C 8B D1 B8` de los stubs reales. Entonces, ¿FreshyCalls
falla? **No.** FreshyCalls lo **cuenta** igual (por su posición en el orden de exports) y le
asigna un SSN; y **la ejecución indirecta funciona**: el experimento 15 lee el tiempo dos
veces y comprueba que es **válido y monótono creciente**.

| Métrica | Resultado |
| --- | --- |
| SSN del catálogo vs stub real | **7/8** (los que *son* stubs) |
| Los 7 stubs coinciden al 100% | ✅ |
| `NtQuerySystemTime` (no-stub) ejecuta correctamente | ✅ |

> Lección: no todos los exports `Nt*` son stubs de syscall. FreshyCalls los tolera, pero hay
> que **documentarlo** (en la Fase 6 se cuantifica a nivel de todo `ntdll`).

## Evidencia (cdb)

```text
u Kagemusha!KageStubStart L6          ; mismo patron, distinto offset de tabla por slot
  mov r10,rcx ; mov eax,[g_SsnTable+0x0] ; jmp [g_GadgetTable+0x0]
  mov r10,rcx ; mov eax,[g_SsnTable+0x4] ; jmp [g_GadgetTable+0x8]

bp Kagemusha!NtAllocateVirtualMemory_I ; g     (syscall de 6 argumentos)
? poi(Kagemusha!g_GadgetTable+18) = 00007ffc`485410c2
eax=18  rip=00007ffc485410c2                   ; SSN correcto; RIP dentro de ntdll
```

### Nota de seguridad (para scripts de cdb)

`NtClose(handle inválido)` genera una **excepción first-chance** `c0000008` que `ntdll` maneja
internamente. Los scripts de `cdb` deben **ignorarla** con `sxi c0000008`, o el script se
detiene. Lo dejamos documentado para el futuro.

## Qué aprendimos

- **Un template, muchas funciones.** La macro elimina la repetición y garantiza consistencia.
- **El `jmp` es la clave de la aridad.** No hay que adaptar el stub a 0, 4 o 6 argumentos.
- **No todos los `Nt*` son syscalls.** Los `jmp Rtl*` existen y hay que tratarlos con cuidado.
- **Probar la aridad importa.** Una técnica que "funciona" con 1 argumento puede fallar con 6
  si se equivoca el manejo de la pila.

Con 8 syscalls, distintas aridades y 15 experimentos en verde, el sistema ya no es una prueba
de concepto: es un **catálogo**. El siguiente reto es la **robustez frente a hooks**: qué pasa
si un EDR modifica un stub. Eso es la Fase 6.

## Cómo sigue la serie

1. [Guía de syscalls](/blog/guia-syscalls-windows.html)
2. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html)
3. [Fases 0 a 3: del toolchain al gadget](/blog/kagemusha-fases-0-3.html)
4. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html)
5. **Fase 5: generalización y aridad** (esta entrada)
6. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html)
7. [Fase 7 y baterías (T19–T22): ledger, CLI y CET](/blog/kagemusha-fase-7-baterias-cet.html)

## El catálogo: por qué esas 8

Elegimos las 8 syscalls para que el catálogo **ejercite todos los casos** que pueden romper un
sistema de trampolines:

- **Aridad 0** (`NtYieldExecution`): sin argumentos. Si algo fallara con la pila, aquí quizá no
  se note; sirve de control.
- **Aridad 1** (`NtClose`): el caso "fácil", ya probado en la Fase 4.
- **Aridad 4** (`NtQuerySystemInformation`, `NtFreeVirtualMemory`): el límite de los registros.
- **Aridad 5** (`NtQueryInformationProcess`, `NtProtectVirtualMemory`): **el 5.º argumento ya va
  en la pila**; aquí se prueba que el `jmp` lo deja intacto.
- **Aridad 6** (`NtAllocateVirtualMemory`): **el 6.º también en la pila**.
- **Caso especial** (`NtQuerySystemTime`): un export `Nt*` que **no es** un stub de syscall.

Además, `NtProtectVirtualMemory` + `NtFreeVirtualMemory` forman un **round-trip** natural:
reservar/proteger y luego liberar memoria real, comprobando que el efecto llega al kernel.

---

## El contrato de la macro

```asm
KAGE_STUB MACRO name, slot
name PROC
    mov  r10, rcx
    mov  eax, DWORD PTR [g_SsnTable + slot*4]
    jmp  QWORD PTR [g_GadgetTable + slot*8]
name ENDP
ENDM
```

El contrato es estricto y simple:

- **`name`** genera el símbolo del `PROC` (p. ej. `NtAllocateVirtualMemory`).
- **`slot`** fija el desplazamiento en las **dos** tablas (SSN y gadget). El mismo slot debe
  alinear ambas: `g_SsnTable + slot*4` (WORD) y `g_GadgetTable + slot*8` (QLWORD).
- El ASM **no** conoce el SSN ni el gadget: los **lee** de las tablas. Por eso añadir una syscall
  es "una línea en el registro" y **no** tocar el ASM a mano.

> Esta es la diferencia entre 8 stubs copiados y un **sistema**: el registro es la fuente única,
> la macro es el molde, y las tablas son el estado en runtime.

---

## Los 15 experimentos, en detalle

Los 15 experimentos de la Fase 5 no son "pruebas de humo"; cada uno ataca una suposición:

1. `KageInitialize()` resuelve el catálogo entero (init transaccional).
2. Las **8 entradas** de `g_SsnTable` quedan pobladas (no vacías).
3. Los **8 gadgets** son `0F 05 C3` (validados).
4. `g_SsnTable[slot 0]` coincide con el resolver (consistencia interna).
5. Las 8 entradas coinciden con el resolver (consistencia global).
6. SSN == SSN del stub real **por slot con stub real** (oráculo externo; 7/8 por el hallazgo).
7. El bloque ASM contiene **≥ 8 stubs** (la macro generó lo esperado).
8. **Aridad 0** — `NtYieldExecution`.
9. **Aridad 1** — `NtClose`.
10. **Aridad 4** — `NtQuerySystemInformation`.
11. **Aridad 5** — `NtQueryInformationProcess` (arg en pila).
12. **Aridad 6** — `NtAllocateVirtualMemory` (args en pila).
13. **Round-trip** `protect` + `free` sobre memoria real.
14. Caso **negativo**: clase inválida → `STATUS_INVALID_INFO_CLASS`.
15. `NtQuerySystemTime` **monótono creciente** (dos lecturas coherentes).

La combinación de **positivos**, **negativos**, **aridades extremas** y **oráculos** es lo que
convierte "funciona" en "está verificado".

---

## Errores comunes (Fase 5)

- **Desalinear slot y tabla**: un `slot*4` vs `slot*8` mal puesto lee basura como SSN/gadget.
- **Asumir que todos los `Nt*` son stubs**: `NtQuerySystemTime` te lo desmiente.
- **Probar solo aridad 1**: el bug de la pila aparece con 5+ argumentos.
- **No incluir casos negativos**: sin un "debe fallar", no sabes si valida o solo "no crashea".

---

## 🧪 Experimenta tú — mira el catálogo

*(Nivel 🟡. Con el proyecto compilado.)*

Ejecuta la suite y observa cómo pasan los 15 experimentos del catálogo:

```text
bin\Kagemusha_tests.exe
```

Y, con la Fase 7 ya implementada, puedes **ver la tabla** sin debugger:

```text
bin\Kagemusha.exe --dump
```

**Qué deberías ver** (resumido):

```text
[0] NtClose                    SSN=0x00F gadget=00007FFC48540FA2
[1] NtQuerySystemInformation   SSN=0x036 gadget=00007FFC48541482
[3] NtAllocateVirtualMemory    SSN=0x018 gadget=00007FFC485410C2
...
```

Esa tabla es el **estado en runtime** de todo el sistema: el SSN que resolvió FreshyCalls y el
gadget que se usará para cada función. Añadir una syscall nueva = una línea en el registro y
re-ejecutar.

> **Mini-reto:** compara dos builds distintas (o dos máquinas) y observa que los **SSN cambian**
> pero el mecanismo no. Esa es la razón de resolverlo en runtime.

---

## El día que un `Nt*` me tomó el pelo

Cuando amplié el catálogo, uno de los 8 fallaba el experimento 6 ("SSN == SSN del stub real").
Resultó que **`NtQuerySystemTime` no es un stub de syscall**: se exporta como un `jmp` a
`RtlQuerySystemTime`, una implementación en user-mode. O sea, **no tiene** el prólogo
`4C 8B D1 B8` de los stubs reales.

Lo interesante: **FreshyCalls le asigna un SSN correcto igualmente** (por su posición en el orden
de exports), y la ejecución indirecta **funciona** (devuelve tiempo válido y monótono). Es decir,
la técnica tolera este caso… pero conviene **saberlo y documentarlo**. En la Fase 6 se cuantificó:
de 490 exports `Nt*`, **488 son stubs reales y 2 no**.

---

## Qué cubre (y qué no) este catálogo

**Cubre:** varias aridades (0, 1, 4, 5, 6), un caso especial (`NtQuerySystemTime`), un
*round-trip* de memoria (`protect` + `free`) y negativos (clase inválida). Con eso, cualquier
error de paso de argumentos o de tabla saldría a la luz.

**No cubre:** todas las formas de la API ni todas las builds de Windows. La Fase 6 ataca hooks; la
Fase 7 añade herramientas; la Fase 8 mide detección. Cada fase **no** pretende ser el final, sino
un **escalón con su prueba**.

---

## Fondo: leer los `NTSTATUS` como un investigador

Cuando ejecutas el catálogo, verás códigos. Reconocerlos rápido ahorra tiempo:

| Código | Significado | Cuándo aparece |
| --- | --- | --- |
| `0x00000000` | `STATUS_SUCCESS` | la llamada funcionó |
| `0xC0000008` | `STATUS_INVALID_HANDLE` | cerramos algo que no existía |
| `0xC0000003` | `STATUS_INVALID_INFO_CLASS` | pedimos una clase inválida |
| `0xC000000D` | `STATUS_INVALID_PARAMETER` | un argumento no cuadra |
| `0xC0000017` | `STATUS_NO_MEMORY` | asignación imposible |

Que un *negativo* devuelva el **mismo** `NTSTATUS` que la función nativa de `ntdll` no es un
detalle: es una **prueba diferencial** (la usaremos a fondo en la Fase 7).

---

## El catálogo, función por función

```text
slot  syscall                     aridad   por que esta
----  --------------------------  -------  ------------------------------------------
  0   NtClose                        1      el caso de la Fase 4
  1   NtQuerySystemInformation       4      consulta de sistema (registros)
  2   NtQueryInformationProcess      5      5.o argumento EN LA PILA
  3   NtAllocateVirtualMemory       6      args en la pila (reserva real de memoria)
  4   NtFreeVirtualMemory           4      round-trip con 3
  5   NtProtectVirtualMemory        5      round-trip con 3/4 (cambia permisos)
  6   NtQuerySystemTime             1      export ESPECIAL (no es stub, ver abajo)
  7   NtYieldExecution              0      sin argumentos (control)
```

La elección **no** es aleatoria: cada aridad (0, 1, 4, 5, 6) ejercita un camino distinto del paso
de argumentos. La aridad 5 y 6 son las importantes: **el 5.º argumento ya no cabe en registros** y
viaja por la pila.

---

## El contrato de la macro (`KAGE_STUB`)

```asm
KAGE_STUB MACRO name, slot
name PROC
    mov  r10, rcx
    mov  eax, DWORD PTR [g_SsnTable + slot*4]
    jmp  QWORD PTR [g_GadgetTable + slot*8]
name ENDP
ENDM
```

Reglas del contrato:

- **Un slot alinea dos tablas:** `g_SsnTable + slot*4` (WORD) y `g_GadgetTable + slot*8` (QLWORD).
  Un fallo de escala (`*4` vs `*8`) lee basura y ejecutaría **otra** syscall.
- El ASM **no conoce** el SSN ni el gadget: los **lee** de las tablas (que rellena el core en
  runtime). Por eso añadir una función es "una línea en el registro".
- El bloque queda delimitado por `KageStubStart`/`KageStubEnd`, para poder **inspeccionarlo por
  símbolo** en `cdb`.

---

## Los 15 experimentos, por qué cada uno

No son pruebas de humo; cada uno ataca una suposición distinta:

- **Resolución y tablas (1–5, 7):** que el catálogo entero se resuelva, que las 8 entradas de
  `g_SsnTable` queden pobladas, que los 8 gadgets sean `0F 05 C3`, y que el bloque ASM contenga
  **≥ 8 stubs**. Si el resolver o la macro fallaran, aquí se ve.
- **Consistencia con el oráculo (6):** `SSN == SSN del stub real` por slot. Da 7/8 por el caso
  especial (ver abajo).
- **Aridades (8–12):** ejecutar 0, 1, 4, 5 y 6 argumentos. La 5 y la 6 verifican que los
  argumentos en la pila llegan al kernel.
- **Round-trip (13):** `NtProtectVirtualMemory` + `NtFreeVirtualMemory` sobre memoria **real**.
- **Negativo (14):** clase inválida → `STATUS_INVALID_INFO_CLASS`. Saber que **falla bien** es tan
  importante como saber que acierta.
- **Caso especial (15):** `NtQuerySystemTime` devuelve tiempo **válido y monótono**.

> La combinación de **positivos + negativos + aridades extremas** es lo que convierte "funciona"
> en "está verificado".

---

## El caso `NtQuerySystemTime`: no todos los `Nt*` son syscalls

Uno de los 8 no tiene el prólogo de stub (`4C 8B D1 B8`). `NtQuerySystemTime` se exporta como un
`jmp` a `ntdll!RtlQuerySystemTime` (implementación en user-mode). Por eso el experimento 6 compara
**7/8** stubs.

Lo bonito: **FreshyCalls le asigna un SSN igualmente** (por su posición en el orden de exports) y
la ejecución indirecta **funciona**. Es decir, la técnica **tolera** este caso. Documentarlo es
clave: en la Fase 6 se cuantificó a nivel de todo `ntdll` (**488/490** son stubs reales).

---

## Nota de seguridad para scripts de `cdb`

`NtClose(handle inválido)` genera una **excepción first-chance** `c0000008` que `ntdll` maneja
internamente. En scripts de `cdb` hay que **ignorarla** (`sxi c0000008`) o el script se detiene en
una excepción que, en realidad, el sistema ya resolvió. Pequeño detalle, gran ahorro de tiempo.

---

## Añadir una syscall nueva, paso a paso

Uno de los objetivos de la Fase 5 era que escalar fuera **trivial**. El procedimiento:

1. Añadir **una línea** al registro del core (nombre + slot).
2. Regenerar (la macro `KAGE_STUB` crea el `PROC` por ti).
3. Añadir el **wrapper tipado** `_I` correspondiente.
4. Añadir un test.

Nada de copiar/pegar stubs ni de tocar el ASM a mano. El registro es la **fuente única**; el
molde, la macro. Esa es la diferencia entre "8 funciones" y un **sistema**.

---

## La aridad, con la pila a la vista

```text
Aridad 0:  (sin argumentos)                 -> nada en pila
Aridad 1:  RCX (->R10)                       -> nada en pila
Aridad 4:  RCX, RDX, R8, R9                  -> nada en pila
Aridad 5:  RCX, RDX, R8, R9 + [rsp+0x20]     -> 5.o EN PILA
Aridad 6:  RCX, RDX, R8, R9 + [rsp+0x20..28]-> 5.o y 6.o EN PILA
```

Como el `jmp` no toca la pila, las aridades 5 y 6 funcionan **sin cambiar el stub**. Ese es el
motivo de probar justamente esas aridades: si algo estuviera mal en el manejo de la pila, aquí
aparecería.

---

## Preguntas frecuentes (Fase 5)

**¿Qué pasa si me equivoco de `slot`?** Leerías el SSN o el gadget de otra entrada → ejecutarías
**otra** función. Por eso el test 4/5 comprueba consistencia por slot.

**¿Por qué `NtQuerySystemTime` no falla aunque no sea stub?** FreshyCalls lo resuelve por orden de
exports; la ejecución indirecta no depende de que el export sea un stub.

**¿El catálogo cubre todo?** No; cubre aridades y casos representativos. Crecer es "una línea por
función".

---

## El precio de generalizar (y por qué el `jmp` lo minimiza)

Generalizar tiene un coste: cuanto más amplio el catálogo, más combinaciones de argumentos. La
decisión de diseño que lo abarata es el **`jmp`**: como no toca la pila, **un mismo stub** sirve
para cualquier aridad. Sin eso, tendrías que generar (o mantener a mano) un stub por aridad, con
más superficie de error.

Con la macro, el coste de añadir una función es **constante y pequeño**: una línea de registro +
un wrapper + un test. Eso es lo que hace **sostenible** crecer.

---

## Matriz: qué fallo detecta cada aridad

| Aridad probada | Qué fallo expone si estuviera mal |
| --- | --- |
| 0 | Confusión de registros/pila (control) |
| 1 | `mov r10, rcx` y SSN básicos |
| 4 | Uso de `R8`/`R9` (los últimos en registros) |
| 5 | Paso del **5.º** argumento por la pila |
| 6 | Paso del **6.º** argumento por la pila |
| Round-trip | Coherencia de efectos reales (memoria) |
| Negativo | Que **falla bien** (no solo que acierta) |

Cada aridad no es "más de lo mismo": es una **prueba focalizada** de una suposición concreta.

---

## Migrar el catálogo a otra build

Como los SSN se resuelven **en runtime**, migrar a otra build de Windows **no** requiere tocar el
ASM ni el registro: solo volver a ejecutar. Lo que puede cambiar es **cuántos** exports `Nt*` hay y
cuáles no son stubs (`NtQuerySystemTime`-like). Por eso la serie recomienda **registrar la build**
en cada resultado y re-ejecutar la suite en cada entorno.

---

## Bibliografía y referencias

- Microsoft Learn — *x64 calling convention* (registros + pila: base de la aridad).
- jthuraisamy — *SysWhispers* (`github.com/jthuraisamy/SysWhispers`): un stub por función.
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`).
- Fuentes primarias: `docs/research/experimentos-fase5.md`, `docs/evidencias/m5.txt`.

> Aprender a romper para poder defender.
