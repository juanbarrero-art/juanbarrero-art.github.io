---
title: "Kagemusha — Fase 4: ejecución indirecta real"
date: 2026-10-02
tags: windows internals, red team, syscalls, investigacion
serie: Kagemusha
summary: El hito central. NtClose_I ejecuta el syscall dentro de ntdll, el módulo no contiene ninguna instrucción syscall, y tres experimentos de falsabilidad lo demuestran en el debugger.
---

# Kagemusha — Fase 4: ejecución indirecta real

Llegamos al **hito central** del proyecto. En las [fases 0–3](/blog/kagemusha-fases-0-3.html)
preparamos los cimientos: base de `ntdll`, SSN resueltos por FreshyCalls y un gadget
`syscall;ret` validado. Ahora conectamos todo para **ejecutar de verdad** una función `Nt*`
de forma indirecta —y lo demostramos en el debugger—.

> Definición que perseguimos (y que hay que probar): el `syscall` se ejecuta **dentro de
> `ntdll`**, el `RIP` cae en su rango, el SSN lo gobierna nuestra tabla, y **nuestro módulo
> no contiene ninguna instrucción `syscall`**.

![Diagrama: flujo de una syscall](../assets/diag-syscall-flow.svg)

## La implementación

Tres piezas nuevas más las tablas del núcleo:

- **`src/core/core.c`** — las tablas `g_SsnTable` (SSN por slot) y `g_GadgetTable` (gadget por
  slot), y **`KageInitialize` transaccional**: o resuelve **todo** el catálogo y valida **un
  gadget para cada uno**, o falla con un error detallado. Nada queda a medio inicializar.
- **`src/asm/syscalls.asm`** — el trampolín `KageNtCloseStub`, con etiquetas `KageStubStart`
  y `KageStubEnd` (para poder verificar el bloque por símbolo).
- **`src/wrappers/wrappers.c`** — el wrapper tipado `NtClose_I(HANDLE)` que devuelve el
  `NTSTATUS` real del kernel.

### El stub (el "guerrero sombra")

```asm
KageNtCloseStub PROC
    mov  r10, rcx                      ; arg1 -> R10 (ABI syscall)
    mov  eax, DWORD PTR [g_SsnTable]   ; EAX = SSN resuelto en runtime
    jmp  QWORD PTR [g_GadgetTable]     ; salta al syscall;ret de ntdll
KageNtCloseStub ENDP
```

Fíjate en lo que **no** hay: no hay `syscall` (`0F 05`). El stub **solo prepara** (`r10`, `eax`)
y **salta**. La secuencia mágica vive en `ntdll`.

### El wrapper

```c
NTSTATUS NtClose_I(HANDLE h) {
    if (!g_Initialized)            return KAGE_STATUS_NOT_INITIALIZED;
    if (g_SsnTable[0] == 0)        return KAGE_STATUS_SSN_UNRESOLVED;
    if (g_GadgetTable[0] == NULL)  return KAGE_STATUS_NO_GADGET;
    return KageNtCloseStub(h);     /* NTSTATUS del kernel, sin traducir */
}
```

Devolvemos el `NTSTATUS` del kernel **tal cual** (precisión NT), y los errores de *nuestro*
marco se distinguen con prefijo `KAGE_STATUS_*`.

## Cómo funciona (y por qué el `jmp`, no `call`)

Este es el detalle que hace que todo encaje. En la ABI x64 de Windows:

- El primer argumento va en `RCX`, pero la instrucción `syscall` **usa `RCX` para el retorno**,
  así que la convención de syscall manda el primer argumento por `R10`. De ahí el `mov r10, rcx`.
- Al usar **`jmp`** (un *tail call*), **no metemos una nueva dirección de retorno en la pila**:
  heredamos la que puso el wrapper al llamar al stub. Por eso, cuando el gadget ejecuta su
  `ret`, **regresa directamente al wrapper**. Y como no tocamos la pila, los argumentos 5+ (que
  viajan en la pila) llegan intactos al kernel.

> Si usáramos `call`, añadiríamos un frame extra y el `ret` del gadget no volvería al wrapper.
> El `jmp` es la solución **mínima correcta**.

## Pruebas T9 y T10

- **T9 — ejecución real:** `NtClose_I(0xDEADBEEF)` devuelve `STATUS_INVALID_HANDLE`
  (`0xC0000008`); `NtClose_I(handle válido)` devuelve `STATUS_SUCCESS` (`0`). Son **exactamente**
  los `NTSTATUS` que daría la API nativa (mismo kernel, mismo contrato).
- **T10 — propiedad anti-directa:** el stub no contiene bytes `0F 05`, y el **módulo completo**
  tampoco: `verify.ps1` lo comprueba con `dumpbin` **a nivel de mnemónico** y da **0** en ambos
  ejecutables.

## Evidencia (cdb) — el momento clave

Ponemos un breakpoint en el wrapper, dejamos correr y observamos el `RIP` **dentro de `ntdll`**:

```text
bp Kagemusha!NtClose_I ; g
? poi(Kagemusha!g_GadgetTable) = 00007ffc`48540fa2
g
00007ffc`48540fa2 0f05            syscall          ; RIP DENTRO de ntdll
rax=000000000000000f                               ; EAX = SSN de NtClose
rcx=00000000deadbeef  r10=00000000deadbeef         ; arg1 en RCX y R10 (ABI syscall)
rip=00007ffc48540fa2
ntdll  00007ffc`483e0000 - 00007ffc`48647000       ; RIP dentro del rango de ntdll
```

Lee esto despacio, porque es **la tesis hecha realidad**:

1. El `syscall` que se ejecuta está en `00007ffc48540fa2`, que cae **dentro** del rango de
   `ntdll` (`483e0000`–`48647000`).
2. `EAX = 0x0F` es el SSN de `NtClose` (el que resolvió FreshyCalls).
3. `RCX` y `R10` contienen el mismo argumento (`0xdeadbeef`): la ABI de syscall funcionó.

## M4+ — Experimentos de falsabilidad

Verificar que "funciona una vez" no basta. Intentamos **tumbar** la afirmación con tres
experimentos:

**1. La línea de retorno vuelve a nuestro código.** Si el `jmp` no hubiera preservado el frame,
el `ret` del gadget no volvería al wrapper. La pila lo demuestra:

```text
u Kagemusha!KageNtCloseStub L5
  4c8bd1        mov  r10, rcx
  8b05.....     mov  eax, dword ptr [Kagemusha!g_SsnTable]
  ff25.....     jmp  qword ptr [Kagemusha!g_GadgetTable]
dps @rsp L2
  00007ff6`c7712da3  Kagemusha!NtClose_I+0x13   ; <-- vuelve al wrapper
```

**2. El SSN de la tabla gobierna el syscall** (sin llegar a ejecutarlo): cambiamos el SSN en
memoria y observamos que el stub carga el nuevo valor —el SSN **no** está atado a los bytes del
stub, sino a nuestra tabla—:

```text
ew Kagemusha!g_SsnTable 0x55
g
eax=55                            ; el stub cargó 0x55 (no depende del stub)
rip=00007ffc48540fa2              ; sigue en el gadget de ntdll
```

**3. Repetibilidad:** T11 ejecuta **1000** `NtClose_I` consecutivos con resultado idéntico (PASS).

## Qué queda fuera (y por qué se dice)

En el breakpoint del gadget, `dps @rsp` muestra que la dirección de retorno apunta a **nuestro
wrapper** (`Kagemusha!NtClose_I`). Esto **no se oculta** en la v1: significa que un *stack walk*
vería que el *caller* inmediato es nuestro módulo. El *stack spoofing* está **fuera de alcance**
de la v1 y se medirá (no se esconderá) en la Fase de visibilidad. Decirlo es parte del rigor.

## Próximos pasos

- **Fase 5:** generalizar a un catálogo de ≥ 8 syscalls con **un único template ASM** (macro),
  ejercitando distintas aridades (argumentos en la pila).
- **Fase 6:** robustez ante **hooks** y entradas adversas.

Ambas ya están implementadas y verificadas; las contaré en las siguientes entradas.

## Cómo sigue la serie

1. [Guía de syscalls](/blog/guia-syscalls-windows.html)
2. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html)
3. [Fases 0 a 3: del toolchain al gadget](/blog/kagemusha-fases-0-3.html)
4. **Fase 4: ejecución indirecta real** (esta entrada)
5. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html)
6. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html)
7. [Fase 7 y baterías (T19–T22): ledger, CLI y CET](/blog/kagemusha-fase-7-baterias-cet.html)

## La ABI x64, en detalle (por qué esto funciona)

La **ABI** (Application Binary Interface) de Windows x64 es el conjunto de reglas sobre cómo se
pasan argumentos y valores de retorno entre funciones. Entenderla es entender por qué nuestro
trampolín es correcto:

- Los **4 primeros argumentos** van en registros: `RCX`, `RDX`, `R8`, `R9`.
- El **5.º y siguientes** van en la **pila** del llamador.
- El valor de retorno va en `RAX`.
- Además hay **registros volátiles** (que la función puede destruir) y **no volátiles** (que debe
  preservar).

La instrucción `syscall` tiene su propia convención, ligeramente distinta:

- **`RCX` guarda la dirección de retorno** (la sobrescribe la propia instrucción).
- Por eso el **primer argumento va en `R10`** en lugar de `RCX`.

De ahí el `mov r10, rcx` del stub. Si no hiciéramos esa copia, el kernel leería el argumento del
siguiente registro y **fallaría** (o haría algo distinto).

### El detalle que rompe a los novatos: `jmp` vs `call`

```asm
; INCORRECTO: con call, el ret del gadget no vuelve al wrapper
call gadget          ; empuja una direccion de retorno extra

; CORRECTO: con jmp (tail call), el frame del wrapper se preserva
jmp  [g_GadgetTable] ; no toca la pila -> el ret vuelve al wrapper
```

Con `call`, la pila tendría una dirección de retorno de más; el `ret` del gadget volvería al
stub, que volvería a saltar… **bucle o crash**. Con `jmp`, la pila queda tal como la dejó el
wrapper, y el `ret` del gadget regresa **directamente** a él. Además, los argumentos 5+ que
viajan en la pila llegan intactos al kernel.

---

## Interpretación de la evidencia, línea a línea

Volvamos al transcript y traduzcamos cada línea:

```text
bp Kagemusha!NtClose_I ; g          ; paramos en el wrapper y dejamos correr
? poi(Kagemusha!g_GadgetTable) = 00007ffc`48540fa2
                                    ; el gadget que vamos a usar
g                                   ; continuamos
00007ffc`48540fa2 0f05  syscall     ; ESTAMOS EJECUTANDO EL SYSCALL, en esta direccion
rax=000000000000000f                ; EAX = 0x0F = SSN de NtClose (resuelto en runtime)
rcx=00000000deadbeef r10=00000000deadbeef
                                    ; el argumento viaja en RCX y en R10 (ABI syscall)
rip=00007ffc48540fa2                ; el instruction pointer esta en el gadget
ntdll 00007ffc`483e0000 - 00647000  ; y ese gadget cae DENTRO de ntdll
```

Cuando el `RIP` (la instrucción que se está ejecutando) está en `00007ffc48540fa2` y ese valor
cae **dentro del rango de `ntdll`**, la definición de "indirecto" se cumple: **el `syscall` se
ejecutó en memoria de `ntdll`**, no en la nuestra. El `EAX` correcto prueba que el SSN lo puso
nuestra tabla. El `RCX == R10` prueba que la ABI se respetó.

---

## El wrapper y el manejo de errores

El wrapper hace tres cosas, en orden:

1. **Valida el estado del marco**: ¿se hizo `KageInitialize`? ¿la tabla tiene SSN? ¿hay gadget?
   Si algo falta, devuelve un **error propio** (`KAGE_STATUS_*`), no llama al kernel.
2. **Llama al stub** (`KageNtCloseStub`).
3. **Devuelve el `NTSTATUS` tal cual**, sin traducirlo a código Win32 (precisión NT).

Separar los errores del **marco** (nuestro sistema) de los del **kernel** es clave para depurar:
si recibes `KAGE_STATUS_SSN_UNRESOLVED`, el problema es tuyo (init/SSN); si recibes
`STATUS_INVALID_HANDLE`, el kernel hizo su trabajo y el argumento era malo.

---

## Contraste con la llamada nativa

Para convencerse de que hay una diferencia real, se puede comparar el **stack trace** de una
llamada nativa (que pasa por el stub, zona de hooks) con el de nuestra ruta indirecta (que salta
al gadget). En la nativa, el retorno aparece vinculado al stub de `ntdll`; en la indirecta, el
retorno cae en **nuestro wrapper** (`Kagemusha!NtClose_I+0x13`), como vimos en `dps @rsp`.

Esto, lejos de ser un detalle cosmético, es **el dato que un defensor usaría**: el *caller*
inmediato del indirecto puro es el módulo propio. Por eso lo documentamos (y no lo escondemos).

---

## Errores comunes (Fase 4)

- **Usar `call` en vez de `jmp`**: rompe el retorno. Debe ser *tail call*.
- **Olvidar `mov r10, rcx`**: el kernel lee el argumento equivocado.
- **Hardcodear el SSN en el ASM**: rompe entre builds; debe leerse de la tabla.
- **Devolver un error propio como si fuera del kernel**: confunde el diagnóstico.
- **No verificar `RIP` dentro de `ntdll`**: creer que es indirecto sin probarlo.

---

## 🧪 Experimenta tú — observa el salto con tus ojos

*(Nivel 🟡. Si no compilas el proyecto, puedes seguir la idea leyendo; el "ver" es lo divertido.)*

Con el binario compilado (`tools\build.cmd`) y `cdb` en el `PATH`:

```text
cdbX64 -cf tools\cdb_scripts\m4_nclose.txt -logo docs\evidencias\m4.txt bin\Kagemusha.exe
```

**Qué deberías ver** (resumido):

```text
bp Kagemusha!NtClose_I ; g
00007ffc`48540fa2 0f05  syscall
rax=000000000000000f
ntdll 00007ffc`483e0000 - 00007ffc`48647000
```

Traducción para humanos: el programa paró justo en la instrucción `syscall`, y esa instrucción
está **dentro de `ntdll`**. `RAX = 0x0F` es el número que nuestra tabla puso. Si hicieras lo mismo
con un *direct syscall*, esa dirección estaría **fuera** de `ntdll` (en tu `.exe`) y el ejercicio
fallaría —y esa es, precisamente, la diferencia.

> **Mini-reto:** busca con `s -a Kagemusha L? 0f05` (dentro de nuestro módulo) y comprueba que
> devuelve **cero**. Esa "ausencia" es el resultado.

---

## Diario: el error que me costó una tarde

Cuando escribí el primer trampolín, usé `call` en vez de `jmp`. El programa compilaba, arrancaba…
y **se colgaba** al primer `NtClose`. Tardé en entenderlo: el `call` empuja una dirección de
retorno, el `ret` del gadget devuelve el control al **stub** (no al wrapper), el stub vuelve a
saltar al gadget… y entramos en un bucle. **La solución era un `jmp`**, un *tail call* que no
toca la pila. Moraleja: en esta técnica, "ir" y "llamar" **no** son lo mismo.

Lo cuento porque forma parte del método: los errores, documentados, enseñan más que los aciertos.

---

## Fondo: ¿por qué el kernel se cree nuestro `EAX`?

Alguien podría preguntarse: si el SSN viaja en `EAX`, **yo podría poner cualquier número**. Y es
cierto: si pones el SSN de `NtAllocateVirtualMemory` cuando querías cerrar un handle, el kernel
ejecutará **esa otra** función. El kernel **no comprueba** que tú "tengas derecho" a esa syscall
en el sentido de la API Win32: confía en el número.

Justo por eso el SSN correcto importa tanto. Un error de 1 en el índice no da "un fallo
elegante"; da una **llamada a otra función**, con argumentos que no encajan. Y por eso el oráculo
(bytes reales del stub) es **obligatorio**, no opcional.

---

## Cómo se vería desde una defensa

Entender la técnica es la mitad; la otra es saber **cómo se detecta**. Un defensor no vería
"Kagemusha", pero sí podría observar:

| Señal | Qué vería |
| --- | --- |
| **Stack walk** | La dirección de retorno apunta a un módulo **no-ntdll** (el nuestro). |
| **Consistencia RIP/EAX** | Un `syscall` en `ntdll` cuyo *caller* no es un stub habitual. |
| **ETW / callbacks del kernel** | La operación real (cerrar handle, asignar memoria) llega al kernel igual. |
| **Binario estático** | Ausencia de `0F 05` (no prueba nada por sí sola, pero es una pista). |

Ninguna de estas señales es "prueba irrefutable" por separado. La lección defensiva es que
**combatir el indirecto puro es un problema de correlación de telemetría**, no de una firma
mágica. Y medirlo es la Fase 8.

---

## Comparación rápida: directo vs. indirecto (recordatorio)

| Aspecto | Direct | Indirect (Kagemusha) |
| --- | --- | --- |
| ¿`0F 05` en tu módulo? | Sí | **No** |
| `syscall` en `ntdll` | No | **Sí** |
| Necesita SSN | Sí | Sí |
| Necesita gadget | No | **Sí** |
| Evita hooks de user-mode | Sí | Sí |
| Invisible al kernel | No | No |

La tabla resume el compromiso: el indirecto **mueve** el `syscall` a `ntdll` sin eliminar el
hecho de que el kernel lo ve.

---

## El flujo completo de una llamada, paso a paso (con el repo)

Sigamos una `NtClose_I` con los **archivos reales** del repositorio:

```text
[1] wrappers.c: NtClose_I(h)
      - comprueba g_Initialized        (si no, KAGE_STATUS_NOT_INITIALIZED)
      - comprueba g_SsnTable[slot]     (si no, KAGE_STATUS_SSN_UNRESOLVED)
      - comprueba g_GadgetTable[slot]  (si no, KAGE_STATUS_NO_GADGET)
      - llama a KageNtCloseStub(h)
              |
              v
[2] syscalls.asm: KageNtCloseStub
      mov r10, rcx                      ; arg1 -> R10
      mov eax, [g_SsnTable + slot*4]    ; SSN resuelto en runtime
      jmp  [g_GadgetTable + slot*8]     ; salta al syscall;ret de ntdll
              |
              v
[3] gadget en ntdll: syscall ; ret     ; <-- el syscall ocurre DENTRO de ntdll
              |
              v  (ret vuelve al wrapper: la pila no se toco)
[4] kernel: SSDT[EAX] -> NtClose        ; hace el trabajo
              |
              v
[5] wrappers.c: devuelve el NTSTATUS tal cual
```

Cada pieza tiene una responsabilidad **una sola**: el wrapper **valida y delega**, el stub
**prepara y salta**, el gadget **ejecuta**, el kernel **decide**. Si algo va mal, sabes **dónde**
mirar.

---

## El workflow de verificación de 6 puntos

Para la Fase 4, el plan del proyecto exige **seis** comprobaciones (no una). Es la definición
operativa de "esto es indirecto":

1. **El `syscall` se ejecuta DENTRO de `ntdll`.** Con `bp <VA_gadget>`: `lm m ntdll` muestra que
   `rip` cae en `[start, end]`. En un direct syscall, el `0F 05` estaría en `Kagemusha.exe`.
2. **El SSN viaja en `EAX` y es el correcto.** `r @eax` == valor de la tabla (obtenido con
   `uf ntdll!NtClose`). Además, `r @r10 == r @rcx` (ABI).
3. **Nuestro módulo no contiene la instrucción.** `s -a` acotado a `.text` de Kagemusha → **cero**;
   `dumpbin /disasm | findstr syscall` → **cero**.
4. **La dirección de retorno vuelve a nuestro flujo.** En el `bp` del gadget, `dps @rsp L1` apunta
   a `Kagemusha!NtClose_I+...` → el `jmp` preservó el frame.
5. **Contraste pedagógico.** Poner `bp ntdll!NtClose` en una llamada nativa y comparar el *stack
   trace*: la ruta nativa pasa por el stub (zona de hooks); la nuestra, no.
6. **Exactitud semántica.** T9/T6 devuelven el **mismo** `NTSTATUS` que la API nativa para las
   mismas entradas.

> Seis puntos, seis oráculos. No basta con "parece que funciona": hay que **acotar** la propiedad
> por todos los lados.

---

## Los tres experimentos M4+ (falsabilidad), explicados

**1. La línea de retorno (`m4_return.txt`).** Si el `jmp` no preservara el frame, el `ret` del
gadget no volvería al wrapper. La pila lo demuestra:

```text
dps @rsp L2
  00000087`59eff9f8  00007ff6`c7712da3  Kagemusha!NtClose_I+0x13   ; vuelve al wrapper
```

**2. El SSN gobierna el syscall (`m4_falsify.txt`).** Cambiamos `g_SsnTable` en memoria a `0x55` y
observamos que el stub carga `0x55` (no depende de bytes del stub). Se corta **antes** de
ejecutar el syscall alterado: experimento **seguro**.

**3. Repetibilidad (T11).** 1000 `NtClose_I` consecutivos → resultado idéntico (PASS). Un sistema
que funciona "una vez" no está verificado.

---

## El init transaccional: por qué no hay estados a medias

`KageInitialize` no "va rellenando": **o resuelve todo el registro** (SSN + gadget para cada
entrada) **o falla con un error detallado**. Este detalle evita la peor clase de bug: el sistema
"medio inicializado", donde unas syscalls van y otras no, y los fallos son aleatorios. El estado
siempre es coherente: o todo, o error.

Relación con el endurecimiento **A2**: si alguien **usa un wrapper sin init**, este devuelve
`KAGE_STATUS_NOT_INITIALIZED` y **nunca** hace `jmp` a `NULL`. Falla ruidoso, no explota.

---

## Errores del marco vs. errores del kernel

Distinguir el origen de un error es clave para depurar. La Fase 4 lo formaliza así:

| Si ves... | Significa... | Dónde está el problema |
| --- | --- | --- |
| `KAGE_STATUS_NOT_INITIALIZED` | No se llamó a `KageInitialize` | Tu marco |
| `KAGE_STATUS_SSN_UNRESOLVED` | El resolver no dio SSN | Tu marco |
| `KAGE_STATUS_NO_GADGET` | No hay gadget válido | Tu marco |
| `0xC0000008` (`STATUS_INVALID_HANDLE`) | El kernel rechazó el handle | Tu **argumento** |
| `0x00000000` (`STATUS_SUCCESS`) | Todo fue bien | — |

Esta separación convierte "algo falló" en "**falló esto, aquí**".

---

## La pila durante la llamada (el detalle que confunde)

```text
ANTES del jmp (dentro del stub):
  [rsp]     -> direccion de retorno al wrapper   (la puso el "call" del wrapper)
  [rsp+8]   -> 5.o argumento (si existe)
  [rsp+0x10]-> 6.o argumento (si existe)

EL STUB HACE jmp:
  (no empuja nada; la pila NO cambia)

EN EL GADGET:
  syscall      ; entra al kernel
  ret          ; consume [rsp] = vuelve al WRAPPER (no al stub)
```

Esta es la razón por la que el `jmp` (*tail call*) es **obligatorio**: mantiene la pila
**idéntica** a como la dejó el wrapper, así que los argumentos 5+ siguen donde el kernel los
espera, y el `ret` del gadget regresa al sitio correcto.

---

## Preguntas frecuentes (Fase 4)

**¿Por qué `R10` y no `RCX` para el primer argumento?** Porque `syscall` sobrescribe `RCX` con la
dirección de retorno. La ABI de syscall manda el 1.er argumento por `R10`; de ahí `mov r10, rcx`.

**¿Puedo usar cualquier gadget?** Cualquier `syscall;ret` **limpio** y **dentro de `.text`** de
`ntdll` sirve (el SSN viaja en `EAX`). Pero hay que **validarlo** (bytes + rango + no-hook).

**¿Qué pasa si el gadget no está en `ntdll`?** Entonces no sería indirecto puro: la gracia es que
el `RIP` caiga en memoria **legítima**. Por eso lo verificamos.

**¿Por qué 1000 repeticiones?** Porque un resultado puede ser "suerte". 1000 veces demuestra que
es **sistemático**, no casual.

**¿Se puede combinar con *stack spoofing*?** Fuera de alcance de la v1 (es otro problema, v2). La
v1 mide su propia visibilidad en vez de esconderla.

---

## Bibliografía y referencias

- Russinovich, Solomon, Ionescu — *Windows Internals, 7.ª ed.* (transición a kernel, SSDT).
- Microsoft Learn — *x64 calling convention* (por qué el 1.er argumento va en `R10` para `syscall`).
- jthuraisamy — *SysWhispers* (`github.com/jthuraisamy/SysWhispers`): patrón del stub indirecto.
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`).
- Fuentes primarias: `docs/evidencias/m4.txt`, `m4_return.txt`, `m4_falsify.txt`, `tools/cdb_scripts/`.

> Aprender a romper para poder defender.
