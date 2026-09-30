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

## Bibliografía y referencias

- Microsoft Learn — *x64 calling convention* (registros + pila: base de la aridad).
- jthuraisamy — *SysWhispers* (`github.com/jthuraisamy/SysWhispers`): un stub por función.
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`).
- Fuentes primarias: `docs/research/experimentos-fase5.md`, `docs/evidencias/m5.txt`.

> Aprender a romper para poder defender.
