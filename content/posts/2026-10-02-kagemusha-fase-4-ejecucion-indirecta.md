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

> Aprender a romper para poder defender.
