---
title: "Kagemusha: indirect syscalls en Windows x64"
date: 2026-09-30
tags: windows internals, red team, syscalls, investigacion
summary: Cómo construí un sistema de indirect syscalls en C + MASM que resuelve los SSN en runtime con FreshyCalls y verifica cada afirmación con oráculos independientes.
---

# Kagemusha: indirect syscalls en Windows x64

> `Kagemusha` (影武者, "guerrero sombra") es el doble que actúa en lugar del original:
> nuestro código **no ejecuta** la instrucción `syscall`; salta al gadget `syscall;ret`
> que ya vive en `ntdll`, de modo que el `syscall` ocurre **dentro de ntdll** y nunca
> en nuestro módulo.

Este es el primer writeup de una investigación en curso: un **laboratorio** con fases,
evidencia y pruebas reproducibles sobre **indirect syscalls** en Windows x64, escrito en
**C + MASM**. La idea es sencilla de enunciar y difícil de hacer bien: **una sola técnica**,
auditable, y cada afirmación contrastada con una fuente independiente.

## ¿Por qué indirect syscalls?

En user-mode, los EDR suelen colocar **hooks** en los *stubs* de `ntdll` (`Nt*`). Cuando
llamas a la API Win32 o a `Nt*` directamente, pasas por ese código potencialmente
instrumentado. El *direct syscall* evita el stub cargando el SSN y ejecutando `syscall`
tú mismo… pero deja una firma: una instrucción `0F 05` en **tu** binario.

El *indirect syscall* busca el término medio:

- El `syscall` se ejecuta en `ntdll` (no en tu módulo), así que el `RIP` durante la
  transición apunta a memoria legítima de `ntdll`.
- Tu código solo **prepara** `EAX` = SSN y **salta** al gadget.

## Tesis y principios de diseño

> Es posible construir un sistema de syscalls indirecto **puro**, de **una sola técnica**,
> resoluble en runtime y verificable con oráculos independientes.

1. **Solo indirect syscalls.** Ninguna `0F 05` en nuestro binario (verificable en el debugger).
2. **Una sola técnica** de resolución de SSN: *FreshyCalls*. Sin híbridos ni fallbacks.
3. **Resolución en runtime**: los SSN dependen de la build de Windows; nada *hardcodeado*.
4. **Código real y medido.** Cero pseudocódigo; cada función tiene un test.
5. **Fallar de forma ruidosa.** Ante una inconsistencia se aborta; nunca se "adivina".

## Estado de la investigación

| Fase | Hito | Estado |
| --- | --- | --- |
| 0 | Toolchain + debugger + hola-ASM | verificado |
| 1 | `util/` (PEB, exports por hash, rangos, log) | verificado |
| 2 | Resolución de SSN (FreshyCalls) | verificado |
| 3 | Gadget `syscall;ret` validado | verificado |
| 4 | Ejecución indirecta real + wrapper `NtClose_I` | pendiente |
| 5 | Generalización a ≥ 8 syscalls | pendiente |
| 6 | Robustez multi-build + hook simulado | pendiente |

## Resolución de SSN: FreshyCalls

**FreshyCalls** obtiene el número de servicio **sin leer bytes del stub** (lo que lo hace
inmune a hooks), explotando un invariante de Windows 10/11: los stubs `Nt*` residen en
`.text` **en orden de SSN**. Basta con enumerar los exports `Nt*`, ordenarlos por dirección
virtual y usar el **índice como SSN**.

```c
/* idea: ordenar exports Nt* por VA; el indice es el SSN */
qsort(entries, count, sizeof(*entries), cmp_by_va);
for (i = 0; i < count; i++)
    entries[i].ssn = (DWORD)i;
```

Tabla resuelta en la build de referencia (coincide con el stub real):

| Función | SSN | Función | SSN |
| --- | --- | --- | --- |
| NtClose | 0x00F | NtAllocateVirtualMemory | 0x018 |
| NtCreateFile | 0x055 | NtProtectVirtualMemory | 0x050 |
| NtOpenProcess | 0x026 | NtReadFile | 0x006 |
| NtQuerySystemInformation | 0x036 | NtOpenKey | 0x012 |
| NtCreateThreadEx | 0x0C9 | NtWaitForSingleObject | 0x004 |

## El gadget `syscall;ret`

La otra mitad es localizar la instrucción real `syscall;ret` (`0F 05 C3`) **dentro de
`ntdll`** y validar que está en `.text`. Nada de gadgets en regiones raras: bytes + rango.

```text
db poi(Kagemusha!g_Entries+0x18) L3
00007ffc`48540fa2  0f 05 c3        ; syscall; ret
? poi(Kagemusha!g_Entries+0x18) - ntdll = 0x160fa2
```

## Metodología: oráculos independientes

> Ninguna afirmación se comprueba contra el propio sistema. Siempre hay un **oráculo independiente**.

| Afirmación | Oráculo independiente |
| --- | --- |
| PEB walk correcto | `GetModuleHandleW` |
| Export resuelto correcto | `GetProcAddress` |
| Hash DJB2 correcto | vectores calculados con herramienta aparte |
| SSN correcto | bytes reales del stub (`4C 8B D1 B8 <ssn>`) |
| Gadget correcto | bytes `0F 05 C3` + rango `.text` de `ntdll` |
| `syscall` en ntdll (Fase 4) | `RIP` dentro de `ntdll` en cdb |

Cada hito produce **dos** formatos de evidencia: un **test automatizado** (PASS/FAIL) y un
**transcript del debugger** (`cdb`) reproducible con un script.

## Resultados

- Suite completa: **57 PASS / 0 FAIL** (`Kagemusha_tests.exe`, exit 0).
- Demo M0–M3: **`RESULTADO: OK`**.
- `NtClose` resuelto por PEB/hash = `ntdll!NtClose` (diferencia 0).

## Limitaciones y superficie de detección

Ser honesto sobre el alcance importa:

- **Sin stack spoofing (v1):** en un *stack walk*, el *caller* visible sigue siendo el
  módulo propio. Queda **fuera de alcance** y se cuantificará en un experimento aparte.
- El indirect "puro" **no es invisible**: hay que medir qué ve un EDR (call-stack, retorno,
  consistencia de `RIP`/`EAX`). Eso es, precisamente, parte de la investigación.

## Próximos pasos

- **Fase 4:** trampolín ASM + wrapper `NtClose_I`. Criterio: `RIP` en `ntdll`, `EAX`==SSN,
  retorno al wrapper y **cero `0F 05`** en Kagemusha.
- **Fase 5–6:** generalizar a ≥ 8 syscalls, matriz multi-build y test de hook simulado.
- **Fase 7:** núcleo propio (macro MASM + generador), *ledger* de syscalls y extensión `!kage`.

## Cierre

`Kagemusha` es un ejemplo de **investigación medida**: una técnica, un invariante, y una
metodología que se niega a creerse a sí misma sin un oráculo externo. Esa disciplina
—verificar siempre— es más valiosa que la técnica en sí.

> Aprender a romper para poder defender.

*(Investigación en curso. Repositorio-laboratorio con evidencia reproducible.)*
