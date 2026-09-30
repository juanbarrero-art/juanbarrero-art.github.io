---
title: "Kagemusha — Fases 0 a 3: del toolchain al gadget"
date: 2026-10-01
tags: windows internals, red team, syscalls, investigacion
serie: Kagemusha
summary: Construimos los cimientos del sistema paso a paso desde cero: toolchain C+MASM y debugger, PEB walk y hash DJB2, resolución de SSN por FreshyCalls y validación del gadget syscall;ret. Cada hito con su oráculo y su evidencia.
---

# Kagemusha — Fases 0 a 3: del toolchain al gadget

En la [visión general](/blog/kagemusha-indirect-syscalls.html) pusimos la tesis y la
metodología. Aquí empezamos a **construir**. Estas cuatro fases (M0–M3) no ejecutan todavía
ninguna syscall: preparan **los cimientos** para que, en la Fase 4, el `syscall` ocurra dentro
de `ntdll`. Y lo mejor: cada fase termina con una **prueba objetiva** contra una fuente
independiente.

Si algún término te suena raro (stub, SSN, `ntdll`), la [guía de syscalls](/blog/guia-syscalls-windows.html)
es el mejor punto de partida.

---

## Fase 0 — Toolchain + debugger + "hola ASM" · M0 ✅

### El objetivo

Antes de escribir nada "serio", quería validar el **pipeline completo**: compilar C y ASM juntos,
generar símbolos (PDB) y poder depurar **por línea de comandos**. Si esta base falla, todo lo
demás es castillos en el aire.

### El entorno

- **MSVC 19.51** (Build Tools 2026), **MASM `ml64` 14.51**, **Windows SDK 10.0.26100**.
- **`cdb` v10.0.29617** (Debugging Tools for Windows), con `_NT_SYMBOL_PATH` configurado.

Instalar solo los *debuggers* del SDK es tan simple como:

```powershell
# Configurar el servidor de simbolos de Microsoft (una vez)
[Environment]::SetEnvironmentVariable("_NT_SYMBOL_PATH",
    "srv*C:\symbols*https://msdl.microsoft.com/download/symbols", "User")
```

### La implementación

Dos piezas mínimas:

```asm
; src/asm/hello.asm
KageHelloAsm PROC
    mov eax, 42
    ret
KageHelloAsm ENDP
```

```c
/* src/main.c (extracto): el selftest imprime el resultado del ASM */
int main(void) {
    int v = KageHelloAsm();
    printf("M0  KageHelloAsm() = %d\n", v);
    return v == 42 ? 0 : 1;
}
```

Y un `tools/build.cmd` que llama a `vcvars64`, ensambla con `ml64`, compila con `cl` y enlaza
con `link /DEBUG:FULL` (PDB completo).

### La prueba (y por qué PDB importa)

El milestone no es "compila", sino **"puedo poner un breakpoint simbólico y ver el `mov`"**:

```text
bp Kagemusha!KageHelloAsm
Kagemusha!KageHelloAsm:
00007ff6`1cf72a30 b82a000000      mov     eax,2Ah   ; 42
```

Salida: `M0  KageHelloAsm() = 42` (exit 0).

> **Por qué importa:** sin símbolos, en la Fase 4 no podríamos hacer `bp Kagemusha!NtClose_I`
> ni leer el `RIP` con nombre. El PDB es lo que convierte el debugger en una herramienta de
> **evidencia**, no de adivinación.

---

## Fase 1 — Utilidades base (`util/`) · M1 ✅

### El objetivo

Acceder a `ntdll` **sin depender de la IAT** (Import Address Table). La IAT es una lista de
funciones importadas que cualquiera puede ver; evitar `GetModuleHandle`/`GetProcAddress` en el
camino crítico es parte del diseño. En su lugar, hacemos "a mano" lo que esas funciones hacen.

### Las piezas

**1. PEB walk (`src/util/peb.c`).** El **PEB** (Process Environment Block) es la estructura del
proceso que el kernel mantiene; en x64 se localiza con `gs:[0x60]`. Dentro, `Ldr` guarda la
lista de módulos **en orden de carga** (`InLoadOrderModuleList`). Recorriéndola, comparamos
cada nombre contra un **hash** hasta dar con `ntdll`:

```c
PPEB UtlGetCurrentPeb(void) {
    return (PPEB)__readgsqword(0x60);   /* magia del TEB -> PEB */
}
/* UtlFindModuleByHash: camina InLoadOrderModuleList comparando hashes */
```

**2. Hash DJB2 (`src/util/exhash.c`).** En vez de comparar cadenas carácter a carácter
(visible y clásico), comparamos **enteros**: el hash del nombre. Usamos **DJB2**
(`hash = hash*33 + c`), con variantes *case-insensitive* para ANSI y Wide.

```c
DWORD UtlHashStrAnsi(PCSTR s) {
    DWORD h = 5381;
    while (*s) { h = ((h << 5) + h) + (BYTE)tolower(*s++); }
    return h;
}
```

**3. Exports por hash (`UtlGetExportByHash`).** Dado el base de `ntdll`, recorremos su **export
directory** (EAT) y devolvemos la dirección de la función cuyo hash coincide, **descartando
forwarded** (exports que son meros punteros a otro módulo).

**4. Rango `.text` (`UtlGetModuleRange`).** Leemos las cabeceras PE y obtenemos el rango real
de la sección `.text`. Lo necesitaremos para **validar que un gadget está dentro de `ntdll`**.

**5. Log (`src/util/log.c`).** `UtlLog` con niveles, a `stdout` **con `flush`**, para que la
salida aparezca en el transcript de `cdb` sin perderse.

### La prueba (oráculo independiente)

El test **no** dice "creo que es correcto". Lo contrasta con la API de Windows:

```text
rax=00007ffc48540f90                        ; lo que resuelve NUESTRO codigo
00007ffc`48540f90 ntdll!NtClose (NtClose)   ; lo que dice el SIMBOLO de Microsoft
? (rax - ntdll!NtClose) = 0                 ; IDENTICOS
```

Salida: `M1  ntdll base = 00007FFC483E0000`, `.text = ... (1482908 bytes)`,
`NtClose = 00007FFC48540F90`.

> Si nuestro PEB walk devolviera una base falsa, `GetModuleHandleW` lo delataría. Si el hash
> estuviera mal, `GetProcAddress` daría otra dirección. **Nunca nos creemos a nosotros mismos.**

---

## Fase 2 — Resolución de SSN por FreshyCalls · M2 ✅

### El objetivo

Obtener el **SSN** (número de servicio) de cada `Nt*` **sin leer bytes del stub**. ¿Por qué sin
leer bytes? Porque un EDR puede modificar esos bytes (hook). Si dependemos de ellos, dependemos
de que estén intactos.

### El invariante

FreshyCalls explota un hecho de Windows 10/11:

> Los stubs `Nt*` están en `.text` **en el mismo orden que sus SSN**.

Por tanto:

```c
/* 1) coleccionar TODAS las exports "Nt*" (prefijo estricto Nt + mayuscula) */
/* 2) ordenarlas por direccion virtual (VA) ascendente */
qsort(NtExports, n, sizeof(*NtExports), cmp_por_va);
/* 3) el INDICE que ocupa cada una ES su SSN */
for (DWORD i = 0; i < n; i++)
    NtExports[i].ssn = i;
```

Nada de leer `mov eax, SSN` del stub: **solo ordenamos direcciones**. Eso lo hace inmune a que
los bytes del stub estén "modificados".

### Los checks (fallar ruidoso)

El resolver **falla con error** si: la lista está vacía, hay **VAs duplicadas**, aparece un
forwarded, o algún objetivo del catálogo no resuelve. Nada de continuar a medias.

### La prueba (oráculo independiente)

Contrastamos nuestro SSN contra el que dice el **stub real** de Microsoft:

```text
uf ntdll!NtClose
ntdll!NtClose:
00007ffc`48540f93 b80f000000      mov     eax,0Fh    ; SSN real, lo dice el stub
```

Salida: `M2  FreshyCalls: 8/8 coinciden con el stub`. Para las 12 funciones del registro:

| Función | SSN | Función | SSN |
| --- | --- | --- | --- |
| NtClose | 0x00F | NtAllocateVirtualMemory | 0x018 |
| NtCreateFile | 0x055 | NtProtectVirtualMemory | 0x050 |
| NtOpenProcess | 0x026 | NtReadFile | 0x006 |
| NtQuerySystemInformation | 0x036 | NtQueryInformationProcess | 0x019 |

> Un SSN equivocado no "casi funciona": ejecutarías **otra** función del kernel. Por eso el
> oráculo es obligatorio.

---

## Fase 3 — Localizar el gadget `syscall;ret` · M3 ✅

### El objetivo

Encontrar, **dentro de `ntdll`**, la secuencia real de bytes **`0F 05 C3`** (`syscall; ret`) y
garantizar que es ejecutable y que no forma parte de un hook. Ese será nuestro punto de salto
en la Fase 4.

### La idea clave

Un gadget `syscall;ret` es **agnóstico del SSN**: sirve para *cualquier* syscall, porque el
número viaja en `EAX`. Eso permite tener un **pool** de gadgets de respaldo.

### La validación (3 checks)

Localizar los bytes no basta; hay que **validar** el candidato:

1. En esa dirección están exactamente `0F 05` y, dos bytes después, `C3`.
2. La dirección cae **dentro de `.text` de `ntdll`** (el rango del M1).
3. El stub de origen **no empieza con un prólogo de hook** (`E9` / `FF 25`).

El orden de selección es determinista (para que las pruebas sean reproducibles): primero el
stub de la propia función; si está hookeado, el de su gemela `Zw*`; y si no, el pool ordenado
por menor VA.

### La prueba

```text
db poi(Kagemusha!g_Entries+0x18) L3
00007ffc`48540fa2  0f 05 c3                 ; syscall; ret
? poi(Kagemusha!g_Entries+0x18) - ntdll = 0x160fa2   ; dentro de ntdll
```

Salida: `M3  gadgets validos (0F 05 C3 en .text): 8/8`.

> Doble comprobación: **los bytes** son los correctos **y** la dirección pertenece a `ntdll`.
> Un gadget "a mitad de instrucción" provocaría un crash; por eso anclamos a inicio de stub
> validado y patrón exacto.

---

## Qué aprendimos en estas cuatro fases

- **El PDB no es opcional.** Sin símbolos no hay evidencia, solo fe.
- **El hash convierte comparaciones visibles en comparaciones de enteros.** Menos superficie,
  más orden.
- **Nunca hardcodear el SSN.** La tentación de "poner 0x0F y ya" rompe en la próxima build.
- **Validar, no asumir.** Un gadget se *valida* (bytes + rango + no-hook), no se *confía*.
- **Fallar ruidoso.** Un error claro vale más que un resultado silenciosamente incorrecto.

Con los cimientos listos (base de `ntdll`, SSN resueltos y gadget validado), ya podemos hacer
lo importante: **ejecutar de verdad** una `Nt*` de forma indirecta. Eso es la
[Fase 4](/blog/kagemusha-fase-4-ejecucion-indirecta.html).

## Cómo sigue la serie

1. [Guía de syscalls](/blog/guia-syscalls-windows.html)
2. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html)
3. **Fases 0 a 3** (esta entrada)
4. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html)
5. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html)
6. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html)

> Aprender a romper para poder defender.
