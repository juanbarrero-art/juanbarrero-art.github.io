---
title: "Kagemusha — Fases 0 a 3: del toolchain al gadget"
date: 2026-10-01
tags: windows internals, red team, syscalls, investigacion
serie: Kagemusha
summary: Los cimientos del sistema, explicados a fondo. Toolchain C+MASM y debugger por CLI, PEB walk y hash DJB2, resolución de SSN por FreshyCalls y validación del gadget syscall;ret. Cada hito con su oráculo, su evidencia y sus errores comunes.
---

# Kagemusha — Fases 0 a 3: del toolchain al gadget

En la [visión general](/blog/kagemusha-indirect-syscalls.html) pusimos la tesis y la metodología.
Ahora empezamos a **construir**. Estas cuatro fases (M0–M3) todavía **no ejecutan** ninguna
syscall: preparan **los cimientos** para que, en la Fase 4, el `syscall` ocurra dentro de
`ntdll`. Cada fase termina con una **prueba objetiva** contra una fuente independiente.

Si algún término se te escapa (stub, SSN, `ntdll`), la [guía de syscalls](/blog/guia-syscalls-windows.html)
es el mejor punto de partida. Esta entrada asume que ya sabes *qué* es una syscall y se centra
en *cómo* la prepara el sistema.

---

## Fase 0 — Toolchain + debugger + "hola ASM" · M0 ✅

### El objetivo

Antes de escribir nada "serio", hay que validar el **pipeline completo**: compilar C y ASM juntos,
generar símbolos (PDB) y poder depurar **por línea de comandos**. Si esta base falla, todo lo
demás son castillos en el aire.

### El entorno

- **MSVC 19.51** (Build Tools 2026), **MASM `ml64` 14.51**, **Windows SDK 10.0.26100**.
- **`cdb` v10.0.29617** (Debugging Tools for Windows), con `_NT_SYMBOL_PATH` configurado.

```powershell
# Servidor de simbolos de Microsoft (una vez)
[Environment]::SetEnvironmentVariable("_NT_SYMBOL_PATH",
    "srv*C:\symbols*https://msdl.microsoft.com/download/symbols", "User")
```

### La implementación

Dos piezas mínimas —un `PROC` en ASM y un `main` en C— más un `tools\build.cmd` que llama a
`vcvars64`, ensambla con `ml64`, compila con `cl` y enlaza con `link /DEBUG:FULL`:

```asm
; src/asm/hello.asm
KageHelloAsm PROC
    mov eax, 42
    ret
KageHelloAsm ENDP
```

```c
/* src/main.c (extracto) */
int main(void) {
    int v = KageHelloAsm();
    printf("M0  KageHelloAsm() = %d\n", v);
    return v == 42 ? 0 : 1;
}
```

### La prueba (y por qué el PDB es sagrado)

El milestone no es "compila", sino **"puedo poner un breakpoint simbólico y ver el `mov`"**:

```text
bp Kagemusha!KageHelloAsm
Kagemusha!KageHelloAsm:
00007ff6`1cf72a30 b82a000000      mov     eax,2Ah   ; 42
```

Salida: `M0  KageHelloAsm() = 42` (exit 0).

> **Sin símbolos no hay evidencia, solo fe.** El PDB es lo que permite, en la Fase 4, hacer
> `bp Kagemusha!NtClose_I` y leer un `RIP` **con nombre**. El debugger se convierte en una
> herramienta de prueba, no de adivinación.

### Errores comunes en esta fase

- **Olvidar `/Zi` / `/DEBUG:FULL`**: sin PDB no hay símbolos y los `bp` simbólicos fallan.
- **No configurar `_NT_SYMBOL_PATH`**: `ntdll!NtClose` aparecería sin nombre; imposible verificar.
- **Mezclar x86 y x64**: hay que usar el entorno `x64 Native Tools`.

---

## Fase 1 — Utilidades base (`util/`) · M1 ✅

![Diagrama: PEB walk](../assets/diag-peb.svg)

### El objetivo

Acceder a `ntdll` **sin depender de la IAT** (Import Address Table). La IAT lista las funciones
importadas y es visible; evitar `GetModuleHandle`/`GetProcAddress` en el camino crítico es parte
del diseño. Hacemos "a mano" lo que esas funciones hacen.

### Pieza 1 — PEB walk (`src/util/peb.c`)

El **PEB** (Process Environment Block) es la estructura del proceso que mantiene el kernel; en
x64 se localiza con `gs:[0x60]`. Dentro, `Ldr` guarda la lista de módulos **en orden de carga**
(`InLoadOrderModuleList`). Recorriéndola, comparamos cada nombre contra un **hash** hasta dar
con `ntdll`.

```c
PPEB UtlGetCurrentPeb(void) {
    return (PPEB)__readgsqword(0x60);   /* TEB -> PEB */
}
/* UtlFindModuleByHash: camina InLoadOrderModuleList comparando hashes */
```

**¿Por qué no usar `GetModuleHandle`?** Porque es *IAT-visible* y depende de `kernel32`. El PEB
walk hace lo mismo sin dejar esa dependencia.

### Pieza 2 — Hash DJB2 (`src/util/exhash.c`)

En vez de comparar cadenas carácter a carácter (visible y clásico), comparamos **enteros**: el
hash del nombre. Usamos **DJB2** (`hash = hash*33 + c`), con variantes *case-insensitive* para
ANSI y Wide.

```c
DWORD UtlHashStrAnsi(PCSTR s) {
    DWORD h = 5381;
    while (*s) { h = ((h << 5) + h) + (BYTE)tolower(*s++); }
    return h;
}
```

**¿Por qué hashes?** Cambian una comparación de cadenas (fácil de *flagguear*) por una
comparación de enteros. Menos superficie, más orden. Además, los hashes se pueden calcular en
compilación y en runtime solo se comparan números.

### Pieza 3 — Exports por hash (`UtlGetExportByHash`)

Dado el base de `ntdll`, recorremos su **export directory** (EAT): leemos los arrays de
nombres, direcciones y ordinales, calculamos el hash de cada nombre y devolvemos la dirección
de la función que coincide. **Descartamos *forwarded*** (exports que son punteros a otro módulo,
típicamente `Ntdll*` o `api-ms-*`).

### Pieza 4 — Rango `.text` (`UtlGetModuleRange`)

Leemos las cabeceras PE (DOS → NT → secciones) y obtenemos el rango real de `.text`. Es el
**marco de referencia** que usaremos para validar que un gadget está dentro de `ntdll`.

### Pieza 5 — Log (`src/util/log.c`)

`UtlLog` con niveles (Off/Err/Warn/Info/Dbg) a `stdout` **con `flush`**, para que la salida
aparezca en el transcript de `cdb` sin perderse por *buffering*.

### La prueba (oráculo independiente)

El test **no** dice "creo que es correcto": lo contrasta con la API de Windows y con los
símbolos de Microsoft:

```text
rax=00007ffc48540f90                        ; lo que resuelve NUESTRO codigo
00007ffc`48540f90 ntdll!NtClose (NtClose)   ; lo que dice el SIMBOLO de Microsoft
? (rax - ntdll!NtClose) = 0                 ; IDENTICOS
```

Salida: `M1  ntdll base = 00007FFC483E0000`, `.text = ... (1482908 bytes)`,
`NtClose = 00007FFC48540F90`.

> Si el PEB walk devolviera una base falsa, `GetModuleHandleW` lo delataría. Si el hash
> estuviera mal, `GetProcAddress` daría otra dirección. **Nunca nos creemos a nosotros mismos.**

### Errores comunes

- **Hash mal calculado**: comparece un nombre pero devuelve otro export → el oráculo lo caza.
- **No descartar forwarded**: terminabas con una dirección en otro módulo (no en `ntdll`).
- **`+1` de los ordinales**: el EAT usa ordinales basados en `Base`; olvidarlo desalinea todo.

---

## Fase 2 — Resolución de SSN por FreshyCalls · M2 ✅

![Diagrama: FreshyCalls (sort-by-VA)](../assets/diag-freshycalls.svg)

### El objetivo

Obtener el **SSN** (número de servicio) de cada `Nt*` **sin leer bytes del stub**. Si dependemos
de esos bytes y un EDR los modifica (hook), dependemos de que estén intactos. La idea es **no
mirar el stub en absoluto**.

### El invariante

> En Windows 10/11 los stubs `Nt*` están en `.text` **en el mismo orden que sus SSN**.

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
los bytes del stub estén modificados.

**Detalle del filtro:** prefijo estricto **`Nt` + segunda letra mayúscula**. Esto evita falsos
positivos como `NtdllOpen…` que desplazarían el índice.

### Los checks (fallar ruidoso)

El resolver **falla con error** si: la lista está vacía, hay **VAs duplicadas**, aparece un
*forwarded*, o algún objetivo del catálogo no resuelve. Nada de continuar con una tabla a medias.

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

### Errores comunes

- **Incluir exports que no son `Nt*`** (p. ej. `Ntdll*`) → el índice se desplaza y **todos** los
  SSN quedan mal.
- **No ordenar por VA** correctamente: si el `qsort` falla, el índice pierde sentido.
- **Hardcodear el SSN "porque ya lo sé"** (la tentación): rompe en la próxima build.

---

## Fase 3 — Localizar el gadget `syscall;ret` · M3 ✅

![Diagrama: gadget syscall;ret](../assets/diag-gadget.svg)

### El objetivo

Encontrar, **dentro de `ntdll`**, la secuencia real de bytes **`0F 05 C3`** (`syscall; ret`),
ejecutable y que no forme parte de un hook. Ese será el punto de salto de la Fase 4.

### La idea clave

Un gadget `syscall;ret` es **agnóstico del SSN**: sirve para *cualquier* syscall, porque el
número viaja en `EAX`. Eso permite tener un **pool** de gadgets de respaldo y hace el diseño
más simple.

### La validación (3 checks)

Localizar los bytes no basta; hay que **validar** el candidato:

1. En esa dirección están exactamente `0F 05` y, dos bytes después, `C3`.
2. La dirección cae **dentro de `.text` de `ntdll`** (el rango del M1).
3. El stub de origen **no empieza con un prólogo de hook** (`E9` / `FF 25`).

El orden de selección es **determinista** (pruebas reproducibles): primero el stub de la propia
función; si está hookeado, el de su gemela `Zw*` (misma rutina); y si no, el pool ordenado por
**menor VA**.

### La prueba

```text
db poi(Kagemusha!g_Entries+0x18) L3
00007ffc`48540fa2  0f 05 c3                 ; syscall; ret
? poi(Kagemusha!g_Entries+0x18) - ntdll = 0x160fa2   ; dentro de ntdll
```

Salida: `M3  gadgets validos (0F 05 C3 en .text): 8/8`.

> Doble comprobación: **los bytes** son los correctos **y** la dirección pertenece a `ntdll`.
> Un gadget "a mitad de instrucción" provoca un crash; por eso anclamos a inicio de stub
> validado y patrón exacto.

### Errores comunes

- **Encontrar `0F 05` fuera de `.text`** (p. ej. en datos): se ejecutaría algo inválido → crash.
- **Gadget a mitad de instrucción**: los bytes coinciden por casualidad pero no es un `syscall`
  real → hay que anclar a inicio de stub.
- **No contemplar el stub hookeado**: el gadget podría estar "tapado" → usar el pool.

---

## Qué aprendimos en estas cuatro fases

- **El PDB no es opcional.** Sin símbolos no hay evidencia, solo fe.
- **El hash convierte comparaciones visibles en comparaciones de enteros.** Menos superficie, más orden.
- **Nunca hardcodear el SSN.** La tentación de "poner 0x0F y ya" rompe en la próxima build.
- **Validar, no asumir.** Un gadget se *valida* (bytes + rango + no-hook), no se *confía*.
- **Fallar ruidoso.** Un error claro vale más que un resultado silenciosamente incorrecto.

Con los cimientos listos (base de `ntdll`, SSN resueltos y gadget validado), ya podemos **ejecutar
de verdad** una `Nt*` de forma indirecta: la [Fase 4](/blog/kagemusha-fase-4-ejecucion-indirecta.html).

## Preguntas frecuentes (fases 0–3)

**¿Por qué no uso `GetProcAddress` y ya?** Porque es IAT-visible y depende de `kernel32`; el
diseño evita esa dependencia en el camino crítico.

**¿Por qué DJB2 y no otra función de hash?** Es simple, rápida y bien conocida; lo importante es
que sea **determinista** y verificable con un oráculo externo.

**¿Qué pasa si dos exports tienen la misma VA?** Se detecta (VAs duplicadas) y el resolver
**falla ruidosamente**; no se adivina.

## Cómo sigue la serie

1. [Guía de syscalls](/blog/guia-syscalls-windows.html)
2. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html)
3. **Fases 0 a 3** (esta entrada)
4. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html)
5. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html)
6. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html)
7. [Fase 7 y baterías (T19–T22): ledger, CLI y CET](/blog/kagemusha-fase-7-baterias-cet.html)

## Módulos y contratos (vista de implementación)

Estas fases construyen los módulos de abajo hacia arriba. Vale la pena tener claros sus
**contratos** (qué recibe y qué devuelve cada pieza), porque de ellos depende la corrección.

### `util` — utilidades base

```c
PPEB   UtlGetCurrentPeb(void);                              /* gs:[0x60] */
PVOID  UtlFindModuleByHash(DWORD nameHash);                 /* PEB->Ldr, InLoadOrder */
BOOL   UtlGetModuleRange(PVOID base, PVOID *textStart, SIZE_T *textSize);
DWORD  UtlHashStrAnsi(PCSTR name);                          /* DJB2 */
DWORD  UtlHashStrWide(PCWSTR name);
PVOID  UtlGetExportByHash(PVOID dllBase, DWORD funcNameHash);/* export directory, sin forwarded */
VOID   UtlLog(UTL_LOGLEVEL, PCSTR fmt, ...);                /* stdout + flush (cdb) */
```

`UtlGetExportByHash` es la **única vía** de obtención de direcciones: sin `GetModuleHandle` ni
`GetProcAddress` en el camino crítico. Los hashes se calculan en compilación (macro
`KAGE_HASH("NtClose")`) y en runtime solo se comparan enteros.

### `resolver` — SSN y gadget

```c
typedef struct _KAGE_SSN_ENTRY {
    DWORD NameHash;         /* DJB2("NtClose") */
    WORD  Ssn;              /* indice en el sort == SSN */
    PVOID FunctionAddress;  /* VA real del export */
    PVOID StubAddress;      /* VA del stub (referencia) */
} KAGE_SSN_ENTRY;

NTSTATUS KageResolveSsnTable(PVOID ntdllBase, KAGE_SSN_ENTRY *entries, DWORD count);
NTSTATUS KageFindGadgetInStub(PKAGE_SSN_ENTRY entry, PVOID *pGadget);
NTSTATUS KageValidateGadget(PVOID base, PVOID textStart, SIZE_T textSize, PVOID cand);
```

Una sola fuente de verdad (el orden de exports). Sin lecturas de bytes ni fallbacks. Checks de
init: lista no vacía, sin VAs duplicadas, y todos los objetivos resuelven.

### `asm` — trampolín

Un `PROC` por syscall. Regla de oro: el ASM **nunca** contiene el SSN literal ni `0F 05`; solo
lee `g_SsnTable`/`g_GadgetTable`. Los índices (slots) los asigna el registro central, no el ASM.

### `wrappers` — capa C tipada

Cada `Nt*` soportada expone una firma tipada con sufijo `_I` (`NtClose_I`, …). El wrapper valida
estado (init, tablas), llama al stub y devuelve el **`NTSTATUS` tal cual**. Los errores del marco
se distinguen con prefijo `KAGE_STATUS_*` (`NOT_INITIALIZED`, `SSN_UNRESOLVED`, `NO_GADGET`).

---

## El plan de arquitectura (v1): alcance

| Incluido en v1 | Fuera de alcance |
| --- | --- |
| SSN por FreshyCalls (sort-by-VA) | Direct syscalls como mecanismo de producción |
| Gadget `syscall;ret` validado | Stack/call-stack spoofing |
| Trampolín MASM por función | Sleep obfuscation / cifrado |
| Wrappers C tipados | VEH + hardware breakpoints |
| PEB walk, DJB2, logging, rangos | Unhooking / ntdll limpio desde KnownDlls |
| Harness determinista + cdb | x86, WoW64, ARM64 |
| Verificación de `RIP` dentro de ntdll | Inyección de procesos / payloads |

Acotar el problema es lo que hace que la solución sea **verificable**. Cada cosa fuera de
alcance se documenta para no dar falsas expectativas.

---

## Workflow de depuración por línea de comandos

La verificación no es "ejecutar y mirar": es un **protocolo** reproducible con `cdb`.

```text
# Ejecucion con script y transcript de la sesion
cdbX64 -cf tools\cdb_scripts\m1_exports.txt -logo docs\evidencias\m1.txt bin\Kagemusha.exe

# Simbolos
.symfix
.reload /f Kagemusha.exe

# Inspeccion clave (el "corazon" de la practica)
x ntdll!NtClose          ; VA del stub real
uf ntdll!NtClose         ; ver "mov eax, <SSN>"
db <gadget> L3           ; ver "0f 05 c3"
r @eax @r10 @rcx @rip    ; EAX=SSN, R10=arg1, RIP=gadget
lm m ntdll               ; rango de ntdll -> RIP dentro?
? @rip - ntdll           ; offset de RIP respecto a la base
dps @rsp L4              ; pila: a donde apunta el retorno
```

Cada script vive en `tools/cdb_scripts/` y genera un transcript en `docs/evidencias/`. Así, el
resultado de hoy se puede **reproducir** mañana, en la misma build.

### Checklist de verificación (por fase)

- [ ] El binario compila con **PDB completo** y los `bp` simbólicos funcionan.
- [ ] `UtlGetExportByHash("NtClose")` == `GetProcAddress` (oráculo).
- [ ] El SSN de FreshyCalls == SSN del stub real (oráculo).
- [ ] El gadget tiene bytes `0F 05 C3` **y** cae en `.text` de `ntdll`.
- [ ] La suite sale **0 FAIL** y el transcript queda archivado.

---

## Errores comunes (resumen de las fases 0–3)

- **Sin PDB, sin evidencia.** Los `bp` simbólicos fallan y no puedes verificar nada.
- **Hash o filtro mal hechos** desplazan el índice de SSN y **todas** las syscalls fallan.
- **Ordenar mal por VA** invalida el invariante de FreshyCalls.
- **No validar el gadget** (bytes + rango + no-hook) abre la puerta a crashes.
- **Hardcodear SSN** "porque ya lo sé" es la trampa clásica: rompe en la próxima build.
- **No registrar la build** hace irreproducible cualquier resultado.

---

## 🧪 Experimenta tú — compila y mira los símbolos

*(Nivel 🟡. Requiere VS Build Tools + `cdb`.)*

```text
tools\build.cmd                              :: compila (genera .exe + .pdb)
bin\Kagemusha_tests.exe                      :: corre la suite (esperado: 0 FAIL)
bin\Kagemusha.exe                            :: selftest M0..M5
cdbX64 -cf tools\cdb_scripts\m1_exports.txt -logo docs\evidencias\m1.txt bin\Kagemusha.exe
```

**Qué deberías ver (m1):** la dirección de `ntdll!NtClose` resuelta por nuestro PEB walk y la
misma resuelta por el símbolo de Microsoft, **idénticas** (diferencia `0`). Esa igualdad es la
prueba de la Fase 1.

> **Mini-reto:** cambia a propósito el hash de `NtClose` por otro y observa cómo el test **falla**
> (o resuelve un export equivocado). Ver el fallo es entender por qué el oráculo importa.

---

## Fondo: cómo es una cabecera PE (por qué leemos "a mano")

Para resolver exports sin `GetProcAddress`, hay que recorrer el archivo/DLL a bajo nivel. Un PE
(Portable Executable) tiene capas:

```text
+------------------+  <- inicio
| DOS header       |   e_magic ("MZ"), e_lfanew -> apunta a la cabecera NT
+------------------+
| NT headers       |   FileHeader + OptionalHeader (SizeOfImage, secciones...)
+------------------+
| Section headers  |   .text, .rdata, .data... (cada una con su RVA y tamaño)
+------------------+
| .text            |   codigo
| .rdata           |   import/export directories
| .data            |   datos
+------------------+
```

- **`e_lfanew`** dice **dónde** empieza la cabecera NT. Un valor absurdo (malicioso o corrupto)
  llevaría a leer "fuera del archivo" → por eso el proyecto **valida** ese offset.
- El **export directory** (en `.rdata`) lista los nombres y sus **RVAs**; para ordenar por
  **dirección virtual** (FreshyCalls) necesitamos `SizeOfImage` y la base del módulo.

Entender esto explica **por qué** la Fase 6 hace fuzz del parser: un PE malformado es una
*vulnerabilidad* si confías en él a ciegas.

---

## Fondo: el PEB y la lista de módulos

El **PEB** es la estructura del proceso que mantiene el kernel. Nos interesa sobre todo la lista
de módulos cargados (`PEB->Ldr->InLoadOrderModuleList`), que es una **lista doblemente enlazada**
de entradas `LDR_DATA_TABLE_ENTRY`:

```text
PEB
 └─ Ldr
     └─ InLoadOrderModuleList  <-> [ ntdll ] <-> [ kernel32 ] <-> [ kernelbase ] <-> ...
```

Cada nodo tiene `BaseDllName` (el nombre) y `DllBase` (la dirección base). Nuestro walker la
recorre **comparando hashes** en lugar de cadenas. ¿Por qué `InLoadOrder` y no otra lista?
Porque el orden de carga es estable y predecible, y `ntdll` suele estar entre los primeros.

---

## Bibliografía y referencias

- Russinovich, Solomon, Ionescu — *Windows Internals, 7.ª ed.* (PEB, Ldr, export directory).
- Microsoft Learn — *PEB/Ldr structures*, *PE format*, *x64 calling convention*.
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`).
- am0nsec & smelly__vx — *Hell's Gate* (`github.com/am0nsec/HellsGate`); Sektor7 — *Halo's Gate*.
- thefLink — *RecycledGate* (`github.com/thefLink/RecycledGate`).
- Fuentes primarias: `docs/evidencias/m0..m3.txt`, `tools/cdb_scripts/`.

> Aprender a romper para poder defender.
