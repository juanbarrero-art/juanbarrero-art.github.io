---
title: "Guía completa: syscalls en Windows para investigadores"
date: 2026-09-29
tags: guia, windows internals, syscalls, principiantes, malware
serie: Kagemusha
summary: Guía extensa de system calls de Windows para investigadores de malware: modelo de memoria y privilegios, la cadena kernel32/ntdll/kernel, anatomía del stub, SSN y SSDT, objetos y NTSTATUS, syscalls directas e indirectas, hooks y EDR, técnicas de resolución de SSN, cómo observarlo tú mismo con cdb, errores comunes y glosario.
---

# Guía completa: syscalls en Windows para investigadores

Esta guía es el **punto de partida** de la serie [Kagemusha](/blog/serie/kagemusha.html). Está
escrita para **investigadores de malware y Windows internals** que quieren entender *de verdad*
qué pasa cuando un programa le pide algo al sistema, y por qué esa frontera es el campo de
batalla entre atacantes y defensas. No asumimos experiencia previa: construimos las ideas desde
cero, con analogías, diagramas y código.

> Meta: que al terminar puedas leer las siguientes entradas de la serie **entendiendo cada
> término**, y que sepas **observar** una syscall por ti mismo con un debugger, no solo creer lo
> que te cuentan.

---

## 1. Por qué esto importa (sobre todo si analizas malware)

Casi todo lo interesante que hace un programa en Windows —abrir un archivo, crear un proceso,
leer memoria, conectarse a la red— termina, tarde o temprano, en una **system call**: una
petición al **kernel**. Para quien analiza malware, este es *el* punto clave:

- **Un EDR** pone trampas aquí (los famosos *hooks*) para ver qué pide cada proceso.
- **El malware moderno** intenta evitar esas trampas usando syscalls "a pelo".
- **Tú, como analista**, necesitas entender lo uno para entender lo otro: cómo se llama a una
  syscall, cómo se oculta una llamada y **cómo se detecta**.

En pocas palabras: si entiendes las syscalls, entiendes la línea del frente. Todo lo demás
(PE, ofuscación, inyección) son vehículos; el objetivo final suele ser **ejecutar una syscall**
que el defensor no vea.

---

## 2. El gran muro: user-mode y kernel-mode

Windows separa el código en dos mundos con privilegios muy distintos:

- **User-mode (modo usuario):** donde corren tus programas (`.exe`, navegador, juegos).
  Está **aislado**: no puede tocar hardware ni la memoria de otros procesos. Un bug aquí, en el
  peor caso, solo tumba tu programa.
- **Kernel-mode (modo kernel):** donde vive el corazón del sistema (`ntoskrnl.exe`). Tiene
  **privilegios totales**: maneja memoria, procesos, disco, red. Un bug aquí **tumba el sistema**
  (la temida *pantalla azul*).

Esta separación no es capricho: es lo que hace que un programa mal escrito no pueda formatear
tu disco sin permiso. La CPU lo implementa con niveles de privilegio (los *rings*; Windows usa
el ring 3 para user-mode y el ring 0 para kernel). El paso de uno a otro se llama **transición**,
y es relativamente **caro** (guardar/restaurar contexto), por lo que el diseño del sistema
minimiza las transiciones.

### Memoria virtual, en una frase

Cada proceso cree que tiene toda la memoria para sí mismo: eso es la **memoria virtual**. El
kernel mantiene las traducciones dirección-virtual → dirección-física. Cuando un programa "toca
memoria", el hardware consulta esas tablas. Esta indirección es la que permite aislar procesos
y también la que hace que los *punteros* sean "virtuales" (nunca físicos). Nos importará porque
muchas técnicas manipulan **direcciones virtuales** (VAs): la de un stub, la de un gadget, etc.

---

## 3. La cadena de capas: de `CloseHandle` a la syscall

Cuando en C llamas a una función "normal" de Windows, ocurre una cadena de capas. Ejemplo con
`CloseHandle`:

```text
CloseHandle()        -> kernel32.dll   (API Win32, "cara amable")
      |
      v
NtClose()            -> ntdll.dll      (capa nativa)
      |
      v
syscall              -> transicion a KERNEL
      |
      v
Kernel: NtClose      -> ntoskrnl.exe   (hace el trabajo real)
```

- **`kernel32.dll` (`CloseHandle`)** es la **API de alto nivel**: cómoda, documentada, estable.
- **`ntdll.dll` (`NtClose`)** es la **capa nativa**: funciones que empiezan por `Nt*`. No está
  pensada para que la llames directamente, pero es la **puerta real** al kernel.
- **La instrucción `syscall`** es el "salto" físico al kernel.

> Clave: **casi todo** lo que hace Windows termina, tarde o temprano, en una función `Nt*` de
> `ntdll` y en una instrucción `syscall`. Esa es la razón por la que los defensores miran ahí.

---

## 4. El stub: anatomía de la puerta

En `ntdll`, cada función `Nt*` tiene un pequeño fragmento de código (un **stub**, "trozo"). En
Windows x64 se ve así (simplificado):

```asm
ntdll!NtClose:
    mov  r10, rcx          ; copia el 1er argumento a R10
    mov  eax, 0x0F         ; 0x0F = numero de servicio (SSN)
    syscall                ; <-- entra al kernel
    ret                    ; <-- vuelve al que llamo
```

Tres cosas importantes:

1. **`mov r10, rcx`**: en la convención de syscall de x64, el primer argumento va en `R10`. ¿Por
   qué no `RCX`? Porque la propia instrucción `syscall` **usa `RCX` para guardar la dirección de
   retorno**. Por eso el stub copia el argumento de `RCX` a `R10`.
2. **`mov eax, 0x0F`**: carga en `EAX` el **número de servicio** (SSN). Aquí `0x0F` = `NtClose`.
3. **`syscall`**: la instrucción real que cruza al kernel. En bytes es **`0F 05`**. Tras el
   `syscall` (y el trabajo del kernel), un `ret` devuelve el control a quien llamó.

En los stubs reales, entre el `mov eax, SSN` y el `syscall` puede haber un pequeño chequeo
(`test`/`jne`) relacionado con la ruta rápida de llamada del sistema (`KiFastSystemCall`). El
patrón de bytes del prólogo —`4C 8B D1 B8 <SSN>`— es tan estable que se usa como **huella** para
reconocer stubs de syscall (y para detectar cuándo un EDR los ha modificado).

---

## 5. El SSN y la SSDT: el "número de mesa"

El kernel no identifica las funciones por nombre, sino por un **número**: el **SSN** (System
Service Number). Es como el número de mesa en un restaurante: el mesero no grita tu nombre,
grita "¡mesa 15!".

En el kernel, la **SSDT** (System Service Dispatch Table) es una tabla indexada por ese número.
`syscall` con `EAX = 0x0F` va a `SSDT[0x0F]` → `NtClose`.

El detalle **crucial**:

> **El SSN de una función cambia según la versión/build de Windows.**

Es decir: `NtClose` puede ser `0x0F` en una build y otro número en la siguiente. Por eso **no
puedes** confiar en un número escrito "a fuego" (hardcodeado): hay que **resolverlo en runtime**.
Toda la serie gira, en gran parte, alrededor de **cómo resolver el SSN de forma fiable**.

---

## 6. Objetos, handles y NTSTATUS (el "qué" de las syscalls)

Las funciones `Nt*` no operan sobre "cosas" abstractas, sino sobre **objetos** del kernel
(procesos, hilos, archivos, claves de registro, secciones de memoria…). En user-mode accedes a
ellos mediante **handles**: números pequeños que actúan como entradas en una tabla privada de tu
proceso. Un handle **no** es el objeto; es una referencia a él.

Y las funciones `Nt*` no devuelven "éxito/fracaso" a lo `bool`, sino un **`NTSTATUS`**: un
código de 32 bits (`0` = éxito; `0xC0000008` = `STATUS_INVALID_HANDLE`; etc.). Es más preciso
que el `GetLastError` de la API Win32, y es lo que verás cuando llames a `Nt*` directamente.

> Por eso, cuando en la serie invocamos `NtClose_I(0xDEADBEEF)` y obtenemos `0xC0000008`,
> estamos viendo el **`NTSTATUS` real del kernel**: la prueba de que el viaje funcionó.

---

## 7. Syscall directa vs. indirecta

Ahora el corazón del asunto. Hay dos formas de "saltar" al kernel desde tu propio código.

### Syscall directa (direct syscall)

Tu **propio** módulo contiene la instrucción `syscall`:

```asm
; dentro de TU binario
mov  r10, rcx
mov  eax, SSN
syscall          ; <-- 0F 05 EN TU MODULO
ret
```

Funciona, pero deja una **firma**: una instrucción `0F 05` dentro de **tu** ejecutable. Un
analista (o un EDR) que inspeccione tu binario la verá y dirá: "este programa ejecuta syscalls
por su cuenta".

### Syscall indirecta (indirect syscall)

Tu módulo **no** contiene `syscall`. En su lugar, **salta** a un fragmento `syscall;ret`
que **ya vive dentro de `ntdll`**:

```asm
; dentro de TU binario
mov  r10, rcx
mov  eax, [ssn]        ; SSN resuelto en runtime
jmp  [gadget]          ; gadget = syscall;ret que esta en ntdll
```

Así, la instrucción `syscall` **se ejecuta dentro de `ntdll`** (memoria legítima). Es la idea del
"doble" que da nombre a **Kagemusha** (影武者, *guerrero sombra*): el doble actúa en lugar del
original.

---

## 8. ¿Por qué importa? Hooks y EDR

Un **EDR** (Endpoint Detection and Response) es un antivirus "de nueva generación" que observa
el comportamiento. Sus fuentes de telemetría incluyen:

- **Hooks en user-mode:** modifica el **principio de los stubs `Nt*`** en `ntdll` (un `jmp`, en
  bytes `E9` o `FF 25`). Cuando tu programa llama a `NtClose`, primero corre el código del EDR.
- **Callbacks del kernel:** el kernel notifica a los drivers registrados ciertos eventos
  (creación de proceso/hilo, carga de imagen, operaciones de archivo/registro).
- **ETW (Event Tracing for Windows):** un sistema de trazas donde el kernel y otros componentes
  emiten eventos que el EDR puede consumir.

Si llamas a `NtClose` normal, pasas por el hook. Las syscalls (directas o indirectas) **evitan
los hooks de user-mode** porque no ejecutan el código del stub que fue modificado.

> **Honestidad:** esquivar hooks de user-mode **no** te vuelve invisible. El kernel sigue viendo
> la llamada y hay más telemetría. La serie **mide** esa visibilidad en vez de ignorarla.

---

## 9. Resolver el SSN: el panorama de técnicas

Para la syscall indirecta necesitas el SSN. Hay varias técnicas conocidas:

| Técnica | Idea | ¿Lee bytes del stub? | ¿Inmune a hooks user-mode? |
| --- | --- | --- | --- |
| Hardcodear SSN | Poner el número "a fuego" | No | Rompe entre builds |
| **Hell's Gate** | Leer `mov eax, SSN` del stub | **Sí** | **No** |
| **Halo's Gate** | Como Hell's, pero "cuenta vecinos" si está hookeado | **Sí** (heurística) | Parcial |
| **FreshyCalls** | Ordenar exports `Nt*` por VA; el índice es el SSN | **No** | **Sí** |
| LayeredSyscall / VEH | Resolver vía *Exception Directory* | No | Sí (más frágil) |

Kagemusha elige **FreshyCalls**: no lee el stub, así que modificarlo (hook) **no la afecta**.
El invariante que explota es que, en Windows 10/11, los stubs `Nt*` están en `.text` **en el
mismo orden que sus SSN**; por tanto, el índice del export ordenado por dirección **es** el SSN.

---

## 10. El gadget `syscall;ret`

Para la ejecución indirecta necesitas un fragmento que ya contenga `syscall` seguido de `ret`
(bytes **`0F 05 C3`**) y que esté en una zona ejecutable legítima, como `.text` de `ntdll`. Ese
fragmento se llama **gadget**. Es **agnóstico del SSN**: sirve para cualquier syscall, porque el
número viaja en `EAX`. Localizar uno válido y comprobar que está dentro de `ntdll` es parte del
trabajo (y se verifica con bytes reales).

---

## 11. Cómo observarlo tú mismo (con `cdb`)

Una de las mejores formas de aprender es **verlo**. Con `cdb` (Debugging Tools for Windows):

```text
# Ver el stub real de NtClose (y su SSN)
uf ntdll!NtClose
ntdll!NtClose:
  mov r10, rcx
  mov eax, 0Fh         ; <-- SSN real
  ...

# Buscar la instruccion syscall (0F 05) dentro de ntdll
s -a ntdll L? 0f05

# En un breakpoint en el gadget: comprobar que el RIP cae dentro de ntdll
lm m ntdll
? @rip - ntdll
```

Estos comandos son exactamente los que usa la serie para **verificar** cada afirmación. Si algo
de esto te parece "magia", deja de parecerlo en cuanto lo ves con tus ojos.

---

## 13. Glosario

| Término | Significado |
| --- | --- |
| **user-mode** | Modo aislado donde corren tus programas |
| **kernel-mode** | Modo privilegiado del núcleo de Windows |
| **transición** | Paso controlado de user a kernel |
| **syscall** | Instrucción (`0F 05`) que cruza de user a kernel |
| **ntdll** | DLL nativa con las funciones `Nt*` |
| **stub** | Trozo de código en `ntdll` que prepara la syscall |
| **SSN** | Número de servicio; indexa la SSDT del kernel |
| **SSDT** | Tabla del kernel que mapea SSN → función |
| **NTSTATUS** | Código de retorno preciso del kernel |
| **handle** | Referencia a un objeto del kernel |
| **hook** | Desvío de código (p. ej. por un EDR) |
| **EDR / ETW** | Seguridad de endpoint / sistema de trazas |
| **direct syscall** | `syscall` ejecutado en tu propio módulo |
| **indirect syscall** | `syscall` ejecutado dentro de `ntdll` |
| **FreshyCalls** | Resolver SSN ordenando exports por VA |
| **gadget** | Fragmento `syscall;ret` reutilizable |

---

## 14. Riesgos, ética y defensa

Entender esto sirve **para defender**: quien no comprende la técnica no puede detectarla. La
serie documenta **cómo se ve** desde fuera para que la comunidad defensiva tenga criterios:

- Practica **solo** en máquinas virtuales aisladas y con snapshots.
- No publiques muestras ni binarios utilizables; publica **conocimiento** y **detección**.
- Documenta y verifica: una afirmación sin prueba es solo una opinión.

---

## 15. Cómo sigue la serie

1. **Guía de syscalls** (esta entrada) — contexto para principiantes e investigadores.
2. [Visión general, tesis y metodología](/blog/kagemusha-indirect-syscalls.html) — el proyecto completo.
3. [Fases 0 a 3: del toolchain al gadget](/blog/kagemusha-fases-0-3.html).
4. [Fase 4: ejecución indirecta real](/blog/kagemusha-fase-4-ejecucion-indirecta.html).
5. [Fase 5: generalización y aridad](/blog/kagemusha-fase-5-generalizacion.html).
6. [Fase 6: robustez, hooks y límites](/blog/kagemusha-fase-6-robustez.html).
7. [Fase 7 y baterías (T19–T22): ledger, CLI y CET](/blog/kagemusha-fase-7-baterias-cet.html).
8. [Visibilidad y evasión (Defender, E2, E3, E4c)](/blog/kagemusha-visibilidad-evasion.html)

---

## 🧪 Experimenta tú (nivel 🟢): encuentra al "mesero"

No hace falta programar. Vamos a **ver** las piezas de las que hablamos.

1. **Localiza `ntdll.dll`.** Abre esta carpeta y busca el archivo:
   `C:\Windows\System32\ntdll.dll` (suele pesar ~2 MB). Es la DLL que contiene las funciones
   `Nt*`; el "mesero" del que hablaremos todo el rato.
2. **Mira qué DLLs carga un proceso** con **Process Explorer** (Sysinternals): abre el Bloc de
   notas y, en Process Explorer, dale a *View → Lower Pane → DLLs*. Verás `ntdll.dll` en la
   lista: **todos** los procesos la cargan, siempre.
3. **Mira sus peticiones** con **Process Monitor** (Sysinternals): guarda un archivo con el Bloc
   de notas y observa los eventos `CreateFile`, `WriteFile`, `CloseFile`. Esas son las
   "comandas" al kernel.

**Qué deberías concluir:** todo programa **pide cosas** a Windows, y esas peticiones pasan por
`ntdll.dll`. Ya tienes el 80% del mapa mental de esta guía.

---

## El mapa de herramientas

A medida que avances, estas son las herramientas que verás una y otra vez:

| Herramienta | Para qué sirve | Nivel |
| --- | --- | --- |
| **Process Monitor** (Procmon) | Ver operaciones en vivo (archivos, registro, red) | 🟢 |
| **Process Explorer** | Ver procesos, handles y **DLLs cargadas** | 🟢 |
| **Process Hacker / System Informer** | Alternativa potente a Process Explorer | 🟡 |
| **WinDbg / cdb** | Ver el `syscall` a nivel de instrucción (lo usamos en la serie) | 🔴 |
| **Dependencies / PE-bear / CFF Explorer** | Inspeccionar un `.exe`/`.dll` estáticamente | 🟡 |
| **x64dbg** | Depurar en vivo con interfaz gráfica | 🟡 |

Empieza con las dos primeras; con ellas ya "ves" los conceptos. El debugger dejalo para cuando
quieras bajar al detalle.

---

## Cómo está organizada la API de Windows

Un detalle que confunde a muchos: `kernel32.dll` **no** es "la" API del sistema. En Windows
moderno, la capa cómoda está partida:

```text
kernel32.dll      ->  la "cara" clasica (CloseHandle, CreateFile...)
kernelbase.dll    ->  gran parte de la implementacion real en user-mode
ntdll.dll         ->  la capa nativa Nt* (la que habla con el kernel)
```

- **`kernel32`** reenvía muchísimas funciones a **`kernelbase`** (y algunas a `ntdll`).
- **`ntdll`** contiene las funciones **`Nt*`** (syscalls) y **`Rtl*`** (rutinas de runtime).
- Por eso decimos que **casi todo termina en `ntdll`**: es la última capa antes del kernel.

Saber esto te permite leer mejor los *stack traces*: si ves `KERNELBASE!...` → `ntdll!Nt...`, ya
sabes que el programa está en la antesala del kernel.

---

## Preguntas frecuentes (principiantes)

**¿Necesito saber ensamblador (ASM) para entender la serie?** Para la guía y las primeras
entradas, no. Para las fases 4–7, ayuda: leerás `mov`, `jmp`, `ret`. Aun así, todo va explicado.

**¿Puedo romper mi PC?** La serie trabaja en una **máquina virtual aislada**. No ejecutes nada de
esto en tu equipo de trabajo.

**¿Es legal?** Esto es **investigación educativa y defensiva** en tu laboratorio. El objetivo es
**entender para detectar**, no atacar a nadie.

**¿Por dónde empiezo?** Misión 0 → esta guía → Visión general. Luego, si quieres, las fases.
*(Enlaza: [Cómo leer la serie + Misión 0](/blog/como-leer-serie-mision-0.html).)*

**¿Qué pasa si un EDR me bloquea los experimentos?** Es **parte del juego**: ese bloqueo es
información. La serie mide esa visibilidad en la Fase 8.

---

## 16. Bibliografía y referencias

**Documentación oficial**
- Microsoft Learn — *Ntdll*, *System Calls*, *Register usage / x64 calling convention* (`learn.microsoft.com/windows/win32/`).
- Russinovich, Solomon, Ionescu — *Windows Internals, 7.ª ed.* (Microsoft Press): kernel, SSDT, transición.

**Investigación y herramientas**
- am0nsec & smelly__vx — *Hell's Gate* (`github.com/am0nsec/HellsGate`).
- Sektor7 — *Halo's Gate*.
- crummie5 — *FreshyCalls* (`github.com/crummie5/FreshyCalls`): sort-by-VA.
- thefLink — *RecycledGate* (`github.com/thefLink/RecycledGate`).
- MDSec — *LayeredSyscall*.
- jthuraisamy — *SysWhispers* (`github.com/jthuraisamy/SysWhispers`).

**Detección y defensa**
- Microsoft Learn — *ETW* y *Windows Defender Application Control*.

> Aprender a romper para poder defender.
