---
title: "Kagemusha F10 — Contra-instrumentación: encadenar, filtrar y medir el callback de un EDR"
date: 2026-10-13
tags: kagemusha, edr, evasion, instrumentation callback, windows internals, syscalls, research
serie: Kagemusha
orden: 16
summary: Fase 10 del proyecto Kagemusha. Reversamos el ProcessInstrumentationCallback, construimos un shim zero-clobber que encadena al callback del EDR sin romperlo, filtramos por pila ([rsp]) los syscalls propios (100→0 sin colaterales), añadimos una sonda de liveness para la guerra de punteros y medimos el delta kernel-vs-callback (100) que delata la manipulación ante un EDR que fusione fuentes. Con errores encontrados, límites declarados y reproducción.
---

# Kagemusha F10 — Contra-instrumentación: encadenar, filtrar y medir el callback de un EDR

Hay un momento en cualquier investigación en el que dejas de preguntarte *"¿cómo esquivo esto?"* y empiezas a preguntarte *"¿esto que creía intocable, lo es de verdad?"*. La Fase 10 de **Kagemusha** nació exactamente así: la fase anterior había terminado con una lista de "techos estructurales" —sensores que, decíamos, no se podían cegar desde user-mode— y uno de ellos arrastraba una sospecha incómoda. No había ingeniería inversa detrás de esa clasificación. Era una **inferencia**. Y las inferencias, en este proyecto, se auditan.

Este artículo cuenta la Fase 10 completa: **qué es el `ProcessInstrumentationCallback` de Windows**, por qué los EDR lo usan, cómo lo reversamos (`E10.1`), cómo construimos un *probe* para detectarlo (`E10.2`), cómo montamos un **shim zero-clobber** que **encadena** al callback del EDR sin romperlo (`E10.3`), cómo **filtramos selectivamente por pila** los syscalls del mecanismo (`E10.4`), cómo añadimos una **sonda de liveness** para la guerra de punteros (`E10.5`) y cómo medimos el **delta kernel-vs-callback** que delata la manipulación ante un EDR que sepa fusionar fuentes (`E10.5.3`).

Con números medidos, con los errores que encontramos por el camino y con los límites bien marcados. Como siempre en esta serie: **un informe sin límites es publicidad**.

## Resumen ejecutivo (para quien tiene prisa)

- **Qué se consiguió:** un proceso puede descubrir si un tercero instaló un instrumentation callback, **encadenarse** a él (el EDR sigue viendo el **100 %** de los syscalls, sin notar nada), **filtrar** después solo los syscalls de Kagemusha (`100 → 0` con **0 colaterales** en las llamadas legítimas), **detectar en ≤ 1 syscall** que le han robado el slot y **reinstalarse**, todo desde **user-mode**, sin hooks y sin una sola instrucción `syscall` propia.
- **Qué NO se consiguió (y se dice):** un EDR que **fusione** la telemetría de kernel con su callback ve un hueco de **delta = 100** entre lo que el kernel contó y lo que su callback reportó. Ese silencio es la señal de manipulación. El techo real no desaparece: se **mueve**.
- **Corrección al modelo propio:** la Fase 9 clasificó este sensor como *"techo estructural, no cegable desde user-mode"*. La Fase 10 demuestra que esa clasificación era **incorrecta**: S5 pasa de techo absoluto a **plano reducible con techo residual de fusión**.
- **Suite del proyecto:** **440 PASS / 0 FAIL** (build stealth) y **407 PASS / 0 FAIL** (build CET); **0 instrucciones `syscall`** en los binarios propios; 0 detecciones de Defender sobre el mecanismo.
- **Estado:** Fase 10 cerrada (M10), commits `b88c3f6` → `9a69741` en `main`.

## 1. La grieta en un techo

### 1.1 Qué había dicho la Fase 9

Para situarnos. La [Fase 9](/blog/serie/kagemusha.html) del proyecto construyó una capa de ejecución de blobs con "señal mínima" y, al cerrar, publicó una **matriz de señal**: 9 sensores de EDR cruzados con 8 pasos del ciclo de ejecución (resolver, planificar, asignar, escribir, proteger, transferir, ejecutar, limpiar). Cada celda se midió **antes → después** y se clasificó: reducible, techo estructural, o "requiere capa conducta".

De aquella matriz quedaron **4 celdas `=2`** declaradas **techo estructural**, es decir, insumos de regla que no se pueden eliminar desde user-mode:

| Celda | Sensor | Qué la producía |
|---|---|---|
| S5 @ E5/E6 | Instrumentation callback del EDR | Ve **todos** los syscalls, incluidos los indirectos |
| S4 @ E5/E6 | Scanner/walk de pila | Retorno a mitad del stub de ntdll + caller = módulo propio |
| S6 | ETW-TI del kernel | Telemetría de kernel sobre memoria/hilos |
| S8 | Callbacks de kernel | Plano no observable desde el proceso |

La justificación de S5 en el documento era una frase: *"el callback del EDR ve todos los syscalls (incl. indirectos), retorno en R10; no cegable desde user-mode"*. Y aquí está el problema: **esa segunda cláusula nunca se había reversado**. No sabíamos quién escribe el slot, si se puede leer, si se puede encadenar, qué ve exactamente el callback ni cuándo. Era un techo heredado de una suposición razonable, pero suposición al fin y al cabo.

Además había una contradicción interna en el propio repo: la Fase 9 ya había demostrado que **`KageClearInstrumentationCallback` funciona**, es decir, que un proceso **sí puede escribir su propio slot** vía `NtSetInformationProcess`. Teníamos la primitiva de escritura en casa y, aun así, habíamos clasificado el sensor como inalcanzable.

### 1.2 La hipótesis

La Fase 10 parte de un principio que el propio marco teórico del proyecto ya tenía escrito: **un sensor de user-mode que vive dentro del proceso observado es ciego ante un atacante que controla su propio proceso**. Y el instrumentation callback cumple esa condición de principio a fin: el puntero vive en la estructura del proceso, el código suele vivir en una DLL inyectada por el EDR, y el despacho ocurre al volver del syscall, en user-mode.

La hipótesis, por tanto: **si el sensor vive en el proceso, se puede auditar, encadenar y filtrar**. No se trataba de eliminar el techo real (ETW-TI y callbacks de kernel siguen ahí), sino de demostrar con medición que **S5 pertenece al plano reducible** y reescribir la clasificación.

### 1.3 La analogía, antes de bajar al detalle

En la entrada [¿Por qué la evasión es en capas?](/blog/kagemusha-articulo-por-que-evasion-capas.html) usamos una casa con cámaras. Sigamos con esa imagen, porque el instrumentation callback encaja perfecto:

- Tu programa es una casa. Cada vez que necesitas algo del "ayuntamiento" (el kernel), pasas por la **puerta principal** (el syscall).
- El EDR quiere saber **qué pides**. Para eso no basta con mirar desde fuera: coloca una **cámara dentro de tu casa**, en el pasillo de salida de la puerta. Cada vez que vuelves del ayuntamiento, la cámara graba qué pediste y qué te contestaron.
- Esa cámara es el **instrumentation callback**. No es un hook: es una **redirección legítima** que Windows ofrece. Por eso la Fase 1 del proyecto (indirect syscalls) no la evita: el `syscall` ocurre dentro de `ntdll`, sí, pero la cámara graba **al volver**, no al salir. Da igual por qué puerta salgas: la cámara está en el pasillo de vuelta.

Y aquí viene lo interesante de la Fase 10: si la cámara está **dentro de tu casa**, tú puedes poner delante de ella tu propia cámara intermedia que:

1. **Deje pasar la señal original** (que la cámara del EDR siga grabando todo, exactamente igual: transparencia).
2. **Decida qué no se graba** (filtrar solo los pedidos que hacen los "empleados" del mecanismo, no todos).
3. **Detecte si alguien la desenchufó** (liveness).
4. **Asuma que el ayuntamiento tiene su propio registro** y que, si alguien compara, el hueco se ve (delta de fusión).

Las cuatro piezas son las cuatro secciones centrales de este artículo. Antes, dos fundamentos imprescindibles: **qué es exactamente el callback** (contrato) y **cómo trabaja este proyecto** (metodología).

## 2. El sensor: qué es el `ProcessInstrumentationCallback`

### 2.1 El mecanismo

Windows permite que **cada proceso** tenga un callback de instrumentación. Se instala con una clase de información de proceso:

```c
NtSetInformationProcess(
    NtCurrentProcess(),
    ProcessInstrumentationCallback,   /* clase 0x28 */
    &CallbackAddress,
    sizeof(CallbackAddress));
```

Cuando ese puntero está puesto, el kernel deja de devolver el control directamente al user-mode al terminar **cada syscall**. En su lugar, redirige la ejecución a tu callback **en modo usuario** y con el estado del retorno intacto. Cuando tu callback termina (saltando a `R10`, que contiene la dirección de retorno efectiva), el hilo continúa como si nada.

Esto no es un hook ni un parche: es una **funcionalidad documentada y soportada por el sistema operativo**. Ese detalle es el que hace al sensor tan atractivo para un EDR y, a la vez, tan interesante para nosotros: vive en el proceso observado.

### 2.2 El contrato de dispatch (lo que el callback recibe)

La Fase 10 invirtió sesiones enteras de depurador en formalizar el contrato exacto, registro a registro. La tabla siguiente está medida con `cdb` sobre la build de referencia (Windows 11, build 26100) y es la base de todo el diseño posterior:

| Registro | Contenido observado | Semántica verificada |
|---|---|---|
| `RAX` | `0` / `0xC0000008` | **NTSTATUS** de retorno del syscall |
| `R10` | `ntdll!stub+2` | **RIP de retorno efectivo** (el `ret` del gadget; o el dispatcher de excepciones) |
| `RCX` | dirección del propio callback | **no es el RCX del usuario**: es la dirección del callback instalado |
| `R8` | igual a `RSP` | **RSP del usuario** en el punto del syscall |
| `R11` | igual a `RFLAGS` (`0x246`) | **RFLAGS** del usuario |
| `RDX` / `R9` | `0` | machacados por el dispatch (no fiables) |
| `RBX`, `RBP`, `RSI`, `RDI`, `R12`–`R15` | valores del hilo | contexto de usuario **preservado** |
| `RSP` | pila de usuario | **sin frame de kernel**: `[rsp]` es el call-site original, intacto |
| `CS` / `SS` / `FS` / `GS` | `0x33` / `0x2b` / `0x53` / TEB | modo usuario, TEB accesible vía `gs:` |

Dos consecuencias que parecen detalles y lo cambian todo:

1. **El callback corre con la pila del usuario intacta.** Eso significa que puede leer `[rsp]` y saber *desde dónde* se llamó al syscall (el call-site). Es la materia prima del filtrado selectivo.
2. **`RCX` no es un registro libre.** Es parte del contrato: el kernel lo entrega apuntando al callback. Un shim que lo modifique rompe el proceso anfitrión. Esto lo aprendimos de la peor manera (ver §5.4).

### 2.3 Por qué un EDR lo usa (y por qué la Fase 1 no bastaba)

Un EDR con este callback consigue algo que los hooks de `ntdll` no le dan:

- **Ve todos los syscalls**, incluidos los **indirect syscalls** como los de Kagemusha. La Fase 1 del proyecto ([Visibilidad y evasión](/blog/kagemusha-visibilidad-evasion.html)) ya midió esto: el hook inline se evita con FreshyCalls, pero el callback ve el indirecto igual.
- **Ve el retorno** (`RAX`) y **puede reconstruir nombre y argumentos** del syscall: la pila del usuario sigue conteniendo los argumentos, y con `NtQueryInformationThread(ThreadLastSystemCall)` se puede mapear el SSN a la función. Nuestro propio observador (`E2`, `--instrument`) lo hace exactamente así.
- **No depende de que el atacante use los stubs**: aunque salgas por una "puerta lateral", la cámara del pasillo de vuelta graba.
- **Es silencioso y barato**: unas pocas instrucciones por syscall, sin tocar código ajeno.

La técnica pública existe en dos linajes que el proyecto reconoce y cita en el código:

- **x86matthew — InstrumentationCallbackSyscallLogger** (MIT): el logger de syscalls que el proyecto portó como observador propio (`src/core/instrument.c`).
- **paranoidninja — Process-Instrumentation-Syscall-Hook (`etwti-hook`)**: el callback que lee el número de syscall desde `[r10-0x10]` y decide con un pequeño prólogo en ASM. El proyecto lo usa como **EDR-simulado** (el harness `AVA`, `--avatest/--cbava`) y como detector de referencia.

### 2.4 El ciclo de vida del slot: "el último que escribe gana"

El puntero del callback vive en una única ranura ("slot") por proceso. No hay cola, no hay notificación, no hay contrato de exclusividad:

- Instalar cuando ya había otro **sustituye en silencio** al anterior. El callback viejo deja de ejecutarse sin enterarse.
- Re-afirmar el mismo puntero es inocuo (el kernel no avisa, pero tampoco pasa nada).
- Ponerlo a `NULL` lo desactiva. La Fase 9 ya lo hacía desde user-mode.

Ese comportamiento explica las dos guerras del proyecto: la **guerra de punteros** (el EDR puede re-afirmar su callback cuando quiera y el shim debe detectarlo) y el **techo de re-verificación** (el EDR puede, en teoría, leer su slot; resulta que desde user-mode **no puede** — ver §4.2).

## 3. Cómo trabaja este proyecto (metodología en cinco reglas)

Antes de contar la implementación conviene recordar las reglas no negociables de Kagemusha, porque son las que convierten esto en ingeniería y no en una demo:

1. **Solo indirect syscalls, cero `syscall` propio.** Ningún binario del proyecto contiene la instrucción `0F 05`; el `syscall` se ejecuta siempre dentro de `ntdll`, saltando a un gadget `syscall;ret` real. Lo verifica `dumpbin` en cada cierre.
2. **SSN en runtime (FreshyCalls).** Nada hardcodeado; los números de servicio se resuelven por orden de export. En F10, además, **los call-sites se auto-calibran** desde los propios stubs: cero offsets fijos también aquí.
3. **Oráculo independiente por afirmación.** Si decimos "el EDR vio 100 llamadas", contrastamos contra el **ledger** interno; si decimos "el error es exacto", contrastamos el NTSTATUS contra el valor real; cada hallazgo de RE lleva su transcript de `cdb` reproducible.
4. **Fallar ruidoso.** Ante una inconsistencia se aborta con error; nunca se "adivina". En F10 añadimos `KageInstrumentLastStatus` para que un fallo de instalación diga *por qué*.
5. **Un hallazgo sin transcript no es un hallazgo.** Cada pregunta `Q10.x` se cerró con evidencia versionada en `docs/evidencias/e10_*.txt`.

El **modelo de amenaza** del experimento es local y controlado: un "EDR-sim" que vive en el propio proceso (el harness AVA, que instala su callback y cuenta lo que ve) más el detector de referencia de paranoidninja. No hay EDR comercial real en la ecuación, y eso se dice en los límites.

Y un apunte de método que da color a la fase: el plan original asumía que el discriminador del indirecto sería `R10`. La revisión de ingeniería inversa (`E10.1`) **desmintió esa suposición con evidencia** y obligó a rediseñar el shim sobre `[rsp]`. Que el plan se equivoque y la evidencia mande es exactamente cómo debe funcionar esto.

## 4. E10.1 — Ingeniería inversa: el contrato, el slot y la guerra

La fase arrancó con seis preguntas numeradas (`Q10.1` a `Q10.6`) y una regla: **nadie escribe código que dependa de una pregunta sin cerrarla antes con evidencia**. Estas son las respuestas.

### 4.1 Q10.1 — El contrato de dispatch, medido

Método: dos scripts de `cdb` reproducibles (`k10_cb_dispatch.txt`, `k10_cb_indirect.txt`) con el observador propio activo. El primero rompe en la primera instrucción del callback (`pushfq`) y captura el estado de entrada; el segundo filtra por pila para capturar **específicamente** los syscalls originados en wrappers de Kagemusha.

La tabla completa está en §2.2; lo relevante aquí es **cómo se validó**: el contrato observado se contrastó con el que ya usaba nuestro observador (que guarda `RAX` como retorno y sale con `jmp r10`) y con el que usa el detector de referencia. Coincidencia registro a registro. **No hay frame de kernel en la pila de usuario** al entrar: el callback es user-mode puro.

Un detalle operativo que salió de aquí: el callback **también ve los syscalls del propio instrumentador** (por ejemplo, los `NtRaiseException`/`NtQueryInformationThread` que el handler usa para resolver nombres). El shim tendrá que no confundirlos con los del catálogo: se resuelve clasificando por call-site, no por "quién llama".

### 4.2 Q10.2 — ¿Se puede *leer* el slot? Negativo (y es una buena noticia)

La pregunta era: ¿puede un proceso preguntarle a Windows quién es su callback? Si se pudiera, un EDR podría **re-leer** su slot y detectar que lo hemos sustituido. El proyecto probó la clase `0x28` en modo lectura:

```text
NtQueryInformationProcess(proceso actual, 0x28, &buf, 16, &retlen)
  -> 0xC0000003  (STATUS_INVALID_INFO_CLASS)
  -> retlen = 0
  -> buffer intacto (patrón 0xAA)
  -> barrido de longitudes 0..32 en pasos de 4: mismo status en todas
```

Resultado: en esta build la clase **solo soporta escritura (Set)**. Consecuencias directas:

- El **discovery** del callback ajeno no puede usar una query; será por **firma de código** y orden de instalación en laboratorio.
- Un EDR user-mode **no puede re-verificar su puntero por esta vía**. El "techo de re-verificación" que temíamos queda, de momento, del lado del atacante... salvo que el EDR tenga su propio driver de kernel (que es precisamente el techo que no se toca; ver §10).

### 4.3 Q10.3 — Dónde vive el código ajeno y qué firma tiene

Instalamos el EDR-sim (el harness AVA) y localizamos su callback con `cdb` + `!kage`:

| Caso | Dirección | Región | Tipo |
|---|---|---|---|
| Callback del EDR-sim (AVA) | `Kagemusha.exe+0x90a5` | `.text` de la imagen principal | `MEM_IMAGE`, `PAGE_EXECUTE_READ` |
| Callback de `etwti-hook.exe` (paranoidninja) | `0x4016f0` | `.text` de [`0x401000`,`0x403000`) | `MEM_IMAGE`, `PAGE_EXECUTE_READ` |

Y extrajimos la **firma común** del prólogo estilo `hook.asm` (14 bytes):

```text
51 52 49 8B 52 F0 E8 ?? ?? ?? ?? 5A 59 C3
push rcx ; push rdx ; mov rdx,[r10-10h] ; call rel32 ; pop rdx ; pop rcx ; ret
```

Dos observaciones de oro:

- El callback de esta familia **termina en `ret`**, no en `jmp r10`. Es una variante válida (consume de la pila la dirección real), pero nosotros ya sabíamos por `Q10.6` que `ret` es frágil en el primer retorno de hilos nuevos. El shim, por contrato, saldrá siempre con `jmp r10`.
- `[r10-0x10]` es el **número de syscall**, visible para el callback sin tocar el kernel. Es exactamente lo que el detector usa para saber qué se llamó.

El barrido de falsos positivos con la firma completa de 14 bytes dio **0 hits** en `ntdll.dll`, `kernel32.dll`, `KernelBase.dll` y `user32.dll`, y 1 hit en cada binario que la contiene. Eso valida el discovery por firma *para esta familia de callbacks*, con el límite declarado: un EDR con otro compilador o prólogo no tiene por qué matchear; por eso `KageCbProbe` usa una **cascada** (firma + calibración por orden de instalación en el laboratorio), no una sola heurística.

### 4.4 Q10.5 — Los offsets del PDB (Ghidra headless)

Para no depender de foros ni de offsets de terceros, el proyecto descargó el PDB de `ntoskrnl` y lo procesó con **Ghidra 12.1 headless** (un script Java que vuelca todos los campos `*Instrumentation*`). Resultado:

| Estructura | Offset | Campo |
|---|---|---|
| `_KPROCESS` | **+0x168** | `InstrumentationCallback` (puntero del slot) |
| `_TEB` / `_TEB64` | +0x2d0 | `InstrumentationCallbackSp` |
| `_TEB` / `_TEB64` | +0x2d8 | `InstrumentationCallbackPreviousPc` |
| `_TEB` / `_TEB64` | +0x2e0 | `InstrumentationCallbackPreviousSp` |
| `_TEB` / `_TEB64` | +0x2ec | `InstrumentationCallbackDisabled` |
| `_TEB` / `_TEB64` | +0x110 | `ReservedForDebuggerInstrumentation[16]` |
| `_TEB` / `_TEB64` | +0x16b8 | `Instrumentation[11]` |
| `_TEB32` (WOW64) | +0x1ac…+0x1b8 | equivalentes 32-bit |

Dos lecturas importantes:

1. **El slot no está en `EPROCESS`, está en `_KPROCESS+0x168`** (el proyecto lo había supuesto mal en el plan). Inaccesible desde user-mode directamente: solo se llega vía la llamada de Set.
2. El **TEB sí es user-mode** y expone maquinaria interna (Sp/Pc/Sp previos y un flag `Disabled`), pero en esta build **no señaliza**: los campos quedan a 0 incluso con el callback ejecutándose (20/20). Traducción: el TEB no sirve para confirmar "hay callback instalado"; esa confirmación queda para la **sonda de liveness** de `E10.5`. Otro plan que se corrige con medición.

### 4.5 Q10.6 — La guerra de punteros y los dos bugs reales

El modo `--cbwar` monta una guerra determinista entre dos callbacks (A y B) y documenta el modelo:

```text
[A instalado]      syscalls=5
[A re-afirmado x3] syscalls=13      (re-afirmar el mismo puntero: inocuo, sin pérdida)
[B sustituye a A]  AVA=0  B=7       (sustitución silenciosa: el anterior queda mudo)
[A recupera slot]  syscalls=5       (el slot es "el último que escribe")
```

Pero lo valioso de `Q10.6` fue lo que se rompió mientras lo construíamos. El port literal del callback de paranoidninja tenía **dos bugs reales**, y los dos importan:

**Bug 1 — `RAX` no preservado.** El harness AVA era C y machacaba `RAX`; con el callback activo, `CreateEventA` devolvía `NULL` (error 317). Diagnóstico con `--cbava`:

```text
[AVA on] CreateEventA=0            <- roto
(fix)     CreateEventA=0xA8 err=0  <- correcto
```

Cualquier API que lea el NTSTATUS que el callback dejó en `RAX` se rompía. Lección: **zero-clobber no es solo `R10`**; `RAX`, `RCX`, `RDX` y `RFLAGS` también son contrato.

**Bug 2 — salir con `ret`.** En el **primer retorno de un hilo nuevo** creado con el callback activo, la pila no tiene el marco que `ret` espera; el hilo salta a un destino inválido y se produce una **excepción de acceso (`c0000005`)** capturada con `cdb` en `docs/evidencias/e10_cbwar_crash.txt`. El fix es el contrato correcto: salir con **`jmp r10`** (la dirección de retorno efectiva que el kernel dejó en `R10`), no fabricar un `ret`.

De aquí salieron las reglas de diseño del shim que veremos en §5: **zero-clobber obligatorio**, salida por `jmp r10`, y contadores en memoria (nunca en registros).

## 5. E10.2 — `KageCbProbe`: descubrir si te están grabando

Antes de tocar nada, hay que saber **si hay alguien**. Como la query del slot es negativa (§4.2), `KageCbProbe` implementa el discovery en cascada por **firma de código**:

- Recorre las regiones **ejecutables** del proceso con `NtQueryVirtualMemory` (wrapper indirecto propio), con un presupuesto máximo de **512 MB** y validación `SEH` por región para no caer con mapeos raros.
- Busca dos patrones de la familia `hook.asm`/paranoidninja:
  - **Firma completa** (14 bytes): `51 52 49 8B 52 F0 E8 ?? ?? ?? ?? 5A 59 C3`.
  - **Variante** `49 8B 52 F0 E8` con validación de cola (`41 FF E2` = `jmp r10`) en una ventana de 48 bytes.
- Resuelve el **módulo anfitrión** del candidato (para reportar "está en `KageAvaCallback`", no una dirección suelta).

### 5.1 Resultados

| Prueba | Resultado |
|---|---|
| Proceso limpio, sin callback instalado (TEB sin señal) | **20/20** "sin callback" |
| Candidato de código presente pero sin instalar | **20/20** 1 hit (el código existe en la imagen) |
| EDR-sim (AVA) instalado | **20/20** 1 candidato dentro de `KageAvaCallback` |
| Build CET | idéntico, exit 0 |

Dos aprendizajes medidos que conviene apuntar:

- El patrón correcto es **`49 8B 52 F0`** (`REX.WB` de `mov rdx,[r10-0x10]`), no `48 …`: el bug se detectó y corrigió durante la implementación.
- El hit cae a **+0x8 del entry** del callback, porque el harness AVA antepone 8 bytes de prólogo. El probe reporta el candidato y la normalización al entry exacto se hace al encadenar.

Y una lección conceptual importante: **"código presente" no es "callback instalado"**. El binario contiene el código del AVA siempre; el probe encuentra el candidato igual en un proceso limpio. La confirmación de instalación no viene del TEB (no señaliza) ni de la query (no existe): viene de la **liveness** (§8). El probe, por tanto, es un auditor de *"qué telemetría in-proces existe aquí"*, no un detector de *"me están espiando ahora mismo"*.

## 6. Filtrar por pila: por qué `[rsp]` y no `R10`

Este es el hallazgo técnico central de la fase, y merece su propia sección porque **corrige la suposición con la que se escribió el plan**.

### 6.1 La suposición (equivocada)

El plan original decía: *"el discriminador es `R10`"*, es decir, si el callback mira la dirección de retorno en `R10` y ve que cae dentro del módulo sospechoso, marca el syscall como indirecto. Suena razonable... hasta que se mide.

### 6.2 Lo que dice la evidencia

Captura filtrada por pila de un syscall **indirecto** de Kagemusha (`NtClose_I` con handle inválido):

```text
R10  = 00007ffc`48544e80   -> ntdll!KiRaiseUserExceptionDispatcher
[rsp]= 00007ff6`5b665039   -> Kagemusha!NtClose_I+0x29   (call-site del wrapper)
```

Y en un syscall **nativo** (por ejemplo, el `NtAllocateVirtualMemory` interno del heap):

```text
R10  = 00007ffc`48540f92   -> stub de ntdll +2
[rsp]= dirección de kernelbase/ntdll (código del sistema)
```

Conclusiones:

1. **En el indirecto, `R10` apunta al mismo tipo de sitio que en el nativo**: nuestro stub salta al **mismo gadget** `syscall;ret` de `ntdll` que usa el sistema, así que el retorno efectivo es indistinguible. `R10` **no identifica el origen**.
2. Peor aún: `R10` **ni siquiera es estable semánticamente**. Si el syscall genera una excepción (`NtClose` inválido → `STATUS_INVALID_HANDLE`), el kernel pone en `R10` el **dispatcher de excepciones del kernel** (`KiRaiseUserExceptionDispatcher`), no un stub. Cualquier detector que use `R10` como "dirección de retorno" tiene que lidiar con dos casos distintos.
3. **Lo que sí identifica es la pila**: el callback corre con la pila de usuario intacta, y `[rsp]` es **el call-site real** — la dirección dentro del wrapper desde la que se llamó al stub. En el caso indirecto: `Kagemusha!NtClose_I+0x29`.

### 6.3 Cómo se explota sin offsets hardcodeados

Aquí está la parte elegante: los call-sites no se calculan a mano ni se leen de un PDB; **los propios stubs los registran al ejecutarse**. En la macro MASM que genera cada stub del catálogo:

```asm
; g_CbCallSites[slot] = [rsp]  (call-site real del wrapper)
mov r11, QWORD PTR [rsp]
mov QWORD PTR [g_CbCallSites + slot*8], r11

mov r10, rcx                              ; ABI syscall x64
mov eax, DWORD PTR [g_SsnTable + slot*4]  ; SSN resuelto en runtime
jmp QWORD PTR [g_GadgetTable + slot*8]    ; gadget syscall;ret de ntdll
```

La calibración (`KageCbShimCalibrate`) ejecuta una invocación benigna de cada wrapper y los stubs van dejando sus call-sites en la tabla. Cero offsets hardcodeados, consistente con el invariante del proyecto. **Coste honesto:** esas dos instrucciones se ejecutan en **cada** syscall del catálogo, incluso sin shim instalado. Es un coste de rendimiento trivial, pero es un artefacto forense permanente (toda syscall del catálogo escribe en `g_CbCallSites`), y lo dejamos anotado en los límites.

**¿Y los falsos positivos?** ¿Puede una llamada legítima de otro módulo tener un `[rsp]` que coincida con un call-site nuestro? Por construcción, no: para que `[rsp]` caiga dentro de un wrapper de Kagemusha, alguien tendría que estar llamando a **nuestros** wrappers. En un `.exe` de laboratorio, eso solo pasaría si código de terceros invocara nuestros wrappers exportados — no aplica al diseño. Riesgo despreciable, pero listado por completitud.

**Cobertura pendiente:** el caso "filtro activo + syscall que genera excepción" (drop con `jmp r10 = KiRaiseUserExceptionDispatcher`) no tiene test dedicado; el análisis dice que replica el retorno natural, pero es un hueco de cobertura que dejamos declarado.

En resumen: **`R10` dice a dónde ibas a volver; `[rsp]` dice quién te llamó.** Para esconder selectivamente solo lo nuestro, necesitábamos lo segundo. Ese es el "filtrar por pila".

## 7. E10.3 / E10.4 — El shim: encadenar sin romperlo y filtrar

Con el contrato claro, el slot localizado y el discriminador resuelto, llegó la pieza central: **`KageCbShim`**, un callback propio que se instala en el slot **en lugar** del callback ajeno, pero que lo **encadena** (le reenvía las llamadas) para que el EDR siga viendo exactamente lo mismo... hasta que decidimos qué no ve.

### 7.1 API y ciclo de vida

```c
NTSTATUS KageCbProbe(PVOID *ForeignCallback, PWSTR HostModuleHint);
NTSTATUS KageCbShimInstall(PVOID ForeignCallback);   /* pisa el slot con el shim */
NTSTATUS KageCbShimUninstall(VOID);                  /* restaura el ajeno (nunca NULL a ciegas) */
NTSTATUS KageCbShimSetFilter(ULONG64 SlotMask);      /* bitmask de slots a ocultar */
BOOL     KageCbShimLiveness(VOID);                   /* ¿sigo en el slot? */
NTSTATUS KageCbShimReinstall(VOID);                  /* me han pisado: vuelvo */
```

Reglas del ciclo de vida:

- **Install** exige que el núcleo esté inicializado, rechaza doble instalación (`KAGE_ERR_COLLISION`), guarda el puntero ajeno (`g_CbForeign`), resetea máscara y contadores, y **pisa el slot** llamando a `KageInstrumentSetCallback`.
- **Uninstall nunca pone `NULL` a ciegas**: restaura el callback ajeno descubierto (o `NULL` si éramos los únicos), para dejar el proceso como estaba. Verificado por test y por evidencia (`AVA tras restaurar=1`).
- Los **contadores** (`fwd`, `drop`) viven en memoria y se incrementan con `lock inc` desde el dispatcher ASM; la máscara de filtro es un bitmask de 10 bits (uno por slot del catálogo).

### 7.2 El dispatcher zero-clobber, instrucción a instrucción

Este es el corazón del diseño. El dispatcher entra con **todos** los registros en un estado que el callback ajeno espera recibir intacto. No puede usar registros para clasificar; solo memoria, y con cuidado quirúrgico:

```asm
KageCbShimEntry:
    endbr64                       ; defensivo (la entrada real es IRET del kernel)
    pushfq                        ; salva RFLAGS
    push rax                      ; salva RAX (NTSTATUS del syscall)
    mov  rax, QWORD PTR [rsp+10h] ; rax = call-site original ([rsp] antes de los push)

    ; --- clasificador: 10 bloques, uno por slot ---
    test BYTE PTR [g_CbFilterMask+0], 01h   ; ¿slot 0 enmascarado?
    jz   kage_shim_skip0
    cmp  rax, QWORD PTR [g_CbCallSites+0]   ; ¿call-site == el calibrado del slot 0?
    je   kage_shim_drop                      ; SÍ -> es nuestro: ocultar
    ; ... (idéntico para los slots 1..9)

    ; --- forward: syscall ajeno o nativo -> que lo vea el EDR ---
    pop  rax                        ; restaura NTSTATUS
    cmp  QWORD PTR [g_CbForeign], 0 ; ¿hay callback ajeno?
    je   kage_shim_drop2
    lock inc QWORD PTR [g_CbFwdCount]
    popfq                           ; restaura flags
    jmp  QWORD PTR [g_CbForeign]    ; encadena: el EDR ve lo mismo que siempre

    ; --- drop: como si el callback no existiera ---
kage_shim_drop:
    pop  rax
kage_shim_drop2:
    lock inc QWORD PTR [g_CbDropCount]
    popfq
    jmp  r10                        ; retorno efectivo (contrato), nunca `ret`
```

Detalles que hacen que esto funcione:

- **`[rsp+0x10]`** es el `[rsp]` original: tras los dos `push`, la pila tiene `RAX` guardado, `RFLAGS` guardado y luego el call-site. De ahí el `+0x10`.
- **El clasificador solo toca `RAX` (temporal) y memoria.** `RCX`, `RDX`, `R8`, `R11`, la pila y los flags quedan intactos.
- **El forward no toca `RCX`.** Este fue el fix crítico de `E10.5`: el diseño original hacía `mov rcx,[g_CbForeign]` "para restaurar el contrato", pero el contrato **no** exige la dirección del callback ajeno: exige la **RCX tal cual la entregó el kernel** (la dirección del callback *instalado*, es decir, la del shim). Modificarla mataba los hilos nuevos con `STATUS_DATATYPE_MISALIGNMENT`. La lección completa está en `Q10.6`/`E10.5` y ahora tiene regresión permanente (`T53.3b` y el modo `--cbthread`).
- **El drop sale con `jmp r10`**, exactamente el retorno que el kernel habría restaurado si no hubiera callback. Eso hace el drop **indistinguible** para el hilo: no hay frame extra, no hay `ret` fabricado, no hay pila tocada.
- **`lock inc` antes de `popfq`**: así los flags que el `inc` modifica quedan sobrescritos por los flags restaurados del usuario. El orden está cuidado en ambos caminos.

### 7.3 Resultados medidos

Evidencia versionada en `docs/evidencias/e10_cbshim.txt`, reproducida en cada cierre:

| Paso | Resultado |
|---|---|
| Calibración de call-sites | **10/10** |
| Fidelidad (forward transparente), 100 syscalls | el EDR-sim **vio 100** |
| Zero-clobber: `NtClose` inválido con shim | **`0xC0000008`** exacto |
| Filtro total: 100 syscalls del catálogo | el EDR-sim **vio 0** (drop 100) |
| Control nativo (`CreateEventA`/`CloseHandle`) | el EDR-sim vio 3 (**0 colaterales**) |
| Contadores | `fwd=105`, `drop=100` |
| Uninstall | restaura el callback ajeno (status 0) |
| Suite | T50–T52 → 407/0 stealth; con T53 → **440/0** stealth y **407/0** CET |

Traducido a las cuatro piezas del artículo: **encadenar** funciona (100/100), **filtrar** funciona (100→0), **no romperlo** funciona (zero-clobber exacto, 0 colaterales, proceso anfitrión intacto). Y el control nativo es la clave de la discreción: el EDR sigue viendo **todo lo que no es nuestro**, que es lo que hace que no sospeche.

### 7.4 Notas honestas sobre esta parte

- El harness AVA (EDR-sim) **cuenta toda ejecución de su callback**, no discrimina por "el return address cae en la imagen propia" como decía un comentario heredado del port. La métrica que usamos (cuántas llamadas ven el callback) es exactamente la que necesitábamos, así que los resultados no cambian; pero la **descripción** del criterio en la doc interna quedó inexacta y así lo dejamos anotado.
- El contador `drop` significa "**no reenviado**", que con un callback ajeno válido instalado coincide con "filtrado por máscara", pero semánticamente es más amplio (también cuenta el caso `g_CbForeign == NULL`).
- `Uninstall` no limpia el puntero ajeno ni los contadores (solo `Install` los resetea): estado residual menor entre ciclos.
- `Install` acepta `ForeignCallback == NULL` por diseño (el shim se comporta como drop total), pero no está declarado explícitamente en la cabecera pública.

## 8. E10.5 — Liveness: la guerra de punteros

### 8.1 El problema: la derrota es silenciosa

El slot tiene una sola plaza y **gana el último que escribe**. Si el EDR re-afirma su callback —porque lo hace periódicamente, porque sospecha, o simplemente porque se reinstala—, nuestro shim deja de ser llamado. Y nadie nos avisa: no hay señal, no hay error, no hay notificación. Para el proceso, todo sigue funcionando; simplemente hemos dejado de ver.

Si el EDR re-afirma en bucle, un shim pasivo se queda fuera para siempre. La guerra de punteros necesita, por tanto, **un detector propio de que seguimos vivos** y un mecanismo de reconquista.

### 8.2 La sonda de liveness (≤ 1 syscall)

La idea es la de un guardia que cada poco se llama a sí mismo para comprobar que su extensión sigue enchufada:

```c
BOOL KageCbShimLiveness(VOID)
{
    LONG64 Before = g_CbFwdCount + g_CbDropCount;
    NtYieldExecution_I();               /* 1 syscall del catálogo (call-site calibrado) */
    LONG64 After = g_CbFwdCount + g_CbDropCount;
    return (After > Before);            /* si el contador subió, el shim sigue en el slot */
}
```

Por qué funciona con cualquier configuración: si el filtro está **OFF**, la llamada de prueba se reenvía y sube `fwd`; si está **ON** y el slot 7 está enmascarado, se hace drop y sube `drop`. En ambos casos, **si el shim está instalado, el contador sube**. Y si alguien nos pisó el slot, no sube nada. La latencia de detección es **≤ 1 syscall** por diseño: no hay polling ciego.

Cuando la sonda falla, `KageCbShimReinstall` vuelve a pisar el slot con el shim y `InterlockedIncrement64` cuenta la reconquista. Coste de la sonda: un syscall benigno (`NtYieldExecution`) y dos lecturas de contadores. La lectura del par de contadores **no es atómica** (son dos cargas separadas), pero el sesgo máximo es de 1 y solo puede producir un falso "sigo vivo" en una carrera extrema, nunca un falso positivo de sustitución. Lo dejamos declarado.

### 8.3 La guerra, medida

Dos pruebas complementarias:

**Guerra determinista (10 rondas):** el EDR-sim pisa el slot; la sonda lo detecta; el shim reinstala. Resultado: **10/10 rondas detectadas y reconquistadas**, contador de reinstalaciones coherente. Esto valida el ciclo completo detección → reconquista.

**Guerra concurrente:** dos hilos compitiendo durante 200 ms — uno re-afirmando el callback del EDR-sim cada ~1 ms, otro haciendo liveness + reinstalación sin parar. La evidencia versionada registra:

```text
[war concurrente] pings vivos=260471 muertos=20 -> shim vivo 100.0%
```

Es decir: de ~260 000 comprobaciones, el shim estaba en el slot en todas menos 20, y cada una de esas 20 se convirtió inmediatamente en una reconquista. En la reproducción del cierre, 263 029 vivos / 33 muertos: mismo 100.0 %. 

**Soak de 100 000 syscalls con guerra activa:**

```text
soak: N=100000 fallos=0 fwd=276688 drop=0 reinstalls=19 pings=176907/19
```

Cero fallos, cero fugas, 19 reconquistas a lo largo de la prueba. (El `drop=0` es correcto: el soak corre con el filtro OFF, así que todo lo que pasa por el shim se reenvía.)

**Dos matices honestos** sobre estas cifras:

- Entre "la sonda detecta que me han pisado" y "reinstalo" hay una **ventana TOCTOU** en la que el EDR posee el slot. Los "pings muertos" (20, 33, 19) la acotan indirectamente, pero el 100.0 % de "shim vivo" mide **reconvergencia del ping**, no exposición temporal absoluta. Es una métrica conservadora en la dirección correcta, pero no es "0 % de exposición".
- Las cifras buenas lo son porque el EDR-sim re-afirma a un ritmo humano (~1 ms). Un EDR que re-afirmara en un bucle apretado convertiría esto en una carrera de CPU; el modelo de guerra está documentado como **carrera abierta**, no como victoria garantizada.

## 9. El delta kernel vs callback: el techo que no desaparece

### 9.1 La idea

Cegar el callback es cegar **una** fuente. Pero el kernel tiene las suyas: telemetría (ETW-TI), callbacks de kernel, contadores internos. Si un EDR **funde** (cruza) sus fuentes:

- La fuente de kernel dice: *"este proceso ejecutó 100 syscalls de su catálogo"*.
- Su callback dice: *"yo vi 0"*.

Y ese hueco —el **delta**— no es un fallo de telemetría: es **la señal de manipulación**. El silencio delata.

### 9.2 La medición en el laboratorio

El proyecto no tiene ETW-TI habilitable desde user-mode, así que construyó el **análogo de laboratorio**: el `ledger` interno de Kagemusha (la verdad de tierra de lo que el mecanismo ejecutó de verdad) contra el contador del callback del EDR-sim. Con el filtro activo:

```text
[fusion] catalogo(ledger)=100 callback(AVA)=0 delta=100
```

Reproducido por test (`T53.9`–`T53.11`) y por el modo `--cbwar`. **Un EDR que fusione fuentes detecta el filtro con un delta de 100 llamadas.** El experimento no dice "somos invisibles"; dice exactamente lo contrario: *"este es el rastro que deja la manipulación ante quien sepa mirar"*.

**Nota de precisión:** el "kernel" del delta es el ledger del laboratorio, no ETW-TI real. Es un modelo cuantificado del techo, no una captura del techo. La distinción importa y por eso está escrita.

### 9.3 Qué cambia esto

- **Para el defensor** (que es el objetivo real de esta serie): la lección es de arquitectura de sensores. Un sensor in-proces **solo** no es confiable ante un atacante que controla el proceso. La defensa correcta es **fusión cross-source** (kernel + callback + pila) y **verificación de integridad del propio sensor** desde un plano que el atacante no controle (kernel). Lo que el atacante puede silenciar en user-mode, el defensor debe poder reconstruirlo desde abajo.
- **Para el atacante** (que es el modelo simulado): contra un EDR que solo escucha su callback, el filtrado selectivo funciona y es transparente. Contra un EDR que fusiona, no: el hueco lo delata. El techo real de la fase no es "no se puede cegar el callback" —eso se hizo— sino "**no se puede cegar la fusión** desde user-mode".

### 9.4 Y los otros techos siguen ahí

Para que no se malinterprete el alcance de la Fase 10, así queda el mapa tras la fase:

| Techo / límite | Estado tras F10 |
|---|---|
| Instrumentation callback (S5) | **Reducible**: encadenable, filtrable y con liveness. Con techo residual de **fusión** y **re-verificación desde kernel** |
| Re-lectura del slot por el EDR | Imposible desde **user-mode** (query negativa, §4.2); posible con driver propio |
| Scanner/walk de pila (S4) | Intacto: el shim solo ciega la ruta *callback*; el retorno "a mitad de stub + caller propio" sigue visible a un stack walker |
| ETW-TI (S6) | Intacto: no habilitable ni cegable desde user-mode |
| Callbacks de kernel (S8) | Intactos: plano no observable desde el proceso |
| IBT estricto (CET completo) | Riesgo residual no cerrado: `jmp [foreign]`/`jmp r10` sin `ENDBR64` en los destinos; en el host de referencia no se imponía |

Esa tabla es, en el fondo, la conclusión de la fase: **no existe la invisibilidad; existe el movimiento del techo.**

## 10. La corrección del modelo: S5 ya no es "techo estructural"

La matriz de la Fase 9 clasificaba **S5 @ E5/E6** como techo estructural con esta justificación: *"no cegable desde user-mode"*. La Fase 10 midió lo contrario con el detector de referencia (el propio AVA que implementa el criterio in-process de paranoidninja):

- Con el filtro **OFF**: el detector marca los syscalls del catálogo (N de N).
- Con el filtro **ON**: el detector pasa a **0** para los syscalls del catálogo, y **sigue marcando los controles** (llamadas nativas que no son nuestras).

Es decir: la celda **S5 @ E5/E6 pasa de `2` a `1` medida**, con un techo residual formalizado (fusión kernel-vs-callback y re-verificación del puntero desde kernel). La clasificación original no era un dato: era una inferencia. Ahora es una medición.

Un límite declarado importante: el detector de referencia **in-process** es el oráculo end-to-end; el binario externo `etwti-hook.exe` **no puede observar nuestro proceso** (vive fuera) y por eso queda fuera del alcance por diseño. No se está midiendo contra un EDR comercial real, y eso se dice.

Con esto, la jerarquía del proyecto queda aún más clara: **conducta > ejecución > mecanismo**. Puedes encadenar, filtrar y sobrevivir a la guerra de punteros (mecanismo/sensor), pero lo que de verdad decide una alerta sigue siendo lo que el proceso **hace**, y lo que de verdad cierra el techo es lo que se ve desde el **kernel**.

## 11. Errores, deuda y límites (lo que no salió redondo)

Publicar solo los números bonitos sería hacer publicidad. Esto es lo que la revisión del código y del repo encontró, y que dejamos anotado:

| # | Hallazgo | Impacto |
|---|---|---|
| 1 | La sección §11 del informe interno aún describe el forward con `mov rcx,[g_CbForeign]` (diseño anterior al fix E10.5); la corrección está en §12 del mismo documento | Doc interna desactualizada; el código manda |
| 2 | El harness AVA **cuenta toda ejecución** de su callback, no discrimina por return address como sugiere un comentario heredado | La métrica usada es la correcta; la descripción del criterio era inexacta |
| 3 | Los stubs **escriben el call-site en cada syscall** del catálogo (2 instrucciones extra), también sin shim instalado | Coste trivial, pero es un artefacto forense permanente y se aleja del "señal mínima" |
| 4 | El contador `drop` significa "no reenviado", no "filtrado por máscara" | Coinciden en el caso normal; semántica más amplia de lo que sugiere el nombre |
| 5 | La lectura de los contadores en liveness **no es atómica** | Sesgo de a lo sumo 1, solo en carrera extrema; no puede dar falso positivo de sustitución |
| 6 | Ventana **TOCTOU** entre detectar el robo del slot y reinstalar | El EDR ve syscalls en esa ventana; el 100.0 % mide reconvergencia, no exposición cero |
| 7 | `Uninstall` no limpia `g_CbForeign` ni los contadores | Estado residual entre ciclos (menor, por diseño del test) |
| 8 | `Install` acepta `ForeignCallback == NULL` sin declararlo en la cabecera | Comportamiento válido (drop total), documentación incompleta |
| 9 | **IBT estricto**: el forward y el drop saltan a destinos sin `ENDBR64`; no hay fail-loud si IBT se impone | Riesgo residual número uno en entornos CET completos (shadow stack + IBT); en el host de referencia no se imponía |
| 10 | Del plan original quedaron sin implementar: el wrapper propio `NtSetInformationProcess_I` (se usa `GetProcAddress` directo), los tests T54–T59, el detector externo end-to-end y el fail-loud de CET | Deuda declarada; los resultados medidos (T50–T53) no dependen de ello |
| 11 | El transcript del crash mostraba un AV en la región del callback; la frase "RIP=0" del informe era la explicación del mecanismo, no una línea literal del transcript | Matiz de precisión; el fenómeno está acreditado |
| 12 | El README conserva dos referencias a "T0..T49" en la sección de arquitectura | Cosmético; la suite real llega a T53 |

Ninguno de estos hallazgos invalida las mediciones de la fase; pero todos ellos forman parte del resultado y así deben leerse. La crítica número 9 (IBT) es la única con potencial de romper el shim en un entorno distinto, y por eso queda marcada como **riesgo abierto**, no como límite cerrado.

## 12. Cómo reproducirlo

Todo el laboratorio es local; nada sale del equipo. Requisitos: Windows 11 x64, VS Build Tools con `ml64` (la configuración exacta está en `tools\build.cmd`).

```text
tools\build.cmd                   :: -> bin\Kagemusha.exe + bin\Kagemusha_tests.exe
tools\build_cet.cmd               :: -> bin_cet\ (variante /CETCOMPAT)

bin\Kagemusha.exe --cbquery       :: Q10.2: la query del slot es negativa (0xC0000003)
bin\Kagemusha.exe --cbprobe       :: E10.2: discovery por firma (20/20, 0 FP en modulos del sistema)
bin\Kagemusha.exe --cbshim        :: E10.3/E10.4: calibracion 10/10, forward 100/100, filtro 100->0
bin\Kagemusha.exe --cbthread      :: contrato RCX: hilo nuevo con shim (regresion del fix)
bin\Kagemusha.exe --cbwar         :: E10.5: guerra deterministico + concurrente + delta de fusion
bin\Kagemusha.exe --cbsoak        :: soak 100k con guerra activa
bin\Kagemusha_tests.exe           :: suite completa (T0..T53): 440/0 stealth, 407/0 CET
powershell -File tools\verify.ps1 :: 0 instrucciones syscall en los binarios propios
```

Las preguntas de RE (`Q10.1`–`Q10.6`) se reproducen con los scripts de `tools\cdb_scripts\k10_*.txt` y `cdb`; los transcripts están en `docs\evidencias\e10_*.txt` y el informe completo en `docs\research\experimento-e10-dispatch.md`.

## 13. Qué queda por delante

- **Fase 11 (capa conducta):** romper la correlación S9 (staging multi-contexto) y formalizar los predicados de las reglas; es la fase natural tras mecanismo (F1–F8), ejecución (F9) y sensor (F10).
- **L2 (contextos legítimos):** ejecutar blobs en hilos del threadpool en vez de crear un hilo propio, como sub-experimento de F11.
- **Techos de kernel:** ETW-TI y callbacks de kernel siguen intactos; la fusión kernel+callback queda cuantificada como el detector que el shim no puede cegar desde user-mode.

## 14. Conclusiones

1. **Un sensor de user-mode que vive dentro del proceso observado es controlable.** Eso ya estaba en el marco teórico del proyecto; F10 lo convirtió en medición: encadenado transparente (100/100), filtrado selectivo por pila (100→0, 0 colaterales) y liveness (≤ 1 syscall).
2. **La transparencia es la clave de la discreción.** El shim no apaga la cámara: la deja grabando todo lo que no es suyo. Un EDR que solo mira su callback no tiene motivo para sospechar.
3. **La guerra de punteros es ganable contra un rival que no re-verifica**, con métricas medidas (100.0 % de shim vivo, soak de 100 000 syscalls con 0 fallos y 19 reconquistas). Y es **perdible** contra un rival que fusione fuentes: delta = 100.
4. **El techo se mueve, no desaparece.** S5 pasa de "estructural no cegable" a "reducible con techo residual de fusión/re-verificación". S4, S6 y S8 siguen donde estaban.
5. **El método es el resultado.** Preguntas cerradas con transcript, oráculos independientes, un plan que se equivoca y una evidencia que lo corrige, y una lista de errores propios publicada junto a los números. Eso es lo que separa un informe de un anuncio.

> Aprender a romper para poder defender.

## Referencias

- Código y documentación del proyecto: `Kagemusha` (`README.md`, `docs/research/experimento-e10-dispatch.md`, `docs/evidencias/e10_*.txt`, `docs/fase9/matriz-final.md`).
- Microsoft Learn — *ProcessInstrumentationCallback* (`NtSetInformationProcess`), *Control-flow Enforcement Technology (CET)*.
- x86matthew — *InstrumentationCallbackSyscallLogger* (MIT).
- paranoidninja — *Process-Instrumentation-Syscall-Hook* (`etwti-hook.exe`).
- crummie5 — *FreshyCalls*; WKL-Sec — *LayeredSyscall*.

Serie completa: **[Kagemusha](/blog/serie/kagemusha.html)**. Entradas relacionadas: [Visibilidad y evasión](/blog/kagemusha-visibilidad-evasion.html), [Metodología de verificación](/blog/kagemusha-metodologia-verificacion.html), [Informe técnico de evasión](/blog/kagemusha-informe-tecnico-evasion.html) y [Por qué la evasión es en capas](/blog/kagemusha-articulo-por-que-evasion-capas.html).
