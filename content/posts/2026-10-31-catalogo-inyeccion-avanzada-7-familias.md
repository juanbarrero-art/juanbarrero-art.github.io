---
title: "Catálogo de inyección avanzada: las 7 familias del código que no debería estar ahí"
date: 2026-10-31
tags: inyeccion, windows internals, evasion, edr, malware analysis, red team, blue team, research
summary: Un mapa didáctico de 40 técnicas de inyección y ejecución avanzada agrupadas en 7 familias. Para cada una: qué es, cómo funciona por dentro y qué señal deja. Con el triángulo de legitimidad (región, hilo, apariencia), tablas comparativas, mitos frecuentes, glosario y bibliografía comentada con fuentes verificadas.
---

# Catálogo de inyección avanzada: las 7 familias del código que no debería estar ahí

Hay una pregunta que separa el juego de verdad de la nostalgia: **¿por qué un EDR ve lo que ve?**

No ve "malware". Ve objetos. Ve una región de memoria con un tipo (`MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`), una protección (`RX`, `RWX`), un módulo que la respalda —o ninguno— y un hilo que empieza a ejecutar en una dirección concreta. A partir de esos objetos reconstruye una historia. Si la historia no cuadra, salta la regla.

Toda la inyección avanzada, desde el thread hijacking de manual hasta el module overloading de hasherezade, se reduce a **cambiar uno de esos objetos para que la historia cuadre**.

Este artículo es un catálogo. No es un tutorial de "copia y pega": es el mapa mental de las técnicas, con **qué es**, **cómo funciona por dentro** y **qué señal deja**. Al final deberías poder mirar cualquier técnica nueva y ubicarla en una de las siete familias sin perderte.

> **Regla de oro:** ninguna técnica es invisible. Cada una no elimina la señal: la **mueve de sitio**. La pregunta correcta nunca es "¿me ven?", sino "¿qué ven ahora, y eso es consistente con lo que este proceso debería ser?".

## 🧭 El triángulo de legitimidad

Antes de la primera técnica, fija el modelo. Un proceso que ejecuta código ajeno tiene que responder tres preguntas simultáneas:

```text
                 ¿QUIÉN SOY?
          (región de memoria e inventario)
                    /\
                   /  \
                  /    \
     ¿DÓNDE VIVO? ----- ¿QUIÉN ME ARRANCA?
       (memoria)           (hilo, objeto, callback)
```

- **Dónde vive el código** (Familia 1): ¿la región es imagen, mapeada o privada? ¿Tiene un archivo detrás? ¿Está firmada?
- **Quién arranca la ejecución** (Familia 2 y 3): ¿el hilo nació en `ntdll`, en una API legítima, en un callback, en un objeto COM?
- **Cómo se ve el proceso** (Familia 4, 5 y 6): ¿la línea de comandos, el padre, los flags del PEB, la pila y el módulo cuentan una historia coherente?

Y una cuarta dimensión transversal: **qué queda en reposo** (Familia 7), porque el payload pasa más tiempo dormido que ejecutando.

> 💡 **Truco didáctico:** cuando veas una técnica nueva, pregúntate qué casilla del triángulo mueve. Si mueve dos o tres a la vez, es de las caras. Si mueve una sola, probablemente necesites combinarla con otra.

## 🗺️ Las siete familias de un vistazo

| Familia | Pregunta que responde | Qué cambia | Nº de técnicas |
|---|---|---|---|
| **1. Dónde vive** | ¿Qué tipo de región soy? | Tipo, respaldo, integridad del módulo | 8 |
| **2. Cómo arranca** | ¿Quién crea el hilo? | Origen del hilo, pila, API de disparo | 16 |
| **3. Activación por objetos** | ¿Quién me llama? | Registro COM, shell, WER, IFEO | 5 |
| **4. Cómo se ve el proceso** | ¿Qué dice mi biografía? | Línea de comandos, padre, flags | 4 |
| **5. Higiene de API y pila** | ¿Cómo llamo al kernel? | Syscalls, gadgets, stack walk | 3 |
| **6. Post-explotación** | ¿Dónde corre mi post-ex? | COFF/PIC dentro del módulo | 2 |
| **7. En reposo** | ¿Qué ven mientras duermo? | Cifrado, desmapeo, timers | 2 |

## 📖 Cómo leer las fichas

Cada técnica sigue el mismo formato: **qué es**, **cómo funciona**, **qué gana**, **qué cuesta** y **qué ve el sensor**. Los nombres de API son los del contrato real de Windows; no hace falta memorizarlos, están para que puedas buscarlos y verificar lo que lees.

---

## 🧬 Familia 1 — Dónde vive el código

Esta familia ataca la primera casilla: la **legitimidad de la región**. Un clasificador de memoria hace cuatro preguntas sobre una página ejecutable:

1. ¿Cuál es su `Type`? (`MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`)
2. ¿Qué `Protection` tiene? (`RX`, `RWX`, `EXECUTE_WRITECOPY`…)
3. ¿Qué archivo o sección la respalda?
4. ¿El contenido coincide con lo que ese archivo debería tener?

Cada técnica de esta familia miente en una de esas cuatro respuestas.

### Cuadro comparativo

| Técnica | Tipo que aparenta | Cómo se consigue | Señal residual |
|---|---|---|---|
| **Module stomping (full)** | `MEM_IMAGE` | Sobrescribir todo el `.text` de una DLL firmada | Hash del módulo alterado; páginas escribibles dentro de imagen |
| **Module overloading** | `MEM_IMAGE` | Sobrescribir solo huecos muertos entre funciones | Integridad casi intacta; placement complejo |
| **Phantom DLL hollowing** | Módulo en el PEB | Entradas falsas en las listas del PEB | La memoria sigue siendo `MEM_PRIVATE` |
| **Unlinking** | Módulo oculto | Deslinkear entradas reales del PEB | Inconsistencia entre enumeradores |
| **SEC_IMAGE + overwrite** | `MEM_IMAGE` | Sección de imagen sobre archivo legítimo y pisarla | Path raro o módulo no firmado |
| **Section aliasing** | `MEM_MAPPED` | Sección pagefile con vistas RW y RX | Dos vistas de la misma sección |
| **Dirty Vanity (fork)** | Clon de proceso | `RtlCloneUserProcess` | Telemetría de creación de proceso |
| **Data-only (ROP puro)** | Ninguna región nueva | Gadgets de módulos firmados | Cadenas de gadgets y pilas raras |

### 1.1 Module stomping (completo)

**Qué es.** Cargar una DLL firmada y legítima, y **sobrescribir toda su sección `.text`** con tu payload. La ejecución ocurre desde una región que el sistema considera imagen de un módulo firmado.

**Cómo funciona.** Localizas la base del módulo (`GetModuleHandle` o recorriendo el PEB), lees su cabecera PE para encontrar la sección `.text` y su tamaño, cambias la protección a escritura, copias el shellcode y restauras la protección. Después desvías la ejecución a esa dirección. La DLL original queda destruida: si alguien llama a una de sus funciones, el proceso probablemente muera.

**Paso a paso mental.**
1. Elegir una DLL firmada ya cargada y **prescindible** (una que el proceso no vaya a volver a usar).
2. Calcular `base + RVA` de `.text` y comprobar que el payload cabe en su `SizeOfRawData`.
3. Cambiar la protección de esa sección a `PAGE_READWRITE`.
4. Copiar el payload.
5. Restaurar `PAGE_EXECUTE_READ` (o dejar la vista con la protección original).
6. Arrancar la ejecución con cualquier técnica de la Familia 2.

**Variantes.** *Self-stomping* (en el propio proceso) o *remote* (abriendo el proceso objetivo). La variante limpia es la **efímera**: al terminar el trabajo, restaurar el `.text` original desde el archivo en disco. En Kagemusha F14 se hizo exactamente eso, y `pe-sieve` no encontró parches en `msi.dll` porque la sección volvió a su contenido legítimo.

**Qué gana.** Mata de raíz la heurística de "memoria ejecutable no respaldada": el sensor ve `MEM_IMAGE` y un módulo con firma válida.

**Qué cuesta.** La integridad del módulo deja de coincidir con el archivo en disco. Un EDR que compare el hash de las páginas con el `.text` original lo detecta; y la DLL rota es una bomba de relojería: cualquier llamada a sus funciones revienta.

**Qué ve el sensor.** Comparación hash memoria vs. disco, protección de páginas dentro de una imagen, y el hecho de que el hilo ejecute en una zona que no es el entry point del módulo.

### 1.2 Module overloading (hasherezade)

**Qué es.** La versión elegante del anterior: en vez de pisar todo el `.text`, usar solo el **espacio muerto** —slack entre funciones, padding de alineación, secciones que no se usan en runtime—.

**Cómo se encuentran los huecos.** Hay tres fuentes típicas: el **padding de alineación** entre funciones (las funciones suelen alinearse a 16 bytes y sobra relleno), las **regiones de relleno** (`0xCC` o `0x00` repetidos) que el compilador deja entre bloques, y las **secciones que dejan de usarse** tras la carga (por ejemplo, `.reloc` una vez aplicadas las relocaciones). Se localizan parseando la tabla de exports, el directorio de excepciones (`.pdata`) o simplemente buscando runs de relleno lo bastante largos.

**Cómo funciona.** El payload se escribe en esos huecos y se ejecuta desde ahí, normalmente con un pequeño stub que salta de hueco en hueco si el payload está partido. La DLL sigue funcionando porque su código real no se toca.

**Variante por etapas.** Si el payload no cabe de una pieza, se parte en trozos, se colocan en varios huecos y un stub de pocos bytes los encadena. Es más trabajo, pero permite meter un beacon que no cabría en un solo gap.

**Qué gana.** La DLL mantiene su funcionalidad y su integridad aparente mucho mejor. Es la variante más limpia para un beacon pequeño.

**Qué cuesta.** Necesitas espacio contiguo suficiente o un payload más pequeño; el placement es más complejo y frágil entre versiones de la DLL. Un EDR que hashee **por páginas** (no por módulo entero) sigue viendo las páginas modificadas.

**Qué ve el sensor.** Páginas ejecutables dentro de una imagen con contenido que no coincide con el archivo; pero sin el destrozo burdo del stomping completo. Es más difícil de arbitrar porque la mayor parte del `.text` sigue intacta.

### 1.3 Phantom DLL hollowing

**Qué es.** Crear una **entrada falsa de módulo** en las listas del PEB que apunta a tu propia memoria, sin archivo en disco. El PEB mantiene tres listas enlazadas de módulos cargados: `InLoadOrderModuleList` (orden de carga), `InMemoryOrderModuleList` (orden en memoria) e `InInitializationOrderModuleList` (orden de inicialización), todas colgando de `PEB->Ldr`.

**Cómo funciona.** Se construye un `LDR_DATA_TABLE_ENTRY` plausible: los tres pares de enlaces (`Flink`/`Blink`), `DllBase`, `EntryPoint`, `SizeOfImage`, `FullDllName` y `BaseDllName` como `UNICODE_STRING` cuyos buffers viven en tu propia memoria. Después se enlaza en las tres listas ajustando los enlaces de los vecinos. Los enumeradores de módulos, y muchos EDR que construyen su inventario desde el PEB, la ven como un módulo legítimo más.

**Por qué "hollowing".** Porque creas el **caparazón** de un módulo (solo los metadatos) sin el contenido real respaldado por un archivo: el nombre y la estructura están, la imagen no.

**El detalle que casi nadie explica.** El tipo de memoria **sigue siendo `MEM_PRIVATE`**. Quien mire `MEMORY_BASIC_INFORMATION` verá memoria privada, no imagen. Es un disfraz del inventario, no del tipo de página. Las reglas que miran allocation-type pueden seguir viendo ejecución unbacked, así que esta técnica se combina muy bien con la 1.6: la entrada fantasma da el nombre y la sección mapeada da un tipo menos sospechoso. Aun así, solo una sección de imagen real produce `MEM_IMAGE`.

**Qué gana.** Disfraza el **inventario**: tu memoria aparece como si fuera una DLL cargada, y los enumeradores que solo miran el PEB se lo creen.

**Qué cuesta.** Hay que mantener vivos los buffers de los nombres y la propia entrada mientras dure el disfraz; si el proceso recorre las listas mientras las modificas, puedes corromper el recorrido. Y no engaña a quien compare con el kernel.

**Qué ve el sensor.** El `Type` real de la región y el contraste entre el PEB y las estructuras del kernel (VAD, lista de módulos cargados).

### 1.4 PEB masquerading inverso (unlinking)

**Qué es.** Lo contrario del anterior: **quitar** módulos reales de las listas del PEB para que no aparezcan. Se usa para ocultar los propios, no para ejecutar.

**Cómo funciona.** Cada entrada es un nodo de una lista doblemente enlazada. Desenlazarla consiste en hacer que el `Flink` del nodo anterior apunte al `Blink` del siguiente y viceversa, y repetir en las tres listas. El módulo sigue mapeado, pero invisible para quien enumere solo el PEB.

**El peligro del desenlace.** Si desenlazas mientras otro hilo recorre la lista, el recorrido puede caer en un puntero muerto. Por eso se hace con cuidado y, si el proceso va a seguir vivo, conviene **restaurar** los enlaces antes de terminar.

**Qué gana.** Oculta módulos de los recorridos clásicos del PEB.

**Qué cuesta.** Rompe supuestos del propio proceso y no engaña a quien enumere por VAD, handles de sección o la lista de kernel. Es una técnica de ocultación, no de ejecución: no aporta nada si el payload no está ya colocado.

**Qué ve el sensor.** La incoherencia entre lo que dice el PEB y lo que dice el kernel: módulos mapeados que no están en las listas, o viceversa.

### 1.5 SEC_IMAGE con overwriting

**Qué es.** Crear una **sección de imagen** (`SEC_IMAGE`) sobre un archivo legítimo, mapearla y después pisar sus páginas con el payload.

**Cómo funciona.** `NtCreateSection` con `SEC_IMAGE` sobre el archivo, `NtMapViewOfSection` para obtener la vista, y una primitiva de escritura para sobrescribir el contenido. La región resultante es `MEM_IMAGE`, con las secciones del PE ya mapeadas por el gestor de memoria.

**El muro de VBS/HVCI.** Las secciones de imagen suelen ser **no escribibles** cuando la integridad de código está activa: el sistema bloquea las vistas escribibles de imágenes y el overwrite falla con `STATUS_INVALID_PARAMETER` o `ACCESS_DENIED`. Por eso esta técnica se apoya a menudo en una segunda vista o en un archivo que no esté bajo esa política. Existe además `SEC_IMAGE_NO_EXECUTE`, pensada para mapear sin ejecutar (la usan los antivirus), que no sirve para este fin.

**Qué gana.** El tipo de memoria es imagen, con el respaldo de un archivo real y una ruta que puede ser perfectamente legítima.

**Qué cuesta.** El muro de VBS/HVCI, el riesgo de que el path o el módulo no estén firmados, y que el hash de la imagen deje de coincidir con el fichero.

**Qué ve el sensor.** La ruta del archivo, su firma, el hash de la imagen y si la vista mapeada coincide con el fichero.

### 1.6 Section aliasing / allocation-type masquerading

**Qué es.** En vez de memoria anónima `MEM_PRIVATE`, usar una **sección respaldada por pagefile** con dos vistas: una `RW` para escribir y cifrar, otra `RX` para ejecutar. El tipo pasa a ser `MEM_MAPPED`.

**Cómo funciona.** `NtCreateSection` sobre pagefile (sin archivo detrás), y dos `NtMapViewOfSection` de la **misma** sección con protecciones distintas: escribes por la vista RW, ejecutas por la vista RX. Las dos vistas apuntan a las mismas páginas físicas, así que lo que escribes por una se ve por la otra.

**Por qué W^X sin RWX.** Ninguna vista es escribible y ejecutable a la vez: la de escritura no ejecuta y la de ejecución no escribe. El clásico `PAGE_EXECUTE_READWRITE` desaparece del mapa, y con él la regla más simple de todas.

**El detalle de Okugi.** Esta es exactamente la arquitectura del loader: la sección es `MAPPED`, no `PRIVATE`, con vista RW para descifrar y vista RX para ejecutar. Por eso algunas reglas de "private RWX" no la tocan. El precio es que los handles de sección y las dos vistas son objetos visibles.

**Qué gana.** Evita las reglas de "private RWX" y mantiene W^X de forma estructural.

**Qué cuesta.** Sigue siendo memoria ejecutable sin archivo detrás; los handles de sección y las dos vistas son visibles, y cada map/unmap deja su evento. Durante el sueño conviene desmapear (Familia 7).

**Qué ve el sensor.** `MEM_MAPPED` ejecutable, el handle de la sección, dos vistas de la misma sección y los eventos de map/unmap.

### 1.7 Dirty Vanity (forking)

**Qué es.** Duplicar el proceso actual con `RtlCloneUserProcess` **después** de colocar el payload, de modo que el clon "nazca" ya con el código dentro.

**Cómo funciona.** `RtlCloneUserProcess` con la bandera de crear el clon suspendido devuelve handles al proceso y al hilo clonados. El espacio de direcciones se copia, y el hilo clonado continúa —tras reanudarlo— con el payload ya presente. No hay inyección clásica: el código estaba ahí desde el nacimiento del clon.

**Qué copia y qué no.** No es un `fork` de POSIX: se duplica el llamador y su contexto, no todos los hilos, y los handles y objetos del kernel tienen su propia semántica. Ese matiz es la fuente de la mayoría de los fallos al usarlo.

**Qué gana.** Elimina las primitivas de inyección tradicionales y le da al clon un linaje de proceso legítimo: el payload no llega "después", nace con el proceso.

**Qué cuesta.** Es **muy ruidosa** en telemetría de procesos: la creación del clon, la API en sí y los handles duplicados son eventos poco comunes y muy accionables.

**Qué ve el sensor.** El evento de creación de proceso, la llamada a `RtlCloneUserProcess` y la relación padre-hijo.

### 1.8 Data-only execution (ROP puro)

**Qué es.** Ejecutar el stager **entero por ROP**, usando gadgets de módulos firmados. Cero memoria ejecutable propia: el contador de regiones ejecutables nuevas es cero absoluto.

**Cómo funciona.** Un gadget es una secuencia corta de instrucciones que termina en `ret` (por ejemplo, `pop rcx; ret`). La cadena ROP es una lista de direcciones en la pila: cada `ret` salta al siguiente gadget. Con suficientes gadgets se monta una llamada a API: se cargan los argumentos en `RCX`, `RDX`, `R8` y `R9` con gadgets `pop`, se salta a la función y se continúa la cadena con el valor de retorno. La ejecución salta de gadget en gadget dentro de código legítimo.

**Variantes.** ROP clásico (ret), JOP (saltos indirectos) y COP (llamadas). La escuela de SysWhispers-ROP genera cadenas para syscalls; SilentMoonwalk se centra en la pila y el stack walk.

**Por qué solo el stager.** Una cadena ROP es enormemente frágil: depende de la build exacta de Windows, de los offsets de cada gadget y de la disposición de la pila. Sirve para un stager corto que coloca algo más, no para un beacon completo con su lógica.

**Qué gana.** No hay región ejecutable propia que clasificar: la ejecución vive en código firmado.

**Qué cuesta.** Fragilidad extrema y dependencia de la build; además, CET y el *shadow stack* rompen el ROP clásico cuando están activos.

**Qué ve el sensor.** Pilas con cadenas de retorno improbables, saltos entre gadgets y un stack walk que no cuadra con ninguna función real.

---

## 🧵 Familia 2 — Cómo arranca la ejecución

La segunda casilla es la **legitimidad del hilo**. Al sensor le importa:

- ¿En qué dirección **empieza** el hilo?
- ¿Qué **pila** tiene en el momento de crear?
- ¿Nació de una API legítima o de una escritura de contexto?
- ¿Es un hilo nuevo, un worker del pool, o un hilo secuestrado?

Aquí hay muchas variantes porque Windows ofrece muchas formas de "llámame luego".

### Cuadro comparativo

| Técnica | Qué es | Cómo arranca |
|---|---|---|
| **Thread pool work items** | Trabajo encolado en el pool | `TpAllocWork` + `TpPostWork`; lo ejecuta un worker de `ntdll` |
| **Thread pool timers / waits** | Disparo diferido o por evento | `CreateThreadpoolTimer`, `TpAllocWait`, `RegisterWaitForSingleObject` |
| **Thread hijacking** | Secuestro de un hilo vivo | `SuspendThread` + `SetThreadContext` (RIP) + `ResumeThread` |
| **Special user APC** | APC que corre sin alertable | `NtQueueApcThreadEx` con `SPECIAL_USER_APC` |
| **Early Bird** | APC antes de que el hilo arranque | Proceso suspendido + APC + `ResumeThread` |
| **Fibers** | Contexto de ejecución propio | `ConvertThreadToFiber` + `CreateFiber` + `SwitchToFiber` |
| **Thread start spoofing** | Start address falsa | `NtCreateThreadEx` en un thunk de `ntdll`, entry real por parámetro |
| **Callback overloading** | Ser el callback de una API | Registrar payload como callback y disparar la API |
| **Loader notifications** | Aviso de carga de DLL | `LdrRegisterDllNotification` |
| **WinEvent hook in-context** | Callback de eventos de ventana | `SetWinEventHook` en el propio hilo |
| **`SetWindowsHookEx` local** | Hook sin DLL global | Hook in-context a un hilo propio |
| **Exception dispatch** | Dispatcher de excepciones | VEH / `SetUnhandledExceptionFilter` + `RaiseException` |
| **Instrumentation callback** | Callback por syscall | `ProcessInstrumentationCallback` |
| **Console ctrl handler** | Callback de consola | `SetConsoleCtrlHandler` |
| **Job / completion port** | Callback de ciclo de vida | `JobObjectAssociateCompletionPortInformation` |
| **Timer queue legacy** | Timer con hilo del sistema | `RtlCreateTimerQueue` + `RtlCreateTimerQueueTimer` |

### 2.1 Thread pool work items

**Qué es.** Encolar tu payload como un *work item* del pool de hilos. El hilo que lo ejecuta es un **worker de `ntdll`**, no un hilo nuevo tuyo.

**Cómo funciona.** `TpAllocWork` reserva la estructura, `TpPostWork` la encola. Cuando un worker queda libre, ejecuta el callback. La pila muestra frames del pool (`TppWorkerThread`) y el hilo existe desde antes.

**Qué gana.** No creas hilos y el origen del hilo es legítimo. Es una de las formas más limpias de "ejecutar sin hilo propio".

**Qué cuesta.** Las estructuras de work item y los eventos de thread pool son visibles; el callback apunta a memoria que puede no estar respaldada.

**Qué ve el sensor.** Eventos ETW de thread pool, el callback registrado y la dirección de ejecución.

### 2.2 Thread pool timers y wait callbacks

**Qué es.** Variantes con **disparo**: el payload no corre al encolarse, sino cuando vence un timer o se cumple una espera.

**Cómo funciona.** `CreateThreadpoolTimer` ejecuta el callback al vencer; `TpAllocWait` y `RegisterWaitForSingleObject` lo ejecutan cuando un objeto se señaliza. Igual que el work item, lo corre un worker del sistema.

**Qué gana.** Añade una condición de activación natural y separa el "arma" del "disparo".

**Qué cuesta.** Deja objetos de timer o de espera registrados, y el callback sigue siendo una dirección a inspeccionar.

### 2.3 Thread hijacking

**Qué es.** **Secuestrar un hilo que ya existe**: suspenderlo, cambiar su `RIP` para que apunte al payload y reanudarlo.

**Cómo funciona.** `SuspendThread`, `GetThreadContext`, se reescribe el registro de instrucción, `SetThreadContext`, `ResumeThread`. La escuela de BumbleBee y Pikabot.

**Qué gana.** No creas hilo: el sensor ve un hilo que ya estaba vivo.

**Qué cuesta.** La pila del hilo no corresponde con la nueva dirección de ejecución; el hilo puede estar en kernel y no aceptar el cambio; y los eventos de contexto de hilo son sospechosos.

**Qué ve el sensor.** Cambios de contexto, `RIP` fuera de cualquier función conocida y una pila que no encaja.

### 2.4 Special user APC

**Qué es.** Encolar un **APC especial** que se ejecuta aunque el hilo no esté en estado alertable.

**Cómo funciona.** `NtQueueApcThreadEx` con la bandera `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` sobre un hilo existente. El kernel entrega la rutina en el siguiente punto seguro.

**Qué gana.** Técnica moderna y poco instrumentada; no depende de que el hilo esté esperando.

**Qué cuesta.** Necesitas un hilo objetivo válido, y la cola de APC deja rastro en telemetría.

**Qué ve el sensor.** Encolado de APC, dirección de la rutina y el hecho de que el hilo ejecute código que no pidió.

### 2.5 Early Bird

**Qué es.** Encolar un APC a un hilo **antes de que empiece a ejecutar**.

**Cómo funciona.** Se crea el proceso suspendido, se encola el APC sobre su hilo principal y se reanuda. El APC corre antes que el entry point real.

**Qué gana.** El payload ejecuta antes de que el proceso "arranque", con un hilo legítimo.

**Qué cuesta.** Es la variante **más firmada** de la familia: herramientas y EDR llevan años detectando exactamente esta secuencia.

**Qué ve el sensor.** Proceso creado suspendido, APC encolado antes de la reanudación y ejecución previa al entry point.

### 2.6 Fibers

**Qué es.** Convertir el hilo actual en un **fiber** y crear otro fiber para el payload.

**Cómo funciona.** `ConvertThreadToFiber` convierte el hilo en anfitrión; `CreateFiber` crea el contexto del payload; `SwitchToFiber` salta a él. El hilo original sigue siendo "legítimo".

**Qué gana.** El hilo del sistema no cambia; la ejecución ocurre en un contexto de fiber gestionado por user-mode.

**Qué cuesta.** Las APIs de fiber son poco comunes y el cambio de pila es visible.

### 2.7 Thread start spoofing

**Qué es.** Crear un hilo cuya **dirección de inicio parece legítima** —un thunk de `ntdll`— pero cuyo entry real llega por parámetro o contexto.

**Cómo funciona.** `NtCreateThreadEx` con un start address que es un stub legítimo; el payload se pasa como argumento y el stub lo desvía. Nivel Nighthawk.

**Qué gana.** El sensor que solo mira el start address ve `ntdll`.

**Qué cuesta.** El contexto del hilo y el parámetro no cuadran; es una técnica de estado del arte que exige mucho control.

### 2.8 Callback overloading

**Qué es.** **Ser el callback** de una API legítima: registras tu payload como función de callback y la API lo llama por ti. El hilo entra por una ruta que el sistema considera normal.

**Cómo funciona.** Se elige una API que acepte un callback y se dispara: `CertEnumSystemStoreLocation`, `CryptEnumProviders`, `EnumWindows`/`EnumChildWindows`, `EnumDateFormatsEx`, `RegisterApplicationRestart`, `EnumPrinters`, `SetupDiEnumDriverInfo`, `EnumFonts`, `NotifyIpInterfaceChange`, `EnumSystemLocalesA`… La API itera y llama a tu función.

**Qué gana.** El origen de la llamada es una API documentada y el hilo es del sistema.

**Qué cuesta.** La lista de APIs está cada vez más **quemada como IOC**, y suelen ser *one-shot*: un disparo y ya.

**Qué ve el sensor.** La API disparadora, el callback en memoria no respaldada y el patrón de "API de enumeración que llama a una dirección rara".

### 2.9 Loader notifications

**Qué es.** Registrar un callback que se dispare la **próxima vez que el proceso cargue cualquier DLL**.

**Cómo funciona.** `LdrRegisterDllNotification` guarda tu función; el loader la invoca en cada carga de módulo. Es un disparo contextual natural.

**Qué gana.** El momento del disparo es orgánico y poco vigilado; no necesitas una API de enumeración.

**Qué cuesta.** El registro y el callback son inspeccionables, y necesitas que ocurra una carga de DLL.

### 2.10 WinEvent hooks y hooks locales

**Qué es.** Dos variantes de callback de ventana: `SetWinEventHook` **in-context** en tu propio hilo, o `SetWindowsHookEx` in-context a un hilo propio **sin DLL global**.

**Cómo funciona.** Registras el hook y el sistema llama a tu función cuando ocurre el evento o llega el mensaje. Al ser in-context y sobre tu hilo, no necesitas inyectar una DLL.

**Qué gana.** Callback legítimo, sin archivo en disco y sin inyección global.

**Qué cuesta.** Depende de que haya eventos o mensajes, y los hooks son estructuras visibles.

### 2.11 Exception dispatch

**Qué es.** Usar el **dispatcher de excepciones** como punto de entrada: registras un handler y provocas una excepción; la ejecución empieza desde el camino kernel → `ntdll`.

**Cómo funciona.** `AddVectoredExceptionHandler`, `AddVectoredContinueHandler` o `SetUnhandledExceptionFilter`, y después `RaiseException`. El dispatcher llama a tu handler. Es la escuela de *ghostwrap*.

**Qué gana.** El origen es el mecanismo de excepciones del sistema, no una llamada directa.

**Qué cuesta.** Genera telemetría de excepciones y los handlers registrados son enumerables.

### 2.12 Instrumentation callback

**Qué es.** Registrar un callback que el kernel invoca en **cada retorno de syscall** del proceso.

**Cómo funciona.** `NtSetInformationProcess` con `ProcessInstrumentationCallback` instala la rutina. Se usa para observar syscalls (como hace Okugi en E1), pero también puede servir de dispatcher de ejecución.

**Qué gana.** Es un mecanismo del propio sistema, con cobertura total.

**Qué cuesta.** Es **muy** inusual: un solo callback por proceso y una señal fortísima para cualquier sensor que lo consulte.

### 2.13 Console, jobs y timer queue

**Qué es.** Callbacks de infraestructura: eventos de consola (`SetConsoleCtrlHandler`), mensajes de completion port asociados a un job (`JobObjectAssociateCompletionPortInformation`) y timers legacy (`RtlCreateTimerQueue`).

**Cómo funciona.** Registras el callback y el sistema lo invoca cuando ocurre el evento: Ctrl+C o cierre de consola, cambio de estado del job, o vencimiento del timer en un hilo del sistema.

**Qué gana.** Disparos diferidos y de bajo perfil, con hilos del sistema.

**Qué cuesta.** Requieren que ocurra el evento y dejan objetos registrados.

---

## 🧩 Familia 3 — Activación por objetos

Aquí el sistema no te llama por un callback de API, sino porque **te registraste como proveedor de un objeto**. La ejecución la dispara el mecanismo de activación del propio Windows.

La diferencia mental es importante. En la Familia 2 tú **empujas** ejecución: creas un hilo, encolas un APC, secuestras un contexto. Aquí haces lo contrario: te das de alta en un registro del sistema y dejas que el sistema **tire de ti** cuando ocurra el evento. Es un modelo *pull*.

Y eso cambia por completo el perfil de la señal:

- **Ganas** un origen de ejecución que el sistema considera suyo: el activador de COM, Explorer, WER, el debugger del sistema.
- **Pagas** con un **registro**. Y el registro es el ancla: vive en el proceso, en el registry o en disco.

### Cuadro comparativo

| Técnica | Modelo | Dónde corre | Registro necesario | Rompe fileless | Señal principal |
|---|---|---|---|---|---|
| **COM in-proc en memoria** | Objeto COM local | Tu proceso | Tabla de clases del proceso | **No** | CLSID y clase registrada |
| **COM surrogate hijack** | Servidor COM fuera de proceso | `dllhost.exe` | Registry (AppID / LocalServer32) y DLL | **Sí** | `dllhost` lanzado por COM |
| **ShellExt / verbos de shell** | Extensión de Explorer | `explorer.exe` | Registry + DLL en disco | **Sí** | Explorer cargando DLL sin firma |
| **WerNotify / SilentProcessExit** | Callback de WER o monitor de salida | WER o proceso monitor | Registry (IFEO) | **Sí** | Proceso lanzado al morir otro |
| **IFEO / AEDebug** | Secuestro del debugger | Debugger del sistema | Registry | **Sí** | Debugger adjuntado o lanzado |

> 📌 **Regla de esta familia:** solo la variante **in-proc en memoria** conserva el fileless. Todo lo que necesite registry o disco deja de ser "sin archivo" y pasa a ser **persistencia**, con otro perfil de detección.

### 3.0 In-proc vs. out-of-proc

Antes de las fichas, fija la diferencia, porque decide casi todo:

- **In-proc**: el servidor vive **dentro de tu proceso**. COM lo activa en tu propio espacio de direcciones. No hay archivo, no hay registry, no hay proceso nuevo. Es la variante limpia.
- **Out-of-proc**: el servidor vive **fuera**, en otro proceso (a menudo `dllhost.exe` o `svchost.exe`). COM lo lanza a través de RPC, y para encontrarlo necesita una entrada en el registry. Ganas aislamiento y supervivencia, pero pierdes el fileless.
- **Persistencia**: las variantes de shell, WER e IFEO no buscan ejecutar "ya", sino **volver a ejecutar** cuando ocurra un evento. Son otra categoría aunque compartan mecanismo.

### 3.1 COM in-proc en memoria

**Qué es.** La versión limpia y local de "inyección por activación": un servidor COM **en memoria**, sin DLL en disco, dentro de tu propio proceso.

**Cómo funciona.** Implementas una `IClassFactory` —con `QueryInterface`, `AddRef`, `Release`, `CreateInstance` y `LockServer`— y la registras con `CoRegisterClassObject` para un CLSID, indicando `CLSCTX_INPROC_SERVER` y un modo como `REGCLS_MULTIPLEUSE`. Cuando alguien llama a `CoCreateInstance` sobre ese CLSID, COM busca primero en su tabla de clases del proceso, encuentra tu factoría y te invoca `CreateInstance`. Ahí empieza tu código.

**Paso a paso mental.**
1. `CoInitializeEx` para entrar en el modelo de apartamentos (STA o MTA).
2. Crear tu objeto y su `IClassFactory`.
3. `CoRegisterClassObject` con el CLSID elegido y el contexto in-proc.
4. `CoCreateInstance` sobre ese mismo CLSID.
5. COM llama a tu `CreateInstance`: ejecución disparada por el mecanismo de objetos.
6. Al terminar, `CoRevokeClassObject` y `CoUninitialize`.

**El matiz de los apartamentos.** En un apartamento *single-threaded* (STA), COM puede **marshaling** la llamada al hilo del apartamento en vez de ejecutarla en el llamador. Eso significa que el hilo que acaba ejecutando tu `CreateInstance` puede no ser el que llamó a `CoCreateInstance`. No es un problema, pero explica por qué a veces el stack no es el que esperabas.

**Qué gana.** El hilo entra por el activador de COM, con una ruta de sistema perfectamente documentada, sin crear hilos, sin escribir contexto y sin archivo en disco. Es la forma más limpia de "ejecutar por activación".

**Qué cuesta.** El registro de clase es visible y el CLSID es un ancla: un CLSID raro o una clase in-proc que no corresponde a ninguna DLL registrada es una señal fuerte. COM tiene telemetría propia, y tu factoría debe responder correctamente a las expectativas de COM o la activación falla.

**Qué ve el sensor.** La tabla de objetos de clase del proceso, el CLSID registrado, y el contraste entre "clase in-proc registrada" y "no hay DLL en disco que la respalde". También el origen COM del hilo que ejecuta.

### 3.2 COM surrogate hijack (dllhost)

**Qué es.** Registrar o abusar de un servidor COM **fuera de proceso** para que COM lo lance en un proceso surrogate, típicamente `dllhost.exe`.

**Cómo funciona.** Se declara un `AppID` con `DllSurrogate` o un `LocalServer32` en el registry, y se activa con `CLSCTX_LOCAL_SERVER`. COM arranca `dllhost.exe /Processid:{AppID}` y carga allí el servidor. El código corre fuera de tu proceso, con la identidad y el ciclo de vida que COM decida.

**Qué gana.** Aislamiento y supervivencia: el servidor puede seguir vivo aunque tu proceso muera, y el proceso anfitrión es uno de sistema.

**Qué cuesta.** **Rompe el fileless**: necesita registry y, casi siempre, una DLL en disco. Añade RPC, permisos y una cadena de activación larga y visible.

**Qué ve el sensor.** El lanzamiento de `dllhost` por COM, las claves `AppID`/`LocalServer32`, las escrituras en registry y el tráfico RPC de activación.

### 3.3 ShellExt / IInitializeCommand / verbos de shell

**Qué es.** Registrarse como **extensión del shell** o como **verbo de comando** para que Explorer te cargue o te invoque cuando el usuario interactúe.

**Cómo funciona.** Las extensiones de shell son servidores COM in-proc que Explorer carga en su propio proceso; se registran bajo `InprocServer32` de un CLSID. Los verbos (`shell\open\command`, menús contextuales) se declaran en el registry y Explorer los ejecuta. `IInitializeCommand` es la interfaz que implementa un manejador de comandos de línea para inicializarse con el verbo.

**Qué gana.** La activación la hace Explorer, un proceso de confianza, y el disparo es natural: abrir un archivo, hacer clic derecho.

**Qué cuesta.** Es **persistencia con disfraz de activación**: requiere registry y DLL en disco, depende de la interacción del usuario y es ruidosa. Explorer cargando una DLL sin firma es una de las señales más viejas del catálogo.

**Qué ve el sensor.** Explorer cargando una DLL no firmada, las claves de registro de la extensión y la enumeración de extensiones del shell.

### 3.4 WerNotify / SilentProcessExit

**Qué es.** Hacer que **Windows Error Reporting** o el mecanismo de **salida silenciosa** invoquen tu código cuando un proceso muera o falle.

**Cómo funciona.** `SilentProcessExit` usa claves de IFEO con `GlobalFlag` y un proceso monitor (`MonitorProcess`): cuando el proceso objetivo termina, el sistema lanza el monitor. Las variantes de WER registran módulos o callbacks que se invocan durante la recolección de un crash (`WerRegisterRuntimeExceptionModule` y familia). En ambos casos, el disparador es la **muerte** de otro proceso.

**Qué gana.** Activación diferida y contextual: no ejecutas al arrancar, sino cuando ocurre el evento que te interesa.

**Qué cuesta.** Requiere registry, es **persistencia** y deja un proceso nuevo justo cuando otro muere: una correlación muy visible.

**Qué ve el sensor.** Las claves de IFEO, el lanzamiento del proceso monitor y la telemetría de WER.

### 3.5 IFEO / AEDebug

**Qué es.** Secuestrar el **debugger** que Windows asocia a un ejecutable, mediante *Image File Execution Options* o la clave `AeDebug`.

**Cómo funciona.** Bajo `Image File Execution Options\<ejecutable>` se pone un valor `Debugger`: cuando ese ejecutable arranque, Windows lanzará tu binario como su debugger. `AeDebug` define el debugger **postmortem** que se lanza cuando un proceso falla.

**Qué gana.** El sistema te entrega el control de otro proceso con una ruta de depuración legítima y, en el caso de `AeDebug`, en el momento del crash.

**Qué cuesta.** Disco más registry, y es una de las técnicas **más telemetrizadas** que existen: los EDR vigilan IFEO y `AeDebug` desde hace años.

**Qué ve el sensor.** Escrituras en las claves de IFEO o `AeDebug`, el lanzamiento del debugger y su adjunción al proceso objetivo.

### 3.6 Cómo se encadena con las otras familias

La Familia 3 resuelve la **pregunta del hilo** ("¿quién me arranca?") sin tocar la memoria. Por eso se combina de forma natural:

```text
[REGIÓN]   sección mapeada o módulo stompeado   (Familia 1)
   ↓
[OBJETO]   IClassFactory registrada en memoria  (Familia 3.1)
   ↓
[ACTIVACIÓN] CoCreateInstance -> CreateInstance
   ↓
[APARIENCIA] PEB poison + stack spoof           (Familia 4 + 5)
```

El resultado es un stack en el que la región es legítima, el hilo nace del activador de COM y la biografía del proceso está limpia. El precio sigue siendo el mismo: el CLSID registrado es el hilo del que tirar en un análisis.

---

## 🎭 Familia 4 — Cómo se ve el proceso

La cuarta casilla es la **biografía**: lo que la telemetría y el forense leen sobre quién eres. Y aquí hay una verdad incómoda: **leen el PEB, no la copia real del bloque de parámetros**.

| Técnica | Qué es | Cómo funciona |
|---|---|---|
| **Process Parameter Poisoning** | Reescribir la línea de comandos | Modificar `PEB->ProcessParameters` después del arranque |
| **PPID spoofing** | Padre falso | `UpdateProcThreadAttribute` + `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` |
| **Thread hiding** | Ocultar hilos | `NtSetInformationThread` con `ThreadHideFromDebugger` |
| **Flags del PEB** | Higiene del proceso | Limpiar `NtGlobalFlag`, flags del LDR y `ProcessFlags` |

### 4.1 Process Parameter Poisoning

**Qué es.** Reescribir `PEB->ProcessParameters` —`CommandLine`, `ImagePathName`, incluso `CurrentDirectory`— **después** de que el proceso arranque, para que la telemetría vea un comando inocuo.

**Cómo funciona.** Se llega al PEB por `NtCurrentTeb()->ProcessEnvironmentBlock`, se localiza `ProcessParameters` y se reemplaza el `UNICODE_STRING` de la línea de comandos: nuevo buffer, `Length` y `MaximumLength` coherentes. La copia original que queda en el heap del proceso puede seguir existiendo, así que hay que decidir cuál se pisa y cuál se deja.

**Por qué importa en el laboratorio.** En Okugi la clave RC4 del `.kc3` viajaba en la línea de comandos, y se vio en Elastic. El arreglo correcto es doble: **(a)** mover la clave al blob (cabecera) y **(b)** envenenar los parámetros para que la telemetría muestre un comando aburrido.

**Qué ve el sensor.** La línea de comandos del PEB, su longitud, y la posible discrepancia con la copia original o con el binario en disco.

### 4.2 PPID spoofing

**Qué es.** Hacer que un proceso que lanzas parezca hijo de otro proceso legítimo.

**Cómo funciona.** `UpdateProcThreadAttribute` con `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` antes de `CreateProcess`. El campo de proceso padre se rellena con el PID elegido.

**Qué gana.** Rompe la correlación padre-hijo que usan muchos EDR.

**Qué cuesta.** El padre declarado puede no haber creado realmente el proceso; la telemetría de linaje lo delata.

### 4.3 Thread hiding

**Qué es.** Ocultar un hilo de debuggers e introspección basada en ALPC.

**Cómo funciona.** `NtSetInformationThread` con `ThreadHideFromDebugger` sobre el hilo del payload.

**Qué gana.** El hilo desaparece de varias vistas de depuración.

**Qué cuesta.** La propia llamada y el flag son consultables; no oculta el hilo de todos los sensores.

### 4.4 Higiene de flags del PEB

**Qué es.** Limpiar las marcas que delatan que el proceso está depurado o que se creó en condiciones raras: `NtGlobalFlag`, flags del LDR y `ProcessFlags`.

**Cómo funciona.** Se localiza el campo en el PEB o en el heap y se pone a cero el valor esperado para un proceso normal.

**Qué gana.** Elimina indicadores clásicos de "este proceso está siendo analizado o nació mal".

**Qué cuesta.** Es higiene, no invisibilidad: no cambia la memoria ni el hilo.

---

## 🪄 Familia 5 — Higiene de API y pila

Esta familia no cambia dónde vives ni quién te arranca: cambia **cómo llamas al kernel** y **qué pila muestras** cuando lo haces.

### 5.1 Indirect syscalls + rotación de gadgets

**Qué es.** En vez de tener la instrucción `syscall` en tu propio código, saltar al gadget `syscall; ret` que ya existe en `ntdll`.

**Cómo funciona.** Se resuelve el SSN en runtime (por orden de export, estilo FreshyCalls), se elige un gadget de `ntdll` y se salta a él con los argumentos preparados. La **rotación** consiste en no usar siempre el mismo gadget, para no dejar una firma fija.

**Qué gana.** El `syscall` ocurre en memoria de `ntdll`, y el call stack parece más legítimo. Es la base de Okugi.

**Qué cuesta.** Elegir gadgets por build y mantener la coherencia de la pila; un gadget equivocado rompe todo.

### 5.2 Call stack spoofing

**Qué es.** Construir una **pila plausible** con `push`/`ret` sobre direcciones de módulos reales, para que el stack walk no vea un frame inicial no respaldado.

**Cómo funciona.** Se encadenan direcciones de retorno de funciones firmadas y se ajusta la pila para que el unwinder recorra una historia creíble. Escuela SilentMoonwalk / Nighthawk.

**Qué gana.** Cierra el `frame[0]` unbacked, que es una de las señales más usadas.

**Qué cuesta.** **Frágil por build de Windows**: los offsets y las tablas de unwind cambian. Requiere mantenimiento.

### 5.3 Return-address spoofing puntual

**Qué es.** La variante ligera de lo anterior: falsear solo la dirección de retorno en callbacks concretos usando gadgets `pop`.

**Cómo funciona.** Antes de llamar a la API, se prepara la pila para que el retorno apunte a un sitio legítimo y se restaura después.

**Qué gana.** Menos coste que un spoofing completo, suficiente para un callback puntual.

**Qué cuesta.** No arregla pilas profundas; solo el frame inmediato.

---

## 🧱 Familia 6 — COFF/PIC en post-explotación

Una vez que el beacon corre, el siguiente problema es **dónde ejecuta el post-explotación**. La respuesta elegante: dentro del mismo módulo firmado que ya aloja al beacon.

### 6.1 Stomped module + COFF runner

**Qué es.** El módulo sacrificial no solo aloja el beacon: también aloja el **runner de BOFs** (COFFs position-independent). Todo el post-explotación corre dentro del módulo firmado.

**Cómo funciona.** Se reserva espacio en el módulo (por stomping u overloading), se coloca allí el loader de COFF y se ejecutan los BOFs en ese contexto, con las APIs resueltas desde el propio módulo.

**Qué gana.** Los BOFs quedan blindados igual que el beacon: dejan de ser memoria anónima ejecutable.

**Qué cuesta.** Requiere un runner de COFF propio y espacio suficiente en el módulo; la gestión de relocaciones y símbolos del COFF es trabajo real.

**Contexto.** Es la arquitectura de Havoc/Demon para post-explotación. En Okugi, con E6b ya hay UDRL propio; añadir el runner de COFFs al UDRL es el paso natural: los BOFs que hoy corren in-process pasarían al módulo stompeado.

### 6.2 PIM (Position-Independent Modules)

**Qué es.** Módulos completos **PIC** cargados sin el loader del sistema operativo.

**Cómo funciona.** El módulo se compila para no depender de una base fija ni de un loader; se mapea y se resuelven sus dependencias a mano.

**Qué gana.** Portabilidad y control total del mapeo, sin depender de `LoadLibrary`.

**Qué cuesta.** Compilar y mantener PIC real es delicado; no todos los módulos se prestan a ello.

---

## 🧊 Familia 7 — En reposo

El payload pasa la mayor parte del tiempo dormido. Lo que se ve en reposo importa tanto como lo que se ve ejecutando.

### 7.1 Ekko, Zilean, Foliage, DeathSleep, Cronos

**Qué es.** La familia de **sleep obfuscation**: cifrar el payload y/o desmapear sus vistas mientras duerme, y restaurarlo al despertar.

**Cómo funciona.** Antes de dormir se cifra la región ejecutable y se cambia su protección; al despertar se descifra y se ejecuta un pequeño stub. Cada variante cambia el mecanismo (timers, APC, ROP, callbacks) para que el "dormir" no dependa de una sola primitiva.

**Qué gana.** Reduce a casi cero la ventana en la que el payload está en claro y ejecutable. Es la línea que en el laboratorio cubren E2 + Etapa B.

**Qué cuesta.** El stub de despertar es código propio y hay que protegerlo también; el ciclo de cifrado/descifrado deja eventos.

### 7.2 Desmapear durante el sueño

**Qué es.** Un paso más: **desmapear las vistas** y dejar solo la sección respaldada por pagefile mientras el payload duerme.

**Cómo funciona.** Se conserva la sección, se desmapean las vistas RW y RX, y se vuelven a mapear al despertar. Compatible con la doble vista de Okugi: es un upgrade natural de E2 —dormir con las vistas desmapeadas—.

**Qué gana.** Durante el sueño no hay región ejecutable que clasificar, solo una sección sin vistas.

**Qué cuesta.** Más eventos de map/unmap y una ventana de re-mapeo que hay que coordinar con el despertar.

---

## 🧠 Cómo se combinan (el stack completo)

Las familias no compiten: se **apilan**. Un stack coherente podría verse así:

```text
[REGIÓN]    sección pagefile con vistas RW/RX  (Familia 1.6)
   ↓
[HILO]      work item del thread pool           (Familia 2.1)
   ↓
[DISPARO]   loader notification o callback      (Familia 2.8/2.9)
   ↓
[APARIENCIA] PEB poison + stack spoof           (Familia 4.1 + 5.2)
   ↓
[POST-EX]   COFF runner en módulo stompeado     (Familia 6.1)
   ↓
[REPOSO]    cifrado + desmapeo de vistas        (Familia 7.1/7.2)
```

Cada capa mueve una señal distinta. El error clásico es apilar **dos técnicas que mueven la misma señal** y dejar las otras tres intactas: el sensor sigue teniendo una historia que contar.

> 🎯 **La pregunta de diseño:** no "¿cuál es la técnica más moderna?", sino "¿qué señal me queda descubierta y cuál es la técnica más barata que la tapa?".

## 📋 Matriz de decisión rápida

| Si necesito… | Técnica razonable | Coste principal |
|---|---|---|
| Quitar la memoria unbacked | Section aliasing o module overloading | Dual view / placement |
| No crear hilos | Thread pool work items | Callback visible |
| Un disparo natural y diferido | Timer del pool o loader notification | Objeto registrado |
| Un hilo con origen legítimo | Thread start spoofing | Contexto incoherente |
| Ocultar el inventario | Phantom DLL hollowing | Sigue siendo privada |
| Tapar el post-ex | COFF runner en módulo stompeado | Runner propio |
| Dormir sin payload en claro | Sleep obfuscation + desmapeo | Stub de despertar |

## 🛡️ Cómo lo mira el defensor

Este es el otro lado del catálogo, y el que conviene tener siempre presente:

| Artefacto que se inspecciona | Qué delata | Familia que lo mueve |
|---|---|---|
| `Type` y `Protection` de la región | Memoria privada ejecutable, RWX | 1.6, 1.8 |
| Hash del módulo vs. archivo | Stomping, overloading | 1.1, 1.2 |
| Listas del PEB vs. kernel | Phantom entries, unlinking | 1.3, 1.4 |
| Start address del hilo | Hilos que nacen en memoria rara | 2.3, 2.7 |
| Call stack | Frame[0] unbacked | 5.2, 5.3 |
| Cola de APC / thread pool | Disparos artificiales | 2.1, 2.4, 2.5 |
| Creación de proceso y linaje | Clones, PPID falso | 1.7, 4.2 |
| Línea de comandos del PEB | Secretos en `argv` | 4.1 |
| Handles de sección y map/unmap | Vistas de la misma sección | 1.6, 7.2 |
| Instrumentation callback | Un callback por proceso | 2.12 |

La lectura defensiva es simple: **no busques una técnica, busca una historia incoherente**. Una región `MEM_IMAGE` cuyo hash no coincide, un hilo que empieza en `ntdll` pero cuya pila no tiene sentido, una línea de comandos que no corresponde con el binario. La incoherencia es la señal.

## ⚠️ Mitos frecuentes

- **"Phantom DLL hollowing hace que mi memoria sea legítima."** No. Disfraza el inventario; el `Type` sigue siendo `MEM_PRIVATE`. Quien mire allocation-type te sigue viendo.
- **"Module stomping es indetectable."** El hash del módulo deja de coincidir con el archivo. Es una señal clara, aunque hoy no todos los productos la consulten.
- **"Los callbacks son la técnica nueva."** La lista de APIs está quemada como IOC desde hace años, y casi todas son *one-shot*.
- **"Early Bird sigue siendo top."** Es de las secuencias más firmadas que existen.
- **"El stack spoofing es universal."** Depende de la build exacta de Windows; es frágil y hay que mantenerlo.
- **"Fileless significa sin disco."** Registrar un servidor COM surrogate o un IFEO implica registry o disco: eso ya no es fileless.

## 📚 Glosario mínimo

| Término | En una frase |
|---|---|
| **PEB** | *Process Environment Block*: estructura de user-mode con la información del proceso. |
| **LDR** | El cargador de Windows y sus listas de módulos. |
| **APC** | *Asynchronous Procedure Call*: rutina que el kernel entrega a un hilo. |
| **VAD** | *Virtual Address Descriptor*: el árbol del kernel que describe las regiones de memoria. |
| **`MEM_IMAGE`** | Región respaldada por una sección de imagen (un PE). |
| **`MEM_MAPPED`** | Región respaldada por una sección (por ejemplo, pagefile). |
| **`MEM_PRIVATE`** | Región anónima, sin archivo ni sección detrás. |
| **W^X** | Nunca escribible y ejecutable a la vez; se usan dos vistas. |
| **ETW-TI** | *Threat Intelligence*: ETW de kernel con eventos de operaciones sensibles. |
| **SSN** | *System Service Number*: el número de una syscall. |
| **Gadget** | Secuencia de instrucciones que termina en `ret`, usada en ROP. |
| **BOF / COFF** | *Beacon Object File*: código PIC que se ejecuta en el proceso del beacon. |
| **PIC / PIM** | Código o módulo *position-independent*, sin base fija. |
| **UDRL** | *User-Defined Reflective Loader*: loader propio que mapea el payload. |
| **Stack walk** | Recorrido de la pila usando las tablas de unwind. |

## 📚 Fuentes y lecturas recomendadas

Bibliografía comentada, agrupada por familia. Los enlaces se comprobaron a fecha de publicación; cuando el artículo original de una técnica ya no está disponible, se enlaza el paper de la conferencia o una implementación de referencia.

### General, detección y contexto

- [MITRE ATT&CK — Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/) — el marco de referencia para clasificar inyección y sus sub-técnicas; útil para mapear cada familia a un ID.
- [Elastic — detection-rules](https://github.com/elastic/detection-rules) — las reglas abiertas del producto contra el que se midió el laboratorio; aquí viven muchas de las señales que cita el artículo.
- [Checkpoint — Anti-Debugging Reference](https://anti-debug.checkpoint.com/) — referencia práctica de `ThreadHideFromDebugger`, `NtGlobalFlag` y compañía, con ejemplos.

### Familia 1 — Dónde vive el código

- [Module Stomping, DLL Hollowing and PE Image Relocations](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection.md) — ired.team; la explicación clásica del stomping y del hollowing de DLL con las relocaciones de imagen.
- [hasherezade — module_overloading](https://github.com/hasherezade/module_overloading) — el PoC original de la variante que solo usa el espacio muerto del módulo.
- [hasherezade — 1001 nights](https://hshrzd.wordpress.com/) — el blog de referencia sobre hollowing, overloading y análisis de implantes.
- [Masking Malicious Memory Artifacts — Part I: Phantom DLL Hollowing](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing) — Forrest Orr; el artículo que define el phantom DLL hollowing, con su [PoC](https://github.com/forrest-orr/phantom-dll-hollower-poc).
- [Hiding in Plain Sight: Unlinking Malicious DLLs from the PEB](https://blog.christophetd.fr/dll-unlinking/) — Christophe Tafani-Dereeper; las tres listas del PEB, `LDR_DATA_TABLE_ENTRY` y cómo detectar el desenlace por VAD.
- [Dirty Vanity: A New Approach to Code Injection & EDR Bypass](https://www.deepinstinct.com/blog/dirty-vanity-a-new-approach-to-code-injection-edr-bypass) — Deep Instinct; el paper de Black Hat EU-22 está [aquí](https://i.blackhat.com/EU-22/Thursday-Briefings/EU-22-Nissan-DirtyVanity.pdf) y el [PoC](https://github.com/deepinstinct/Dirty-Vanity) es público.
- [hasherezade — pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) — conversión de PE a shellcode position-independent; la base práctica de la familia PIC.

### Familia 2 — Cómo arranca la ejecución

- [SafeBreach — PoolParty](https://github.com/SafeBreach-Labs/PoolParty) — la investigación sobre inyección abusando de los thread pools de Windows, con las ocho variantes y su [write-up](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/).
- [MITRE — Thread Execution Hijacking (T1055.003)](https://attack.mitre.org/techniques/T1055/003/) — la ficha canónica del secuestro de hilo.
- [MITRE — Asynchronous Procedure Call (T1055.004)](https://attack.mitre.org/techniques/T1055/004/) — la ficha del APC, incluido el Early Bird.
- [FrankensteinAPCInjection](https://github.com/S12cybersecurity/FrankensteinAPCInjection) — implementación moderna con *special user APC* (`NtQueueApcThreadEx2`), sin allocs ni cambios de protección.
- [EarlyBird-APC-Injection](https://github.com/Faran-17/EarlyBird-APC-Injection) — PoC mínimo del Early Bird clásico, mapeado a T1055.004.
- [Executing Shellcode via Callbacks](https://osandamalith.com/2021/04/01/executing-shellcode-via-callbacks/) — Osanda Malith; la idea de usar APIs de enumeración como disparadoras.
- [AlternativeShellcodeExec](https://github.com/aahmad097/AlternativeShellcodeExec) — el catálogo de APIs callback (`CertEnumSystemStoreLocation`, `EnumWindows`, etc.) con sus PoCs.
- [Weaponizing Mapping Injection with Instrumentation Callback](https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html) — splinter_code; el uso del instrumentation callback como dispatcher de ejecución.
- [Windows Instrumentation Callbacks — Part 1](https://cirosec.de/en/news/windows-instrumentation-callbacks/) — cirosec; la serie técnica moderna sobre el mecanismo y sus usos.

### Familia 3 — Activación por objetos

- [CoRegisterClassObject — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coregisterclassobject) — el contrato oficial para registrar una factoría de clases en el proceso.
- [CoCreateInstance — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance) — el camino de activación que termina llamando a tu `CreateInstance`.
- [DllSurrogate — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/dllsurrogate) — cómo COM hospeda un servidor out-of-proc en `dllhost.exe`.
- [IInitializeCommand — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-iinitializecommand) — la interfaz de los manejadores de verbos de shell.
- [MITRE — COM Hijacking (T1546.015)](https://attack.mitre.org/techniques/T1546/015/) — la ficha de persistencia/ejecución vía objetos COM.
- [MITRE — Image File Execution Options Injection (T1546.012)](https://attack.mitre.org/techniques/T1546/012/) — la ficha del secuestro vía IFEO y debugger.

### Familias 4 y 5 — Apariencia y pila

- [Process Parameter Poisoning (P³) — SensePost](https://sensepost.com/blog/2026/process-parameter-poisoning/) — el artículo que da nombre a la técnica y explica el uso de `CommandLine`, `Environment` y `ShellInfo` del PEB; [loader](https://github.com/Orange-Cyberdefense/p3-loader).
- [MITRE — Parent PID Spoofing (T1134.004)](https://attack.mitre.org/techniques/T1134/004/) — la ficha del PPID falso.
- [Hell's Gate](https://github.com/am0nsec/HellsGate) — la implementación original de resolución dinámica de SSN.
- [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), [SysWhispers3](https://github.com/klezVirus/SysWhispers3) y [SysWhispers4](https://github.com/JoasASantos/SysWhispers4) — la evolución de las syscalls directas/indirectas.
- [FreshyCalls](https://github.com/crummie5/FreshyCalls) — resolución de SSN por orden de export, sin leer los stubs.
- [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk) — el call stack spoofer dinámico que cierra el frame no respaldado.

### Familias 6 y 7 — Post-explotación y reposo

- [TrustedSec — COFFLoader](https://github.com/trustedsec/COFFLoader) — ejecución de COFF/BOF en memoria; la pieza que permite el runner dentro del módulo.
- [TheWover — Donut](https://github.com/TheWover/donut) — generación de shellcode position-independent para PE y .NET; referencia obligada de PIC/PIM.
- [Ekko](https://github.com/Cracked5pider/Ekko) — el sleep obfuscation que popularizó el cifrado y el cambio de protección durante el sueño.
- [Cronos](https://github.com/Idov31/Cronos) — la variante con waitable timers, coautoría de Idov31 y YXEL.
- [DeathSleep](https://github.com/janoglezcampos/DeathSleep) — terminar el hilo y restaurarlo al despertar, con cambios de protección durante la no-ejecución.
- [Havoc — Obf.c](https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/core/Obf.c) — implementación de referencia de varias familias de sleep obfuscation (Foliage, Zilean y compañía) en un C2 real.

## Cierre

Este catálogo no es una lista de recetas: es un **mapa de señales**. Cada técnica existe porque hay un sensor mirando algo concreto, y cada una funciona hasta que ese sensor cambia de pregunta.

La lección que deja el laboratorio es siempre la misma: medir, no creer. Una técnica que "en teoría" tapa una señal puede dejar otra abierta, y una que parece ruidosa puede ser invisible para el producto que tienes delante. La diferencia entre un payload y un payload que aguanta no es la técnica más exótica: es **saber qué historia está contando tu proceso** en cada una de las cuatro casillas.

Si algo de esto te sirve, el siguiente paso natural es leer cómo se midió en el laboratorio: [Kagemusha F14–F15 — el módulo prestado](/blog/kagemusha-f14-f15-modulo-prestado-etwti.html) y el [mini-loader en 15 pasos](/blog/mini-loader-15-pasos-pe-sin-loadlibrary.html) para entender el mapeo que hay debajo de casi todas estas familias.
