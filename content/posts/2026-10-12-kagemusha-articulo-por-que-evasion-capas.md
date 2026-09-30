---
title: "Kagemusha — Artículo: por qué investigamos la evasión de EDR (y por qué es en capas)"
date: 2026-10-12
tags: edr, evasion, windows internals, investigacion, principiantes, articulo
serie: Kagemusha
summary: Artículo de síntesis para principiantes. Explica qué es la evasión de EDR, cómo se llegó al informe técnico del proyecto, la lógica de cada pieza, qué cubre y qué no la serie, por qué se crean estos informes, las capacidades medidas del proyecto y por qué la evasión es un problema de arquitectura en capas.
---

# Por qué investigamos la evasión de EDR (y por qué es en capas)

Este artículo es la **puerta de entrada conceptual** a la serie **Kagemusha**. No hace falta que
sepas programar ni seguridad ofensiva para entenderlo: la idea es que **comprendas el "por qué"**
de todo lo demás. Si luego quieres el detalle técnico, cada concepto enlaza a su entrada.

---

## 1. La pregunta de partida

Imagina que eres un **defensor**. Tienes un **EDR** (*Endpoint Detection and Response*): el
antivirus "de nueva generación" que observa **qué hace** un programa, no solo cómo es su archivo.
Ahora la pregunta incómoda:

> **¿Qué haría un atacante para que mi EDR no lo vea?**

Investigar eso no es para atacar: es como estudiar cerraduras para mejorar la seguridad de tu
casa. **Quien no entiende una técnica, no puede detectarla.** Esa es la razón de ser de todo este
proyecto.

## 2. Antes de seguir: cuatro palabras

- **Syscall:** la "petición" que un programa le hace al núcleo de Windows (abrir un archivo, crear
  un proceso…). Es la puerta al **kernel** (el "jefe" del sistema).
- **Núcleo / kernel (ring 0):** el nivel con todos los permisos. Un programa normal corre en
  **user-mode (ring 3)**, sin permisos.
- **Hook (gancho):** una trampa que un EDR pone **en la puerta** para ver las peticiones.
- **Evasión:** *reducir la señal* que tu programa emite, para no disparar las **reglas** del EDR.

Con esto, ya puedes leer el resto.

## 3. La idea central: la evasión es **en capas**

Mira una casa:

- **Capa 1 — la puerta (user-mode).** El EDR pone una **cámara** en la puerta. El atacante usa una
  puerta lateral (**indirect syscalls**) para no pasar por la cámara.
- **Capa 2 — los sensores dentro (telemetría).** El EDR también mira las **pilas de llamadas** y
  eventos (**ETW-TI**, *callbacks de kernel*). El atacante intenta **ocultar la pila** (*stack
  spoofing*) o **apagar cámaras** que sí puede tocar (**parchear ETW de user-mode**).
- **Capa 3 — la alarma central (kernel).** Hay sensores que **solo** funcionan desde el kernel. El
  atacante, desde user-mode, **no puede apagarlos**. Para eso tendría que **bajar al kernel**
  (por ejemplo, reutilizando un driver firmado y vulnerable: **BYOVD**).
- **Capa 4 — la conducta (lo que decides hacer).** Al final, lo que **de verdad** dispara la
  alarma es el **comportamiento** (hacer algo ruidoso), no la puerta que usaste.

De aquí sale la **tesis del proyecto**:

> **La evasión no es "una técnica", es un problema de arquitectura por capas.** Se reduce señal
> capa a capa, y **el techo está en el kernel**.

## 4. Cómo llegamos hasta aquí (el recorrido del informe)

El proyecto no empezó con todas las ideas: **se construyó por pasos**, y cada paso **midió** algo.

1. **Mecanismo (el indirect syscall).** Empezamos haciendo que el `syscall` se ejecute **dentro de
   `ntdll`** (no en nuestro binario), para esquivar los **hooks de user-mode** → [Visión general](/blog/kagemusha-indirect-syscalls.html).
2. **¿Nos ve alguien? (E2).** Registramos un *instrumentation callback* y comprobamos que **sí ve**
   cada syscall, aunque sea indirecto → [Visibilidad y evasión](/blog/kagemusha-visibilidad-evasion.html).
3. **¿Dejamos huella? (E3).** Miramos la **pila** en el momento del syscall: el retorno apunta a
   **nuestro módulo** (una firma) → misma entrada.
4. **¿Podemos borrar la huella? (E4b/E4c).** Parcheamos **ETW de user-mode** y limpiamos el
   callback (E4b); integramos *stack spoofing* (E4c), pero descubrimos que **CET (Shadow Stack) y el
   spoofing clásico son incompatibles** → [Evasión en acción](/blog/kagemusha-evasion-e4b-cet-spoofing.html).
5. **¿Y el techo? (informe de kernel).** Documentamos que **no se puede cegar ETW-TI desde
   user-mode**; el siguiente escalón es el **kernel** (BYOVD) → [Técnicas para alcanzar el kernel](/blog/kagemusha-informe-tecnicas-kernel.html).
6. **Síntesis (informe de evasión).** Reunimos todo en un **marco conceptual** → [Informe de evasión](/blog/kagemusha-informe-tecnico-evasion.html).

**Por eso existen estos informes:** cada uno recoge el **método**, los **resultados medidos** y,
sobre todo, **los límites**. Un informe sin límites es publicidad; con límites, es ciencia.

## 5. La lógica de cada pieza (de un vistazo)

| Pieza | Qué resuelve | Por qué importa |
| --- | --- | --- |
| **Indirect syscall + FreshyCalls** | Esquivar **hooks de user-mode** | El hook no se dispara si no ejecutas el stub |
| **Stack spoofing** | Ocultar la **firma de pila** | Los detectores de pila sí ven el indirecto "puro" |
| **ETW patch + limpiar callback** | Cegar telemetría **de user-mode** | Reduce señales que sí están a tu alcance |
| **Kernel / BYOVD** | Cegar **ETW-TI / callbacks** | Es el **techo**; desde user-mode no se puede |
| **OPSEC / conducta** | No disparar **reglas** | Sin patrón ruidoso, no hay alerta |

## 6. Un concepto que lo cambia todo: **visibilidad ≠ detección**

El error más común es creer que "si el EDR lo ve, lo detecta". **No.**

- **Sensor** → captura un hecho.
- **Telemetría** → el flujo de eventos.
- **Regla** → la lógica que decide.
- **Alerta** → cuando la regla cruza su **umbral**.

Un hecho puede ser **observado** y **no detectado**. Lo comprobamos: **Defender observó** nuestros
syscalls y **no generó ninguna detección**, porque la **conducta** era benigna. Es decir: **el
mecanismo importa, pero la conducta decide**.

## 7. Qué cubre la serie (y qué NO)

Para ser honestos, hay que decir el alcance:

**Cubre (y lo mide):**
- Todo lo alcanzable desde **user-mode**: indirect syscalls, *stack spoofing*, parcheo de ETW de
  user-mode, limpieza del instrumentation callback. **Evasión confirmada** en hooks, pila, ETW
  user y callback.

**NO cubre (y lo documenta como techo):**
- **ETW-TI de kernel y callbacks de kernel** (requeriría kernel/BYOVD).
- **Bootkits / hypervisores / firmware** (below-OS): se describe el **mapa** y las **defensas**, sin
  recetas operativas.
- **Delivery, payloads, persistencia, C2**: fuera del foco; el proyecto estudia el **mecanismo**, no
  la operación completa.

## 8. Las capacidades del proyecto (medidas, no prometidas)

- **178 PASS / 0 FAIL** en la build **stealth** (sin CET, con *spoofing*) y **182 PASS** en la build
  **CET** (`/CETCOMPAT`).
- **0 instrucciones `syscall`** en el módulo (verificado con `dumpbin`).
- **Matriz de evasión** (del informe): hooks ✅ · pila ✅ (stealth) · callback ✅ · ETW user ✅
  · **kernel ❌ (techo)**.
- Todo con **oráculos independientes** (nunca validar contra el propio sistema) → [Metodología](/blog/kagemusha-metodologia-verificacion.html).

## 9. Por qué la evasión es **en capas** (cierre)

- **Capa tras capa**: cada sensor que un atacante neutraliza tiene su **coste** y su **límite**.
- **El techo está abajo**: lo que el kernel ve (ETW-TI, callbacks) no se cierra desde arriba.
- **La conducta manda**: incluso con el mejor mecanismo, un comportamiento ruidoso se detecta.
- **La defensa gana con profundidad**: *"el defensor diversifica sensores; el atacante reduce señal"*.
  Quien tenga la señal **más completa** gana la carrera.

> Esa es la conclusión de la serie y la razón de cada informe: **entender la evasión por capas**
> para, del otro lado, **detectarla mejor**.

---

## Cómo leer la serie

1. **Este artículo** (la idea general y el "por qué").
2. [Cómo leer la serie + Misión 0](/blog/como-leer-serie-mision-0.html) (primer experimento, sin programar).
3. [Guía de syscalls](/blog/guia-syscalls-windows.html) (los conceptos, explicados).
4. Las fases (M0–M7) y los experimentos (E2–E4c).
5. Los **informes técnicos**: [evasión](/blog/kagemusha-informe-tecnico-evasion.html) y
   [técnicas para alcanzar el kernel](/blog/kagemusha-informe-tecnicas-kernel.html).

Toda la serie (navegable): **[Kagemusha](/blog/serie/kagemusha.html)**.

---

## Bibliografía y referencias

- Fuentes primarias: `docs/research/informe-tecnico-evasion.md`,
  `docs/research/informe-tecnicas-kernel.md`, `docs/research/metodologia.md`, `README.md`.
- Microsoft Learn — *ETW/ETW-TI*, *Control-flow Enforcement Technology (CET)*, *HVCI*.
- crummie5 — *FreshyCalls*; `WKL-Sec/LayeredSyscall`; `paranoidninja/Process-Instrumentation-Syscall-Hook`.

> Aprender a romper para poder defender.
