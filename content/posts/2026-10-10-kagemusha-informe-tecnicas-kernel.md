---
title: "Kagemusha — Informe técnico: técnicas para alcanzar el kernel (mapa conceptual)"
date: 2026-10-10
tags: windows internals, red team, blue team, kernel, investigacion, informe
serie: Kagemusha
orden: 14
summary: Documentación del informe técnico conceptual del repositorio (docs/research/informe-tecnicas-kernel.md): el mapa de vías para ejecutar código en kernel (driver propio, DSE, BYOVD, abuso de drivers, EoP, bootkit/UEFI, hypervisor/VBS, firmware), con comparativa, defensas por capa y consideraciones éticas.
---

# Kagemusha — Informe técnico: técnicas para alcanzar el kernel

Esta entrada documenta el **informe técnico conceptual** del repositorio
(`docs/research/informe-tecnicas-kernel.md`).

> El propio informe se define así: *"Documento **conceptual y defensivo**: describe *categorías* de
> técnicas, por qué funcionan y cómo se mitigan. **No contiene recetas operativas** (ni drivers
> concretos, ni IOCTLs, ni exploits, ni pasos de ejecución)."*
>
> Pregunta que responde: *"si BYOVD no es la única forma, ¿qué rutas existen para ejecutar código en
> kernel (o por debajo) y cómo se comparan?"*

## Por qué existe este informe

Kagemusha cubre la capa **user-mode**. Este informe define el **mapa de técnicas** y **el techo**
de la aproximación user-mode: llegar a **kernel** (ring 0) o **por debajo** permite observar,
ocultar o des-registrar casi cualquier cosa —incluidos los sensores de kernel de un EDR.

## Las rutas (resumen ejecutivo del informe)

1. **Escribir y cargar tu propio driver** (exige firma + privilegio).
2. **Burlar la firma de drivers (DSE)**.
3. **BYOVD**: reutilizar un driver **firmado pero vulnerable**.
4. **Abusar de un driver legítimo ya cargado** (IOCTL vulnerable) — puede no requerir admin.
5. **Explotar una vulnerabilidad de kernel (EoP)**.
6. **Bootkits / UEFI**: cargar **antes** que el OS.
7. **Hypervisor / VBS / hyperjacking**: situarse **por debajo** del OS.
8. **Firmware rootkits**.
9. **Sin kernel**: matar/deshabilitar el EDR desde user-mode **con admin**.

## El modelo de privilegios (del informe)

- **Ring 3 (user-mode):** evasión "barata" (indirect syscalls, stack spoofing, ETW patch). **Sin privilegios**.
- **Ring 0 (kernel-mode):** ve y controla todo; requiere código de kernel o explotar.
- **Below-OS:** bootloader/UEFI, hypervisor, firmware. Máximo sigilo y persistencia.

> *"La frontera user↔kernel es el límite duro: desde ring 3 no puedes des-registrar callbacks de
> kernel, tocar la SSDT, ni silenciar ETW-TI."*

### Qué se gana en kernel (del informe)

Des-registrar callbacks del EDR; silenciar **ETW-TI**; manipulación de estructuras (DKOM); filtrar
telemetría; desactivar integridades (DSE, HVCI) o persistir muy abajo.

## Comparativa de técnicas (tabla del informe)

| Técnica | Nivel | ¿Admin? | ¿Firma propia? | Depende de | Detectabilidad | Persistencia |
| --- | --- | --- | --- | --- | --- | --- |
| Driver propio | Ring 0 | Sí | Sí (o bypass) | DSE | Alta | Media |
| Bypass de DSE | Ring 0 | Sí | Bypass/robado | Cert/0-day | Media-Alta | Media |
| BYOVD-privesc | Ring 0 | **No** | No (reusa) | Driver presente/vuln | Media | Media |
| BYOVD-blinding | Ring 0 | Sí (post-ex) | No (reusa) | Driver cargable/vuln | Media | Media |
| Abuso de driver presente | Ring 0 | A menudo no | No | Driver presente | Media | — |
| Exploit de kernel (EoP) | Ring 0 | No | No | Vulnerabilidad | Baja-Media | — |
| Kill/disable EDR | Ring 0/3 | Sí | No | Falla del producto | Media-Alta | Baja |
| Bootkit/UEFI | Below-OS | Sí (o físico) | Firma UEFI/bypass | Secure Boot | Muy baja | **Muy alta** |
| Hypervisor/VBS | Below-OS | Sí | Especial | Hardware/VBS | Muy baja | **Muy alta** |
| Firmware rootkit | Firmware | Sí/físico | Firmware signing | Hardware | Muy baja | **Muy alta** |

**Lectura (del informe):** sin admin se puede llegar a kernel por **BYOVD-privesc**, **abuso de
driver presente** o **EoP**; con admin se abre **BYOVD-blinding**, driver propio o kill/disable;
below-OS es el extremo en sigilo y persistencia.

## Defensas por capa (del informe)

Defensa en profundidad: **DSE + Secure Boot**; **HVCI/VBS**; **blocklist de drivers vulnerables +
LOLDrivers**; auditoría de drivers preinstalados; **ACLs de devices**; **telemetría de kernel +
ETW-TI**; **mitigaciones de explotación** (SMEP/SMAP/kCFG/pool hardening); **atestación del arranque**
(TPM/Measured Boot); **correlación XDR**. *"No hay una única defensa; quien tenga más sensores en más
capas gana la carrera."*

## La cadena típica (del informe)

```text
1. Acceso inicial (0 admin)
2. Evasión user-mode (0 admin)              <- Kagemusha (este proyecto)
3. Escalada: LPE/exploit o BYOVD-privesc
4. Evasión kernel (admin): BYOVD-blinding (quitar callbacks/ETW-TI)
5. Persistencia avanzada (opcional): bootkit / hypervisor / firmware
6. Persistencia, movimiento lateral, impacto
```

*"El kernel no es el punto de partida; es un escalón que se sube por pasos."*

## Conclusión (del informe)

- **BYOVD no es la única vía.** Hay al menos 9 rutas, con distinto privilegio y coste; ninguna universal.
- La tendencia (DSE + blocklist + HVCI) empujó de "escribir tu driver" a **BYOVD** y, en élites, a **below-OS**.
- Para la defensa: **diversificar y profundizar sensores**.

## Consideraciones éticas y de alcance (del informe)

Documento **conceptual**, en laboratorio propio, **sin recetas operativas**. El objetivo es **entender
y defender**. Cualquier trabajo práctico con kernel/BYOVD debe hacerse en **VMs aisladas y sin red**.

---

## Cómo sigue la serie

Toda la serie (navegable): **[Kagemusha](/blog/serie/kagemusha.html)**.

---

## Bibliografía y referencias

- Fuente primaria: `docs/research/informe-tecnicas-kernel.md`.
- Referencias del informe: Microsoft (DSE, *Vulnerable Driver Blocklist*, HVCI/VBS, Secure Boot/
  Measured Boot, ETW-TI); **LOLDrivers**; literatura general de *exploit-development*; literatura de
  rootkits/bootkits (DKOM, UEFI bootkits, hyperjacking); **CHIPSEC**.

> Aprender a romper para poder defender.
