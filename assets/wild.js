/* =====================================================================
   KANON UFO - "Modo salvaje" (vanilla JS, sin dependencias)
   - Fondo de red de nodos (canvas)
   - Intro estilo BIOS/POST (typing)
   - Terminal interactiva (comandos)
   - Cursor retícula
   - Toggle de efectos (localStorage) + prefers-reduced-motion
   ===================================================================== */
(function () {
  "use strict";

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var guardado = null;
  try { guardado = localStorage.getItem("wild"); } catch (e) {}
  var wild = guardado === null ? !reduce : guardado === "on";

  function activar(on) {
    wild = on;
    document.documentElement.classList.toggle("wild-on", on);
    try { localStorage.setItem("wild", on ? "on" : "off"); } catch (e) {}
    var btn = document.querySelector(".wild-toggle");
    if (btn) btn.textContent = on ? "efectos: ON" : "efectos: OFF";
    var cv = document.getElementById("wild-fondo");
    if (cv) cv.style.opacity = on ? "1" : "0";
  }

  /* ---------------- Fondo: red de nodos ---------------- */
  function initFondo() {
    var cv = document.getElementById("wild-fondo");
    if (!cv || !cv.getContext) return;
    var ctx = cv.getContext("2d");
    var DPR = Math.min(2, window.devicePixelRatio || 1);
    var W = 0, H = 0, nodos = [];
    var CA = "0,229,255", CM = "255,45,149";

    function medida() {
      W = cv.width = Math.floor(window.innerWidth * DPR);
      H = cv.height = Math.floor(window.innerHeight * DPR);
      cv.style.width = window.innerWidth + "px";
      cv.style.height = window.innerHeight + "px";
      var n = Math.min(96, Math.floor(window.innerWidth / 15));
      nodos = [];
      for (var i = 0; i < n; i++) {
        nodos.push({
          x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.5 * DPR,
          vy: (Math.random() - 0.5) * 0.5 * DPR,
          r: (0.8 + Math.random() * 1.4) * DPR
        });
      }
    }

    function pintar() {
      ctx.clearRect(0, 0, W, H);
      var lim = 150 * DPR;
      for (var i = 0; i < nodos.length; i++) {
        var a = nodos[i];
        a.x += a.vx; a.y += a.vy;
        if (a.x < 0 || a.x > W) a.vx *= -1;
        if (a.y < 0 || a.y > H) a.vy *= -1;
        ctx.beginPath();
        ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(" + CA + ",0.65)";
        ctx.fill();
        for (var j = i + 1; j < nodos.length; j++) {
          var b = nodos[j];
          var dx = a.x - b.x, dy = a.y - b.y;
          var d2 = dx * dx + dy * dy;
          if (d2 < lim * lim) {
            var alfa = 1 - Math.sqrt(d2) / lim;
            ctx.strokeStyle = "rgba(" + (i % 7 === 0 ? CM : CA) + "," + (alfa * 0.35) + ")";
            ctx.lineWidth = DPR;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }
      requestAnimationFrame(pintar);
    }

    window.addEventListener("resize", medida);
    medida();
    pintar();
  }

  /* ---------------- Intro BIOS/POST ---------------- */
  function initBoot() {
    var boot = document.getElementById("wild-boot");
    if (!boot) return;
    var visto = false;
    try { visto = sessionStorage.getItem("boot") === "1"; } catch (e) {}
    if (!wild || reduce || visto) { boot.hidden = true; return; }

    var lineas = [
      "KAGE-BIOS v4.2.1  (c) KANON UFO",
      "",
      "CPU ......... x64  [ OK ]",
      "MEMORY ...... 64GiB [ OK ]",
      "DETECTANDO DISPOSITIVOS ...",
      "  ntdll.dll ................. [ OK ]",
      "  kernelbase.dll ............ [ OK ]",
      "  instrument_callback ....... [ OK ]",
      "MONTANDO /home/kanon ........ [ OK ]",
      "CARGANDO modulos de evasion . [ OK ]",
      "ANALIZANDO telemetria ....... [ WARN ]",
      "",
      "[ AUTENTICANDO root@kanon-ufo ]",
      "[ ACCESS GRANTED ]",
    ];
    var salida = boot.querySelector(".boot__texto");
    var skip = boot.querySelector(".boot__skip");

    boot.hidden = false;
    var fin = false;
    function terminar() {
      if (fin) return; fin = true;
      boot.hidden = true;
      try { sessionStorage.setItem("boot", "1"); } catch (e) {}
    }
    if (skip) skip.addEventListener("click", terminar);

    var i = 0, j = 0;
    var texto = "";
    function paso() {
      if (fin) return;
      if (i >= lineas.length) { setTimeout(terminar, 700); return; }
      var linea = lineas[i];
      if (j <= linea.length) {
        salida.textContent = texto + linea.slice(0, j) + "\u2588";
        j++;
        setTimeout(paso, 6);
      } else {
        texto += linea + "\n";
        salida.textContent = texto + "\u2588";
        i++; j = 0;
        setTimeout(paso, 70);
      }
    }
    setTimeout(paso, 200);
  }

  /* ---------------- Terminal interactiva ---------------- */
  function initTerminal() {
    var form = document.getElementById("consola-form");
    if (!form) return;
    var salida = document.getElementById("consola-salida");
    var input = document.getElementById("consola-input");
    var historial = [], hIdx = -1;

    var comandos = {
      help: "Comandos disponibles:\n  whoami · about · focus · skills · posts · projects\n  contact · sudo · matrix · banner · date · clear",
      whoami: "KANON UFO  ·  Juan Barrero\nEstudiante de ciberseguridad  |  Blue Team (base Red Team)\nMalware Analysis · Windows Internals · Lubuntu",
      about: "Blog de ciberseguridad a bajo nivel: notas, writeups y laboratorio.\nVer: /blog/",
      focus: "[+] malware analysis\n[+] windows internals\n[+] blue team (base red team)",
      skills: "Blue Team: malware analysis, DFIR, threat hunting\nRed Team : pentesting, reconocimiento, explotacion\nScripting: Python, PowerShell, Bash",
      posts: "Serie activa: Kagemusha (indirect syscalls + evasion de EDR)\n-> /blog/serie/kagemusha.html",
      projects: "Kagemusha: sistema de indirect syscalls en C + MASM (investigacion).",
      contact: "GitHub: https://github.com/juanbarrero-art",
      date: new Date().toString(),
      banner: " ___  __ ___  _  _  ___  _  _    _  _  ___  ___\n| _ \\| |  _ \\| \\| |/ _ \\| \\| |  | || |/ _ \\| __|\n|  _/| | |_| | .` | (_) | .` |  | __ | (_) | _|\n|_|  |_|_|_|_|_|\\_|\\___/|_|\\_|  |_||_|\\___/|_|"
    };

    function esc(s) {
      return String(s).replace(/[&<>]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]; });
    }
    function escribir(html) {
      var p = document.createElement("div");
      p.innerHTML = html;
      salida.appendChild(p);
      salida.scrollTop = salida.scrollHeight;
    }

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var cmd = (input.value || "").trim();
      input.value = "";
      if (!cmd) return;
      historial.push(cmd); hIdx = historial.length;
      escribir('<span class="consola__entrada-eco">kanon@ufo:~$ ' + esc(cmd) + "</span>");

      var partes = cmd.split(/\s+/);
      var base = partes[0].toLowerCase();

      if (base === "clear") { salida.innerHTML = ""; return; }
      if (base === "sudo") {
        escribir('<span class="consola__error">[sudo] contraseña para kanon: ****\nLo siento, esto es un blog. Pero bonito intento. 😉</span>');
        return;
      }
      if (base === "matrix") {
        escribir('<span class="consola__ok">Follow the white rabbit. 🐇 (activa "efectos" para el fondo animado)</span>');
        return;
      }
      if (Object.prototype.hasOwnProperty.call(comandos, base)) {
        escribir('<span class="consola__ok">' + esc(comandos[base]) + "</span>");
      } else {
        escribir('<span class="consola__error">comando no encontrado: ' + esc(base) + " -- escribe 'help'</span>");
      }
    });

    input.addEventListener("keydown", function (ev) {
      if (ev.key === "ArrowUp") {
        if (hIdx > 0) { hIdx--; input.value = historial[hIdx]; }
        ev.preventDefault();
      } else if (ev.key === "ArrowDown") {
        if (hIdx < historial.length - 1) { hIdx++; input.value = historial[hIdx]; }
        else { hIdx = historial.length; input.value = ""; }
        ev.preventDefault();
      }
    });

    document.addEventListener("click", function (ev) {
      if (ev.target.closest(".consola__caja")) input.focus();
    });
    escribir('<span class="consola__ok">KANON-SHELL v1.0 -- escribe "help"</span>');
  }

  /* ---------------- Cursor retícula ---------------- */
  function initCursor() {
    if (!wild) return;
    if (!(window.matchMedia && window.matchMedia("(hover: hover) and (pointer: fine)").matches)) return;
    var punto = document.createElement("div"); punto.id = "wild-cursor";
    var anillo = document.createElement("div"); anillo.id = "wild-cursor-ring";
    document.body.appendChild(punto); document.body.appendChild(anillo);
    var x = 0, y = 0, rx = 0, ry = 0;
    document.addEventListener("mousemove", function (ev) { x = ev.clientX; y = ev.clientY; });
    (function seguir() {
      rx += (x - rx) * 0.18; ry += (y - ry) * 0.18;
      punto.style.transform = "translate(" + x + "px," + y + "px)";
      anillo.style.transform = "translate(" + rx + "px," + ry + "px)";
      requestAnimationFrame(seguir);
    })();
  }

  /* ---------------- Arranque ---------------- */
  function init() {
    var btn = document.querySelector(".wild-toggle");
    if (btn) btn.addEventListener("click", function () { activar(!wild); });
    activar(wild);
    if (wild && !reduce) { initFondo(); initCursor(); }
    initBoot();
    initTerminal();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
