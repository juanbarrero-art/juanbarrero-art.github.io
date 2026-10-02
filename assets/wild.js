/* =====================================================================
   KANON UFO - "Modo salvaje"
   Mejoras multimedia con FALLBACK:
   - Fondo: Vanta.js NET (3D) -> si falla, canvas de red propio.
   - Terminal: Xterm.js (real) -> si falla, terminal vanilla.
   - Intro BIOS/POST, cursor retícula, toggle de efectos.
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
  }

  /* ---------------- Utilidades de carga ---------------- */
  function cargarScript(src) {
    return new Promise(function (res, rej) {
      var s = document.createElement("script");
      s.src = src; s.async = true;
      s.onload = function () { res(src); };
      s.onerror = function () { rej(new Error("no carga: " + src)); };
      document.head.appendChild(s);
    });
  }
  function cargarCSS(href) {
    var l = document.createElement("link");
    l.rel = "stylesheet"; l.href = href;
    document.head.appendChild(l);
  }

  /* ---------------- Comandos (compartidos) ---------------- */
  var COMANDOS = {
    help: "Comandos: whoami · about · focus · skills · posts · projects · contact · rootkit · implant · procs · unhook · etw · sudo · matrix · banner · date · clear",
    whoami: "KANON UFO  ·  Juan Barrero\nEstudiante de ciberseguridad | Blue Team (base Red Team)\nMalware Analysis · Windows Internals · Lubuntu",
    about: "Blog de ciberseguridad a bajo nivel: notas, writeups y laboratorio.\nVer: /blog/",
    focus: "[+] malware analysis\n[+] windows internals\n[+] blue team (base red team)",
    skills: "Blue Team: malware analysis, DFIR, threat hunting\nRed Team : pentesting, reconocimiento, explotacion\nScripting: Python, PowerShell, Bash",
    posts: "Serie activa: Kagemusha (indirect syscalls + evasion de EDR)\n-> /blog/serie/kagemusha.html",
    projects: "Kagemusha: sistema de indirect syscalls en C + MASM (investigacion).",
    contact: "GitHub: https://github.com/juanbarrero-art",
    date: new Date().toString(),
    rootkit: "rootkit v0.7  ·  implante ring 0\n  unhook: OK   etw: suppressed   callbacks: filtered\n  hidden processes: 3   status: UNDETECTED",
    implant: "implant --mode stealth\n[+] cargando en kernel ...\n[+] ocultando procesos .... 3\n[*] UNDETECTED",
    procs: "PID     NOMBRE            ESTADO\n    4   System            [visible]\n  780   svchost.exe       [visible]\n 1337   kage.exe          [HIDDEN]\n31337   rootkit.sys       [HIDDEN]\n0xDEAD  implant.exe       [HIDDEN]",
    unhook: "unhook: ntdll .text restaurado de disco -> stubs limpios: 488/488",
    etw: "etw(user): suppressed  |  etw-ti(kernel): [WARN] requiere ring 0",
    banner: " _  __   _   _  _  ___  _  _   _  _  ___  ___\n| |/ /  /_\\ | \\| |/ _ \\| \\| | | | || |/ _ \\| __|\n| ' <  / _ \\| .` | (_) | .` | | |_|| | (_) | _|\n|_|\\_\\/_/ \\_\\_|\\_|\\___/|_|\\_|  \\___/|_|\\___/|_|"
  };

  function resolverCmd(cmd) {
    var base = (cmd || "").split(/\s+/)[0].toLowerCase();
    if (!base) return null;
    if (base === "clear") return { accion: "clear" };
    if (base === "sudo") return { texto: "[sudo] password for kanon: ****\nLo siento, esto es un blog. Pero bonito intento.", err: true };
    if (base === "matrix") return { texto: "Follow the white rabbit." };
    if (Object.prototype.hasOwnProperty.call(COMANDOS, base)) return { texto: COMANDOS[base] };
    return { texto: "comando no encontrado: " + base + " -- escribe 'help'", err: true };
  }

  /* ---------------- Fondo canvas (fallback) ---------------- */
  function initFondo() {
    var cv = document.getElementById("wild-fondo");
    if (!cv || !cv.getContext) return;
    var ctx = cv.getContext("2d");
    var DPR = Math.min(2, window.devicePixelRatio || 1);
    var W = 0, H = 0, nodos = [];
    function medida() {
      W = cv.width = Math.floor(window.innerWidth * DPR);
      H = cv.height = Math.floor(window.innerHeight * DPR);
      cv.style.width = window.innerWidth + "px";
      cv.style.height = window.innerHeight + "px";
      var n = Math.min(96, Math.floor(window.innerWidth / 15));
      nodos = [];
      for (var i = 0; i < n; i++) {
        nodos.push({ x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random() - 0.5) * 0.5 * DPR, vy: (Math.random() - 0.5) * 0.5 * DPR,
          r: (0.8 + Math.random() * 1.4) * DPR });
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
        ctx.beginPath(); ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0,229,255,0.65)"; ctx.fill();
        for (var j = i + 1; j < nodos.length; j++) {
          var b = nodos[j];
          var dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
          if (d2 < lim * lim) {
            var alfa = 1 - Math.sqrt(d2) / lim;
            ctx.strokeStyle = "rgba(" + (i % 7 === 0 ? "255,45,149" : "0,229,255") + "," + (alfa * 0.35) + ")";
            ctx.lineWidth = DPR; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }
      requestAnimationFrame(pintar);
    }
    window.addEventListener("resize", medida); medida(); pintar();
  }

  /* ---------------- Fondo Vanta.js (upgrade) ---------------- */
  function initVanta() {
    if (!wild || reduce) return;
    var cont = document.getElementById("wild-vanta");
    if (!cont) {
      cont = document.createElement("div");
      cont.id = "wild-vanta";
      document.body.insertBefore(cont, document.body.firstChild);
    }
    cargarScript("https://cdn.jsdelivr.net/npm/three@0.134.0/build/three.min.js")
      .then(function () { return cargarScript("https://cdn.jsdelivr.net/npm/vanta@0.5.24/dist/vanta.net.min.js"); })
      .then(function () {
        if (!window.VANTA || !window.VANTA.NET) throw new Error("sin Vanta");
        window.VANTA.NET({
          el: "#wild-vanta",
          mouseControls: true, touchControls: false, gyroControls: false,
          minHeight: 200, minWidth: 200, scale: 1, scaleMobile: 1,
          color: 0x00e5ff, backgroundColor: 0x05070d,
          points: 10, maxDistance: 22, spacing: 18, showDots: true
        });
        cont.classList.add("wild-vanta--on");
        var fb = document.getElementById("wild-fondo");
        if (fb) fb.style.display = "none"; /* Vanta reemplaza el canvas */
      })
      .catch(function () { /* fallback: se queda el canvas propio */ });
  }

  /* ---------------- Intro BIOS/POST ---------------- */
  function initBoot() {
    var boot = document.getElementById("wild-boot");
    if (!boot) return;
    var visto = false;
    try { visto = sessionStorage.getItem("boot") === "1"; } catch (e) {}
    if (!wild || reduce || visto) { boot.hidden = true; return; }
    var lineas = [
      "KAGE-BIOS v4.2.1  (c) KANON UFO", "",
      "CPU ......... x64  [ OK ]", "MEMORY ...... 64GiB [ OK ]",
      "DETECTANDO DISPOSITIVOS ...",
      "  ntdll.dll ................. [ OK ]",
      "  kernelbase.dll ............ [ OK ]",
      "  instrument_callback ....... [ OK ]",
      "MONTANDO /home/kanon ........ [ OK ]",
      "CARGANDO modulos de evasion . [ OK ]",
      "ANALIZANDO telemetria ....... [ WARN ]", "",
      "[ AUTENTICANDO root@kanon-ufo ]", "[ ACCESS GRANTED ]"
    ];
    var salida = boot.querySelector(".boot__texto");
    var skip = boot.querySelector(".boot__skip");
    boot.hidden = false;
    var fin = false;
    function terminar() { if (fin) return; fin = true; boot.hidden = true; try { sessionStorage.setItem("boot", "1"); } catch (e) {} }
    if (skip) skip.addEventListener("click", terminar);
    var i = 0, j = 0, texto = "";
    function paso() {
      if (fin) return;
      if (i >= lineas.length) { setTimeout(terminar, 700); return; }
      var linea = lineas[i];
      if (j <= linea.length) { salida.textContent = texto + linea.slice(0, j) + "\u2588"; j++; setTimeout(paso, 6); }
      else { texto += linea + "\n"; salida.textContent = texto + "\u2588"; i++; j = 0; setTimeout(paso, 70); }
    }
    setTimeout(paso, 200);
  }

  /* ---------------- Hero: implante auto-ejecutado ---------------- */
  function initImplant() {
    var el = document.getElementById("implant-salida");
    if (!el || !wild || reduce) return;
    var lineas = [
      '<span class="t-verde">root@kernel:~#</span> implant --mode stealth',
      '<span class="t-cian">[+] syscall stub ....... unhooked</span>',
      '<span class="t-cian">[+] etw (user) ........ suppressed</span>',
      '<span class="t-cian">[+] callbacks ......... filtered</span>',
      '<span class="t-cian">[+] hidden procs ...... 3</span>',
      '<span class="t-magenta">[*] status: UNDETECTED</span>',
      '<span class="t-verde">root@kernel:~#</span> <span class="cursor">_</span>'
    ];
    var i = 0;
    function frame() {
      el.innerHTML = lineas.slice(0, i + 1).join("\n");
      i++;
      if (i < lineas.length) setTimeout(frame, 520);
      else setTimeout(function () { i = 0; el.innerHTML = ""; setTimeout(frame, 500); }, 2800);
    }
    el.innerHTML = "";
    setTimeout(frame, 500);
  }

  /* ---------------- Terminal vanilla (fallback) ---------------- */
  function initTerminalVanilla() {
    var form = document.getElementById("consola-form");
    if (!form) return;
    var salida = document.getElementById("consola-salida");
    var input = document.getElementById("consola-input");
    var historial = [], hIdx = -1;
    function esc(s) { return String(s).replace(/[&<>]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]; }); }
    function escribir(html) {
      var p = document.createElement("div"); p.innerHTML = html;
      salida.appendChild(p); salida.scrollTop = salida.scrollHeight;
    }
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var cmd = (input.value || "").trim(); input.value = "";
      if (!cmd) return;
      historial.push(cmd); hIdx = historial.length;
      escribir('<span class="consola__entrada-eco">kanon@ufo:~$ ' + esc(cmd) + "</span>");
      var r = resolverCmd(cmd);
      if (r.accion === "clear") { salida.innerHTML = ""; return; }
      escribir('<span class="' + (r.err ? "consola__error" : "consola__ok") + '">' + esc(r.texto) + "</span>");
    });
    input.addEventListener("keydown", function (ev) {
      if (ev.key === "ArrowUp") { if (hIdx > 0) { hIdx--; input.value = historial[hIdx]; } ev.preventDefault(); }
      else if (ev.key === "ArrowDown") { if (hIdx < historial.length - 1) { hIdx++; input.value = historial[hIdx]; } else { hIdx = historial.length; input.value = ""; } ev.preventDefault(); }
    });
    document.addEventListener("click", function (ev) { if (ev.target.closest(".consola__caja")) input.focus(); });
    escribir('<span class="consola__ok">KANON-SHELL v1.0 -- escribe "help"</span>');
  }

  /* ---------------- Terminal Xterm.js (upgrade) ---------------- */
  function initXterm() {
    if (!wild) return;
    var host = document.getElementById("consola-xterm");
    if (!host) return;
    cargarCSS("https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css");
    Promise.all([
      cargarScript("https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js"),
      cargarScript("https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js").catch(function () {})
    ]).then(function () {
      if (!window.Terminal) throw new Error("sin Xterm");
      var term = new window.Terminal({
        cursorBlink: true, convertEol: true,
        fontFamily: '"JetBrains Mono", Consolas, monospace', fontSize: 14,
        theme: { background: "#03060c", foreground: "#c9d1e0", cursor: "#ff2d95", selectionBackground: "#1c2440" }
      });
      term.open(host);
      var Fit = window.FitAddon && (window.FitAddon.FitAddon || window.FitAddon);
      if (Fit) {
        var fit = new Fit();
        try { term.loadAddon(fit); fit.fit(); window.addEventListener("resize", function () { try { fit.fit(); } catch (e) {} }); } catch (e) {}
      }
      host.hidden = false;
      var vanilla = document.querySelector(".consola__salida");
      var linea = document.querySelector(".consola__linea");
      if (vanilla) vanilla.hidden = true;
      if (linea) linea.hidden = true;

      var buf = "", historial = [], hIdx = 0;
      function prompt() { term.write("\r\n\x1b[32mkanon@ufo:~$\x1b[0m "); }
      function ejecutar(cmd) {
        var r = resolverCmd(cmd);
        if (!r) { return; }
        if (r.accion === "clear") { term.clear(); return; }
        var color = r.err ? "\x1b[31m" : "\x1b[36m";
        term.write(color + r.texto + "\x1b[0m");
      }
      term.writeln("\x1b[36mKANON-SHELL v1.0\x1b[0m -- escribe 'help'");
      prompt();
      term.onData(function (data) {
        if (data === "\r") {
          term.write("\r\n");
          var cmd = buf.trim(); buf = "";
          if (cmd) { historial.push(cmd); hIdx = historial.length; }
          ejecutar(cmd);
          prompt();
        } else if (data === "\u007f" || data === "\b") {
          if (buf.length) { buf = buf.slice(0, -1); term.write("\b \b"); }
        } else if (data === "\u001b[A") {
          if (hIdx > 0) { hIdx--; buf = historial[hIdx] || ""; redibujar(); }
        } else if (data === "\u001b[B") {
          if (hIdx < historial.length - 1) { hIdx++; buf = historial[hIdx] || ""; }
          else { hIdx = historial.length; buf = ""; }
          redibujar();
        } else if (data >= " ") {
          buf += data; term.write(data);
        }
      });
      function redibujar() {
        term.write("\r\x1b[K\x1b[32mkanon@ufo:~$\x1b[0m " + buf);
      }
      host.addEventListener("click", function () { term.focus(); });
      term.focus();
    }).catch(function () { /* fallback: se queda la terminal vanilla */ });
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
    if (wild && !reduce) {
      initFondo();      /* fallback inmediato */
      initVanta();      /* upgrade 3D (si carga) */
      initCursor();
    }
    initBoot();
    initImplant();
    initTerminalVanilla();
    /* initXterm() desactivado: la terminal vanilla es la fiable (Xterm daba problemas). */
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
