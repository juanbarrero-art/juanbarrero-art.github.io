/* =====================================================================
   KANON UFO - Blog (base)
   JavaScript vanilla · menú móvil + año dinámico
   ===================================================================== */
(function () {
  "use strict";

  var toggle = document.querySelector(".nav-toggle");
  var menu = document.getElementById("menu");

  if (toggle && menu) {
    toggle.addEventListener("click", function () {
      var abierto = menu.getAttribute("data-abierto") === "true";
      menu.setAttribute("data-abierto", String(!abierto));
      toggle.setAttribute("aria-expanded", String(!abierto));
      toggle.setAttribute("aria-label", abierto ? "Abrir menú" : "Cerrar menú");
    });

    // Cerrar el menú al elegir un enlace (en móvil)
    menu.querySelectorAll("a").forEach(function (enlace) {
      enlace.addEventListener("click", function () {
        menu.setAttribute("data-abierto", "false");
        toggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  // Año dinámico en el pie
  var anio = document.getElementById("anio");
  if (anio) {
    anio.textContent = String(new Date().getFullYear());
  }
})();
