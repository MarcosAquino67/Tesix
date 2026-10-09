/**
 * Avisos de seguridad (campanita).
 * Muestra las ultimas vulnerabilidades detectadas en los analisis del usuario.
 * Se activa en cualquier boton con el atributo data-avisos.
 */
(function () {
    'use strict';

    var COLOR_SEV = {
        High: 'text-red-400 bg-red-500/10',
        Medium: 'text-amber-400 bg-amber-500/10',
        Low: 'text-emerald-400 bg-emerald-500/10'
    };
    var ETIQUETA = { High: 'Alta', Medium: 'Media', Low: 'Baja' };

    function escapar(texto) {
        var div = document.createElement('div');
        div.textContent = texto == null ? '' : String(texto);
        return div.innerHTML;
    }

    function mensajeVacio(texto) {
        return '<div class="px-4 py-6 text-center text-gray-500 text-xs">' + escapar(texto) + '</div>';
    }

    function pintar(items, panel) {
        if (items.length === 0) {
            panel.innerHTML = mensajeVacio('Sin avisos: tus analisis no detectaron vulnerabilidades.');
            return;
        }
        panel.innerHTML = items.slice(0, 8).map(function (v) {
            var sev = v.severity || '';
            var extra = (v.cve && v.cve !== 'CVE-General') ? ' &middot; ' + escapar(v.cve) : '';
            return '<div class="px-4 py-3 border-b border-[#1e1e2d] last:border-0 hover:bg-[#1a1a26] transition-colors">' +
                '<div class="flex items-start justify-between gap-3">' +
                '<div class="min-w-0">' +
                '<p class="text-xs font-semibold text-white truncate">' + escapar(v.nombre) + '</p>' +
                '<p class="text-[11px] text-gray-400 truncate">' + escapar(v.tipo || '') + extra + '</p>' +
                '</div>' +
                '<span class="shrink-0 px-2 py-0.5 rounded-full text-[10px] font-bold ' +
                (COLOR_SEV[sev] || 'text-gray-400 bg-gray-500/10') + '">' +
                (ETIQUETA[sev] || escapar(sev)) + '</span>' +
                '</div></div>';
        }).join('');
    }

    function actualizarBadge(items) {
        var badge = document.querySelector('[data-avisos-badge]');
        if (!badge) return;
        var altas = items.filter(function (v) { return v.severity === 'High'; }).length;
        badge.classList.toggle('hidden', altas === 0);
        badge.textContent = altas > 0 ? String(altas) : '';
    }

    async function cargar(panel) {
        try {
            var res = await fetch('/api/vulnerabilidades/lista');
            if (res.status === 401) {
                panel.innerHTML = mensajeVacio('Inicia sesion para ver los avisos.');
                return;
            }
            var data = await res.json();
            var items = data.vulnerabilidades || [];
            actualizarBadge(items);
            pintar(items, panel);
        } catch (e) {
            panel.innerHTML = mensajeVacio('No se pudieron cargar los avisos.');
        }
    }

    function crearPanel() {
        var panel = document.createElement('div');
        panel.className = 'avisos-panel hidden absolute right-0 top-full mt-2 w-80 max-w-[85vw] ' +
            'bg-[#14141e] border border-[#232333] rounded-xl shadow-2xl z-50 overflow-hidden';
        panel.innerHTML = '<div class="px-4 py-3 border-b border-[#232333] flex items-center justify-between">' +
            '<span class="text-xs font-bold text-white">Avisos de seguridad</span>' +
            '<a href="/vulnerabilidades" class="text-[11px] font-semibold text-[#8b5cf6] hover:underline">Ver todos</a>' +
            '</div>' +
            '<div class="max-h-72 overflow-y-auto divide-y divide-[#1e1e2d]">' +
            mensajeVacio('Cargando...') + '</div>';
        return panel;
    }

    function init() {
        var boton = document.querySelector('[data-avisos]');
        if (!boton || boton.dataset.avisosListo === '1') return;
        boton.dataset.avisosListo = '1';

        boton.classList.add('relative');
        var panel = crearPanel();
        boton.appendChild(panel);

        var contenedor = panel.querySelector('.max-h-72');
        var abierto = false;

        function alternar() {
            abierto = !abierto;
            panel.classList.toggle('hidden', !abierto);
            if (abierto) cargar(contenedor);
        }

        function cerrar() {
            abierto = false;
            panel.classList.add('hidden');
        }

        boton.addEventListener('click', function (e) {
            e.stopPropagation();
            alternar();
        });

        document.addEventListener('click', function (e) {
            if (abierto && !panel.contains(e.target)) cerrar();
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && abierto) cerrar();
        });

        // Badge inicial con el total de avisos
        cargar(contenedor);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
