---
version: alpha
name: Rabanito Second Brain
description: Consola local de conocimiento citado y evidencia de seguridad.
colors:
  background: "#0b0f14"
  surface: "#111821"
  elevated: "#18222d"
  text: "#e8eef5"
  muted: "#8ea0b5"
  primary: "#63e6be"
  warning: "#ffcc66"
  danger: "#ff7b8b"
  border: "#587086"
typography:
  sans:
    fontFamily: "system-ui, Segoe UI, sans-serif"
    fontSize: "14px"
    lineHeight: "1.45"
  mono:
    fontFamily: "ui-monospace, monospace"
rounded:
  DEFAULT: "8px"
  panel: "12px"
spacing:
  page: "16px"
  gap: "16px"
components:
  panel:
    borderRadius: "12px"
  control:
    borderRadius: "8px"
---

# Rabanito — contexto visual existente

## Overview

Consola de trabajo para una persona que consulta memoria técnica local y evidencia pública de seguridad. Registro de producto, idioma español de México, escritorio Windows1080p/1440p con adaptación a ventanas estrechas. No existe alcance de mercado japonés ni interfaz japonesa. La referencia es una mesa de investigación: fuente, fecha y estado acompañan al dato; no se usan alarmas decorativas ni métricas ficticias.

La identidad procede del dashboard existente; se conserva. Firma de Cyber: cada CVE abre las aportaciones separadas de sus proveedores. El catálogo comienza plegado para preservar el espacio de la memoria documental. El núcleo visual y las operaciones originales no se reconstruyen.

## Colors

Modelo B: las variables de `web/index.html` son canónicas. Este archivo documenta los valores, no genera CSS. Mapa: background→`--bg`, surface→`--panel`, elevated→`--panel2`, text→`--text`, muted→`--muted`, primary→`--accent`, warning→`--warn`, danger→`--bad`, border→`--line`. Los controles usan `--control-border`, los botones `--button-border`; se preservan los valores existentes. Las pruebas Node comprueban contraste de estos roles.

## Typography

Se reutiliza system-ui/Segoe UI sin descargar fuentes. Encabezado24px, secciones15px, cuerpo14px y metadata12px según el CSS existente. Identificadores CVE y fechas permanecen como texto seleccionable. No se transforma contenido público en HTML.

## Layout

Grid de dos columnas con máximo1600px y separación16px. Cyber usa lista/detalle; a1050px se apila. Solo el marco de tabla tiene overflow y altura máxima440px; el detalle hasta540px. La página conserva scroll natural. Paginación de20 filas, controles fuera del área de scroll; el estado reserva altura para carga/error.

## Elevation & Depth

Capas tonales, bordes visibles y sombra moderada ya existente en paneles. No incorporar fondos o efectos que confundan severidad con decoración. Foco de2px con `--accent`.

## Shapes

Paneles12px y controles8px, tabla sin contorno individual por celda. La forma y el texto acompañan al estado; color nunca es el único indicador.

## Components

El panel colapsable Security Architecture/Coding Memory comparte toolbar, inputs/select nativos, paginación y detalle de Cyber. No aplica otra navegación global, framework o paleta. Cards informativas sin cursor de acción; botones explícitos para abrir fichas. Las experiencias muestran sus fragmentos/citas y no inventan una acción de apertura. Se mantienen layouts responsive y presupuestos por biblioteca.

Panel, toolbar, button, input/select, metadata y error reutilizan el CSS existente. Selects y datalist son nativos: se acepta el popup del sistema operativo. No hay calendario ni componente de selección múltiple en Cyber. Scrollbar global tokenizada, visible y compatible con forced-colors.

Los botones conservan texto/dimensiones durante carga y exponen disabled/aria-busy. No se añaden diálogos ni escrituras optimistas. Búsqueda con botón Limpiar, debounce300ms, protección IME y generaciones para ignorar respuestas antiguas. Live regions independientes para consultas, conectores y sincronización. No hay animación nueva; se respeta el renderer de grafo existente.

## Do's and Don'ts

- Conservar citas y fechas exactas del proveedor, diferenciando publicación, modificación y consulta.
- Mostrar datos faltantes como “Sin puntuación” o “No informado”.
- No representar EPSS como explotación observada ni un producto coincidente como proyecto vulnerable.
- No añadir CDN, fuentes remotas, telemetría ni parámetros de búsqueda privados en URLs.

Auditoría visual/renderizada y lint oficial se registran en TEST_RESULTS; la existencia de este archivo no los da por aprobados.
