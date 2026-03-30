# 🏫 Sistema de Control de Asistencias - I.E. Franz Tamayo Solares

Un ecosistema digital completo diseñado para modernizar y automatizar el registro de asistencias de estudiantes y personal en instituciones educativas.

## 📌 C.P.S.R. del Proyecto

* **Contexto:** La I.E. Franz Tamayo Solares utilizaba un sistema tradicional basado en hojas y cuadernos físicos para registrar las asistencias.
* **Problema:** El método manual causaba pérdida de tiempo, riesgo de deterioro de documentos y hacía que la generación de reportes mensuales fuera un proceso lento y propenso a errores.
* **Solución:** Creación de un sistema de 2 aplicaciones interconectadas vía LAN: un servidor principal (gestión y personal) y una app de tablet (para aulas).
* **Resultados:** Automatización del control de asistencias, generación de reportes en Excel en segundos, eliminación del uso de papel y mayor integridad de los datos.

## 🏗️ Arquitectura del Sistema

El proyecto está dividido en dos componentes principales que se comunican a través de la red local (IP):

1. **Control de Asistencias (Servidor Web):** 
   * Aplicación principal desarrollada en Python con Flask.
   * Funciona como servidor y base de datos (SQLite) central.
   * Cuenta con un módulo web táctil para el registro de entrada/salida del personal.
   * Panel de administración para gestionar usuarios, editar alumnos masivamente y generar reportes.
2. **Asistencias de Alumnos (App de Tablet):**
   * Aplicación nativa diseñada para que los docentes marquen la asistencia (Presente, Falta, Justificado) de forma rápida en el aula.
   * Sincroniza los datos con el servidor principal a través de una API REST.

## ✨ Características Principales

- 🔐 **Autenticación y Roles:** Sistema de login seguro, recuperación de contraseñas por token/correo y gestión de usuarios.
- 👥 **Gestión de Personal:** CRUD completo de personal, asignación de horarios y registro de marcaciones (Entrada/Salida).
- 🎓 **Gestión de Estudiantes:** Edición masiva (Bulk Edit) de alumnos, control por niveles, grados y secciones.
- 📊 **Reportes y Exportación:** Generación de tablas mensuales dinámicas y exportación de datos formateados a `.xlsx` (Excel).
- 🔄 **API de Sincronización:** Endpoints robustos con manejo de conflictos (Modo WAL en SQLite) para recibir datos de las tablets sin bloqueos.
- 📦 **Empaquetado:** El servidor está preparado para ser compilado como un ejecutable `.exe` usando PyInstaller para fácil distribución.

## 🛠️ Tecnologías Utilizadas

* **Backend:** Python, Flask, Flask-Mail, Flask-CORS.
* **Base de Datos:** SQLite3 (Modo WAL habilitado para alta concurrencia).
* **Frontend:** HTML5, CSS3, Bootstrap 5.
* **Procesamiento de Datos:** Pandas, OpenPyXL (para exportación a Excel).
* **Despliegue:** PyInstaller.
