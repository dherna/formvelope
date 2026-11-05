# Formvelope

Extensión de Firefox para cifrar el contenido de un campo de texto con una clave
pública OpenPGP. El destinatario podrá descifrarlo con la clave privada
correspondiente.

> Las claves se guardan en el almacenamiento local de Firefox. La clave privada
> debe estar protegida por su contraseña OpenPGP; se guarda cifrada y la
> contraseña no se almacena. Al iniciar una sesión de descifrado, la clave
> desbloqueada se mantiene en el almacenamiento de sesión volátil de la
> extensión durante el tiempo configurado: sobrevive al cambio de página y a
> pausas del proceso en segundo plano, pero se elimina al cerrar Firefox o
> recargar la extensión.

## Preparar y cargar en Firefox

1. Instala Node.js y npm.
2. Ejecuta `npm install` y luego `npm run build` en este directorio. Se generarán
   los bundles necesarios en `build/`.
3. Abre `about:debugging#/runtime/this-firefox` en Firefox.
4. Selecciona **Cargar complemento temporal** y elige el `manifest.json` de este
   directorio.
5. Abre las opciones de Formvelope y carga una clave pública ASCII-armored
   (`.asc`, `.gpg` o `.pgp`) con capacidad de cifrado.
6. (Opcional) Importa una clave privada ASCII-armored protegida por contraseña
   para poder descifrar mensajes destinados a ella.
7. En una página web, enfoca un campo `<textarea>` o un editor `contenteditable`,
   abre el popup y pulsa **Cifrar campo enfocado**.

En la barra inferior negra, el botón de engranaje abre la configuración de
claves y el botón contiguo alterna entre el popup y la barra lateral de Firefox.
La barra lateral tiene un fondo gris claro.

El popup reemplaza el contenido original por el mensaje cifrado ASCII-armored.
Para consultar un mensaje cifrado, enfoca su campo, escribe la contraseña de la
clave privada en el popup y pulsa **Descifrar campo enfocado**. También puedes
cifrar en bloque las áreas multilínea del formulario enfocado o descifrar
fragmentos cifrados visibles en la página, también dentro de tablas. Los
fragmentos se reconocen por los marcadores de un mensaje OpenPGP y se
reemplazan por texto, manteniendo el resto de la estructura y el formato HTML.

En las opciones puedes configurar una sesión temporal (1–1440 minutos) y añadir
dominios permitidos. Solo se admiten dominios HTTPS y se rechazan los sufijos
públicos, como `com` o `github.io`. Firefox solicitará permiso para cada dominio;
marca la casilla correspondiente si quieres incluir también sus subdominios. El
modo automático descifra los fragmentos
de texto que encuentre (incluidas celdas y secciones de tablas) al cargar
páginas permitidas mientras la sesión siga activa. El modo
manual requiere pulsar **Descifrar contenido cifrado de esta página**. La sesión
puede cerrarse desde las opciones; se pierde también al reiniciar Firefox o
recargar la extensión. Los campos de una sola línea se omiten, porque no pueden
representar de forma fiable los saltos de línea del formato ASCII-armored.
Para iniciar la sesión, escribe la contraseña en el popup/barra lateral y pulsa
**Descifrar contenido cifrado de esta página** (también se inicia al descifrar
un campo individual). En modo automático, vuelve a cargar las páginas abiertas después
de activar el modo o añadir un dominio.

## Estructura

- `manifest.json`: manifiesto de Firefox (Manifest V3) y permisos mínimos.
- `src/background.js`: valida claves, conserva la privada cifrada y gestiona las
  sesiones temporales de descifrado.
- `src/content.js`: cifra campos multilínea y descifra fragmentos OpenPGP
  encontrados en el texto de la página, incluidas las celdas de tablas.
- `src/popup.js` / `popup.html` / `sidebar.html`: acciones de cifrado y
  descifrado en el popup y la barra lateral.
- `src/options.js` / `options.html`: importación y eliminación de claves.
- `build/`: bundles generados por `npm run build`.

La clave privada cifrada permanece en el perfil local de Firefox; protege
también el acceso al dispositivo y al perfil. La clave desbloqueada se conserva en el almacenamiento de sesión volátil
durante la sesión configurada y nunca se persiste en disco. El cifrado y el
descifrado se realizan en el navegador. La extensión no firma mensajes.
