import {
  hostPermissionPatterns,
  isValidDomain
} from "./domain.js";
import { isPublicSuffix } from "./publicSuffix.js";

const keyForm = document.querySelector("#key-form");
const keyFile = document.querySelector("#key-file");
const keyStatus = document.querySelector("#key-status");
const removeButton = document.querySelector("#remove-key");
const privateKeyForm = document.querySelector("#private-key-form");
const privateKeyFile = document.querySelector("#private-key-file");
const importPassphrase = document.querySelector("#import-passphrase");
const privateKeyStatus = document.querySelector("#private-key-status");
const removePrivateKeyButton = document.querySelector("#remove-private-key");
const status = document.querySelector("#status");
const settingsForm = document.querySelector("#settings-form");
const decryptionMode = document.querySelector("#decryption-mode");
const sessionDuration = document.querySelector("#session-duration");
const sessionStatus = document.querySelector("#session-status");
const lockSessionButton = document.querySelector("#lock-session");
const domainForm = document.querySelector("#domain-form");
const domainInput = document.querySelector("#domain-input");
const includeSubdomains = document.querySelector("#include-subdomains");
const allowedDomainsList = document.querySelector("#allowed-domains");
let savedSettings;

async function refreshKeyStatus() {
  const result = await browser.runtime.sendMessage({ type: "get-key-status" });
  if (!result?.ok && result?.error) {
    throw new Error(result.error);
  }

  keyStatus.textContent = result.publicKey.configured
    ? `Clave pública cargada (huella: ${result.publicKey.fingerprint}).`
    : "No hay una clave pública cargada.";
  removeButton.hidden = !result.publicKey.configured;
  privateKeyStatus.textContent = result.privateKey.configured
    ? `Clave privada cargada (huella: ${result.privateKey.fingerprint}).`
    : "No hay una clave privada cargada.";
  removePrivateKeyButton.hidden = !result.privateKey.configured;
}

function normalizeDomain(value) {
  const input = value.trim();
  const url = new URL(input.includes("://") ? input : `https://${input}`);
  if (
    url.protocol !== "https:" ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.port ||
    url.username ||
    url.password
  ) {
    throw new Error("Introduce solo un dominio HTTPS, sin ruta ni puerto.");
  }
  const domain = url.hostname.toLowerCase();
  if (!isValidDomain(domain)) {
    if (isPublicSuffix(domain)) {
      throw new Error("No se puede permitir un sufijo público como com o github.io.");
    }
    throw new Error("El dominio no es válido.");
  }
  return domain;
}

function renderAllowedDomains() {
  allowedDomainsList.replaceChildren();
  for (const allowedDomain of savedSettings.allowedDomains) {
    const { domain, includeSubdomains: withSubdomains } = allowedDomain;
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = withSubdomains
      ? `${domain} y sus subdominios`
      : `${domain} (solo este dominio)`;
    const removeDomainButton = document.createElement("button");
    removeDomainButton.type = "button";
    removeDomainButton.className = "secondary";
    removeDomainButton.textContent = "Eliminar";
    removeDomainButton.addEventListener("click", () => {
      removeAllowedDomain(allowedDomain).catch(showSettingsError);
    });
    item.append(label, removeDomainButton);
    allowedDomainsList.append(item);
  }
}

function updateSessionStatus(settings) {
  if (settings.sessionActive) {
    sessionStatus.textContent =
      `Sesión de descifrado activa hasta ${new Date(settings.sessionExpiresAt).toLocaleString()}.`;
    lockSessionButton.disabled = false;
  } else {
    sessionStatus.textContent = "No hay una sesión de descifrado activa.";
    lockSessionButton.disabled = true;
  }
}

async function loadSettings() {
  const settings = await browser.runtime.sendMessage({ type: "get-settings" });
  if (!settings?.ok) {
    throw new Error(settings?.error ?? "No se pudo cargar la configuración.");
  }
  savedSettings = settings;
  decryptionMode.value = settings.decryptionMode;
  sessionDuration.value = settings.sessionDurationMinutes;
  renderAllowedDomains();
  updateSessionStatus(settings);
}

function showSettingsError(error) {
  status.textContent = error instanceof Error
    ? error.message
    : "No se pudo actualizar la configuración.";
}

async function saveSettings(allowedDomains = savedSettings.allowedDomains) {
  const result = await browser.runtime.sendMessage({
    type: "set-settings",
    decryptionMode: decryptionMode.value,
    sessionDurationMinutes: Number(sessionDuration.value),
    allowedDomains
  });
  if (!result?.ok) {
    throw new Error(result?.error ?? "No se pudo guardar la configuración.");
  }
  await loadSettings();
}

async function removeAllowedDomain(allowedDomain) {
  status.textContent = "";
  const allowedDomains = savedSettings.allowedDomains.filter(
    (savedDomain) => savedDomain.domain !== allowedDomain.domain
  );
  await saveSettings(allowedDomains);
  await browser.permissions.remove({
    origins: hostPermissionPatterns(allowedDomain)
  });
  status.textContent =
    `Se eliminó ${allowedDomain.domain} de la lista permitida.`;
}

settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.textContent = "";
  try {
    await saveSettings();
    status.textContent = "Configuración guardada.";
  } catch (error) {
    showSettingsError(error);
  }
});

domainForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.textContent = "";
  try {
    const domain = normalizeDomain(domainInput.value);
    if (
      savedSettings.allowedDomains.some(
        (savedDomain) => savedDomain.domain === domain
      )
    ) {
      throw new Error("Ese dominio ya está en la lista permitida.");
    }

    const allowedDomain = {
      domain,
      includeSubdomains: includeSubdomains.checked
    };
    const granted = await browser.permissions.request({
      origins: hostPermissionPatterns(allowedDomain)
    });
    if (!granted) {
      throw new Error("Firefox no concedió permiso para ese dominio.");
    }

    await saveSettings([...savedSettings.allowedDomains, allowedDomain]);
    domainForm.reset();
    status.textContent = allowedDomain.includeSubdomains
      ? `Se añadió ${domain} y sus subdominios.`
      : `Se añadió ${domain} sin sus subdominios.`;
  } catch (error) {
    showSettingsError(error);
  }
});

lockSessionButton.addEventListener("click", async () => {
  status.textContent = "";
  try {
    const result = await browser.runtime.sendMessage({ type: "lock-session" });
    if (!result?.ok) {
      throw new Error(result?.error ?? "No se pudo cerrar la sesión.");
    }
    await loadSettings();
    status.textContent = "Sesión de descifrado cerrada.";
  } catch (error) {
    showSettingsError(error);
  }
});

keyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.textContent = "";
  const file = keyFile.files?.[0];
  if (!file) {
    status.textContent = "Selecciona un archivo de clave pública.";
    return;
  }

  try {
    const armoredKey = await file.text();
    const result = await browser.runtime.sendMessage({
      type: "import-public-key",
      armoredKey
    });
    if (!result?.ok) {
      throw new Error(result?.error ?? "No se pudo importar la clave.");
    }
    status.textContent = "Clave pública importada.";
    keyForm.reset();
    await refreshKeyStatus();
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudo importar la clave.";
  }
});

privateKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  status.textContent = "";
  const file = privateKeyFile.files?.[0];
  const passphrase = importPassphrase.value;
  importPassphrase.value = "";
  if (!file) {
    status.textContent = "Selecciona un archivo de clave privada.";
    return;
  }

  try {
    const result = await browser.runtime.sendMessage({
      type: "import-private-key",
      armoredKey: await file.text(),
      passphrase
    });
    if (!result?.ok) {
      throw new Error(result?.error ?? "No se pudo importar la clave privada.");
    }
    status.textContent = "Clave privada importada y contraseña verificada.";
    privateKeyForm.reset();
    await refreshKeyStatus();
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudo importar la clave privada.";
  } finally {
    importPassphrase.value = "";
  }
});

removeButton.addEventListener("click", async () => {
  status.textContent = "";
  try {
    const result = await browser.runtime.sendMessage({
      type: "remove-public-key"
    });
    if (!result?.ok) {
      throw new Error(result?.error ?? "No se pudo eliminar la clave pública.");
    }
    await refreshKeyStatus();
    status.textContent = "Clave eliminada.";
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudo eliminar la clave.";
  }
});

removePrivateKeyButton.addEventListener("click", async () => {
  status.textContent = "";
  try {
    const result = await browser.runtime.sendMessage({
      type: "remove-private-key"
    });
    if (!result?.ok) {
      throw new Error(result?.error ?? "No se pudo eliminar la clave privada.");
    }
    await refreshKeyStatus();
    status.textContent = "Clave privada eliminada.";
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudo eliminar la clave privada.";
  }
});

refreshKeyStatus().catch((error) => {
  keyStatus.textContent = error instanceof Error
    ? error.message
    : "No se pudo comprobar la clave.";
});
loadSettings().catch((error) => {
  sessionStatus.textContent = error instanceof Error
    ? error.message
    : "No se pudo cargar la configuración.";
});
