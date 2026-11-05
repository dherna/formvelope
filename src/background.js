import * as openpgp from "openpgp";
import {
  domainMatchesAllowedDomain,
  hostPermissionPatterns,
  isValidAllowedDomain,
  normalizeAllowedDomain
} from "./domain.js";

const KEY_STORAGE_NAME = "recipientPublicKey";
const PRIVATE_KEY_STORAGE_NAME = "privateKey";
const PRIVATE_KEY_SESSION_STORAGE_NAME = "privateKeySession";
const SETTINGS_STORAGE_NAME = "formvelopeSettings";
const AUTOMATIC_SCRIPT_ID = "formvelope-automatic-decryption";

const DEFAULT_SETTINGS = {
  decryptionMode: "manual",
  sessionDurationMinutes: 60,
  allowedDomains: []
};

let privateKeySession;
let sessionTimer;

async function importEncryptionKey(armoredKey) {
  if (typeof armoredKey !== "string" || !armoredKey.trim()) {
    throw new Error("El archivo no contiene una clave OpenPGP.");
  }

  const key = await openpgp.readKey({ armoredKey });
  if (key.isPrivate()) {
    throw new Error("Se requiere una clave pública, no una clave privada.");
  }

  await key.getEncryptionKey();
  return key;
}

async function unlockPrivateKey(armoredKey, passphrase) {
  if (typeof armoredKey !== "string" || !armoredKey.trim()) {
    throw new Error("No hay una clave privada cargada.");
  }
  if (typeof passphrase !== "string" || !passphrase) {
    throw new Error("Introduce la contraseña de la clave privada.");
  }

  const privateKey = await openpgp.readPrivateKey({ armoredKey });
  if (!privateKey.isPrivate()) {
    throw new Error("El archivo seleccionado no contiene una clave privada.");
  }

  const encryptedSecretPackets = [
    privateKey.keyPacket,
    ...privateKey.subkeys.map(({ keyPacket }) => keyPacket)
  ].filter((packet) => packet.isDecrypted() === false);
  if (encryptedSecretPackets.length === 0) {
    throw new Error("La clave privada debe estar protegida con contraseña.");
  }

  return openpgp.decryptKey({ privateKey, passphrase });
}

function normalizeAllowedDomains(entries) {
  if (!Array.isArray(entries)) {
    return [];
  }
  const domains = [];
  const seen = new Set();
  for (const entry of entries) {
    const allowedDomain = normalizeAllowedDomain(entry);
    if (!isValidAllowedDomain(allowedDomain) || seen.has(allowedDomain.domain)) {
      continue;
    }
    seen.add(allowedDomain.domain);
    domains.push(allowedDomain);
  }
  return domains;
}

async function getSettings() {
  const stored = await browser.storage.local.get(SETTINGS_STORAGE_NAME);
  const settings = {
    ...DEFAULT_SETTINGS,
    ...(stored[SETTINGS_STORAGE_NAME] ?? {})
  };
  return {
    ...settings,
    allowedDomains: normalizeAllowedDomains(settings.allowedDomains)
  };
}

async function clearPrivateKeySession() {
  if (sessionTimer !== undefined) {
    clearTimeout(sessionTimer);
    sessionTimer = undefined;
  }
  privateKeySession = undefined;
  await browser.storage.session.remove(PRIVATE_KEY_SESSION_STORAGE_NAME);
}

function schedulePrivateKeySessionExpiry(expiresAt) {
  if (sessionTimer !== undefined) {
    clearTimeout(sessionTimer);
  }
  sessionTimer = setTimeout(() => {
    if (privateKeySession?.expiresAt === expiresAt) {
      clearPrivateKeySession().catch((error) => {
        console.error("No se pudo cerrar la sesión de descifrado:", error);
      });
    }
  }, Math.max(0, expiresAt - Date.now()));
}

async function storePrivateKeySession(privateKey, startedAt, expiresAt) {
  await browser.storage.session.set({
    [PRIVATE_KEY_SESSION_STORAGE_NAME]: {
      armoredKey: privateKey.armor(),
      startedAt,
      expiresAt
    }
  });
  privateKeySession = { privateKey, startedAt, expiresAt };
  schedulePrivateKeySessionExpiry(expiresAt);
}

async function getPrivateKeySession() {
  if (privateKeySession && privateKeySession.expiresAt > Date.now()) {
    return privateKeySession;
  }

  const stored = await browser.storage.session.get(
    PRIVATE_KEY_SESSION_STORAGE_NAME
  );
  const savedSession = stored[PRIVATE_KEY_SESSION_STORAGE_NAME];
  if (!savedSession) {
    return undefined;
  }
  if (
    typeof savedSession.armoredKey !== "string" ||
    !Number.isFinite(savedSession.startedAt) ||
    !Number.isFinite(savedSession.expiresAt)
  ) {
    throw new Error("La sesión de descifrado guardada no es válida.");
  }
  if (savedSession.expiresAt <= Date.now()) {
    await clearPrivateKeySession();
    return undefined;
  }

  const privateKey = await openpgp.readPrivateKey({
    armoredKey: savedSession.armoredKey
  });
  const encryptedSecretPackets = [
    privateKey.keyPacket,
    ...privateKey.subkeys.map(({ keyPacket }) => keyPacket)
  ].filter((packet) => packet.isDecrypted() === false);
  if (!privateKey.isPrivate() || encryptedSecretPackets.length > 0) {
    throw new Error("No se pudo restaurar la sesión de descifrado.");
  }

  privateKeySession = {
    privateKey,
    startedAt: savedSession.startedAt,
    expiresAt: savedSession.expiresAt
  };
  schedulePrivateKeySessionExpiry(savedSession.expiresAt);
  return privateKeySession;
}

async function getDecryptedPrivateKey(passphrase) {
  if (typeof passphrase === "string" && passphrase) {
    const stored = await browser.storage.local.get(PRIVATE_KEY_STORAGE_NAME);
    const privateKey = await unlockPrivateKey(
      stored[PRIVATE_KEY_STORAGE_NAME],
      passphrase
    );
    const settings = await getSettings();
    const startedAt = Date.now();
    const expiresAt = startedAt + settings.sessionDurationMinutes * 60_000;
    await clearPrivateKeySession();
    await storePrivateKeySession(privateKey, startedAt, expiresAt);
    return privateKey;
  }

  const session = await getPrivateKeySession();
  if (session) {
    return session.privateKey;
  }

  throw new Error("Introduce la contraseña para iniciar una sesión de descifrado.");
}

async function decryptText(ciphertext, privateKey) {
  if (typeof ciphertext !== "string" || !ciphertext.trim()) {
    throw new Error("No hay texto cifrado para descifrar.");
  }

  const decrypted = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: ciphertext }),
    decryptionKeys: privateKey
  });
  if (typeof decrypted.data !== "string") {
    throw new Error("El mensaje descifrado no es texto.");
  }
  return decrypted.data;
}

async function isAllowedPage(url, settings) {
  if (typeof url !== "string") {
    return false;
  }
  let hostname;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  const matchingDomains = settings.allowedDomains.filter((entry) =>
    domainMatchesAllowedDomain(hostname, entry)
  );
  for (const entry of matchingDomains) {
    for (const pattern of hostPermissionPatterns(entry)) {
      if (await browser.permissions.contains({ origins: [pattern] })) {
        return true;
      }
    }
  }
  return false;
}

async function isAllowedSenderPage(sender, settings) {
  if (sender?.tab) {
    return isAllowedPage(sender.url ?? sender.tab.url, settings);
  }
  const [tab] = await browser.tabs.query({
    active: true,
    lastFocusedWindow: true
  });
  return isAllowedPage(tab?.url, settings);
}

async function syncAutomaticContentScript() {
  const registered = await browser.scripting.getRegisteredContentScripts();
  if (registered.some(({ id }) => id === AUTOMATIC_SCRIPT_ID)) {
    await browser.scripting.unregisterContentScripts({
      ids: [AUTOMATIC_SCRIPT_ID]
    });
  }

  const settings = await getSettings();
  if (settings.decryptionMode !== "automatic") {
    return;
  }

  const matches = [];
  for (const entry of settings.allowedDomains) {
    for (const pattern of hostPermissionPatterns(entry)) {
      if (await browser.permissions.contains({ origins: [pattern] })) {
        matches.push(pattern);
      }
    }
  }
  if (matches.length === 0) {
    return;
  }

  await browser.scripting.registerContentScripts([{
    id: AUTOMATIC_SCRIPT_ID,
    matches: [...new Set(matches)],
    js: ["build/content.js"],
    runAt: "document_idle",
    persistAcrossSessions: true
  }]);
}

function reportAutomaticScriptError(error) {
  console.error("No se pudo actualizar el descifrado automático:", error);
}

browser.runtime.onStartup.addListener(() => {
  syncAutomaticContentScript().catch(reportAutomaticScriptError);
});
browser.runtime.onInstalled.addListener(() => {
  syncAutomaticContentScript().catch(reportAutomaticScriptError);
});
browser.permissions.onRemoved.addListener(() => {
  syncAutomaticContentScript().catch(reportAutomaticScriptError);
});

async function handleMessage(message, sender) {
  if (message?.type === "import-public-key") {
    const key = await importEncryptionKey(message.armoredKey);
    await browser.storage.local.set({
      [KEY_STORAGE_NAME]: key.armor()
    });
    return { ok: true, fingerprint: key.getFingerprint() };
  }

  if (message?.type === "remove-public-key") {
    await browser.storage.local.remove(KEY_STORAGE_NAME);
    return { ok: true };
  }

  if (message?.type === "import-private-key") {
    const privateKey = await unlockPrivateKey(
      message.armoredKey,
      message.passphrase
    );
    await browser.storage.local.set({
      [PRIVATE_KEY_STORAGE_NAME]: message.armoredKey.trim()
    });
    await clearPrivateKeySession();
    return { ok: true, fingerprint: privateKey.getFingerprint() };
  }

  if (message?.type === "remove-private-key") {
    await browser.storage.local.remove(PRIVATE_KEY_STORAGE_NAME);
    await clearPrivateKeySession();
    return { ok: true };
  }

  if (message?.type === "get-settings") {
    const settings = await getSettings();
    const session = await getPrivateKeySession();
    const sessionActive = Boolean(session);
    return {
      ok: true,
      ...settings,
      sessionActive,
      sessionExpiresAt: session?.expiresAt ?? null
    };
  }

  if (message?.type === "set-settings") {
    const { decryptionMode, sessionDurationMinutes, allowedDomains } = message;
    if (!["manual", "automatic"].includes(decryptionMode)) {
      throw new Error("El modo de descifrado seleccionado no es válido.");
    }
    if (
      !Number.isInteger(sessionDurationMinutes) ||
      sessionDurationMinutes < 1 ||
      sessionDurationMinutes > 1440
    ) {
      throw new Error("La duración de sesión debe estar entre 1 y 1440 minutos.");
    }
    const normalizedAllowedDomains = Array.isArray(allowedDomains)
      ? allowedDomains.map(normalizeAllowedDomain)
      : [];
    if (
      !Array.isArray(allowedDomains) ||
      !normalizedAllowedDomains.every(isValidAllowedDomain) ||
      new Set(normalizedAllowedDomains.map(({ domain }) => domain)).size !==
        normalizedAllowedDomains.length
    ) {
      throw new Error("La lista de dominios permitidos no es válida.");
    }

    const session = await getPrivateKeySession();
    await browser.storage.local.set({
      [SETTINGS_STORAGE_NAME]: {
        decryptionMode,
        sessionDurationMinutes,
        allowedDomains: normalizedAllowedDomains
      }
    });
    if (session) {
      const { privateKey, startedAt } = session;
      const expiresAt = startedAt + sessionDurationMinutes * 60_000;
      await clearPrivateKeySession();
      if (expiresAt > Date.now()) {
        await storePrivateKeySession(privateKey, startedAt, expiresAt);
      }
    }
    await syncAutomaticContentScript();
    return { ok: true };
  }

  if (message?.type === "unlock-session") {
    await getDecryptedPrivateKey(message.passphrase);
    const session = await getPrivateKeySession();
    if (!session) {
      throw new Error("La sesión de descifrado ha caducado.");
    }
    return {
      ok: true,
      sessionExpiresAt: session.expiresAt
    };
  }

  if (message?.type === "lock-session") {
    await clearPrivateKeySession();
    return { ok: true };
  }

  if (message?.type === "get-key-status") {
    const stored = await browser.storage.local.get([
      KEY_STORAGE_NAME,
      PRIVATE_KEY_STORAGE_NAME
    ]);
    const result = {
      publicKey: { configured: false },
      privateKey: { configured: false }
    };
    if (stored[KEY_STORAGE_NAME]) {
      const key = await importEncryptionKey(stored[KEY_STORAGE_NAME]);
      result.publicKey = {
        configured: true,
        fingerprint: key.getFingerprint()
      };
    }
    if (stored[PRIVATE_KEY_STORAGE_NAME]) {
      const key = await openpgp.readPrivateKey({
        armoredKey: stored[PRIVATE_KEY_STORAGE_NAME]
      });
      result.privateKey = {
        configured: true,
        fingerprint: key.getFingerprint()
      };
    }
    return result;
  }

  if (message?.type === "encrypt-text") {
    if (typeof message.text !== "string" || !message.text.trim()) {
      throw new Error("No hay texto para cifrar.");
    }

    const result = await handleMessage({
      type: "encrypt-texts",
      texts: [message.text]
    });
    return { ok: true, ciphertext: result.ciphertexts[0] };
  }

  if (message?.type === "encrypt-texts") {
    if (
      !Array.isArray(message.texts) ||
      message.texts.length === 0 ||
      message.texts.length > 100 ||
      !message.texts.every((text) => typeof text === "string" && text.trim())
    ) {
      throw new Error("No hay campos válidos para cifrar.");
    }

    const stored = await browser.storage.local.get(KEY_STORAGE_NAME);
    if (!stored[KEY_STORAGE_NAME]) {
      throw new Error("Primero importa una clave pública en las opciones.");
    }

    const encryptionKey = await importEncryptionKey(stored[KEY_STORAGE_NAME]);
    const ciphertexts = [];
    for (const text of message.texts) {
      ciphertexts.push(await openpgp.encrypt({
        message: await openpgp.createMessage({ text }),
        encryptionKeys: encryptionKey
      }));
    }
    return { ok: true, ciphertexts };
  }

  if (message?.type === "decrypt-text") {
    const settings = await getSettings();
    if (!await isAllowedSenderPage(sender, settings)) {
      throw new Error("Este dominio no está permitido o falta su permiso.");
    }
    const privateKey = await getDecryptedPrivateKey(message.passphrase);
    const session = await getPrivateKeySession();
    if (!session) {
      throw new Error("La sesión de descifrado ha caducado.");
    }
    return {
      ok: true,
      plaintext: await decryptText(message.ciphertext, privateKey),
      sessionExpiresAt: session.expiresAt
    };
  }

  if (message?.type === "decrypt-page-fields") {
    const settings = await getSettings();
    const isAutomatic = message.automatic === true;
    if (isAutomatic && settings.decryptionMode !== "automatic") {
      return { ok: true, ciphertextCount: 0 };
    }
    if (!sender?.tab || !await isAllowedPage(sender.url, settings)) {
      return isAutomatic
        ? { ok: true, ciphertextCount: 0 }
        : { ok: false, error: "Este dominio no está permitido o falta su permiso." };
    }
    if (
      !Array.isArray(message.ciphertexts) ||
      message.ciphertexts.length > 100 ||
      !message.ciphertexts.every((text) => typeof text === "string")
    ) {
      throw new Error("La lista de campos de la página no es válida.");
    }
    if (message.ciphertexts.length === 0) {
      return { ok: true, plaintexts: [], ciphertextCount: 0 };
    }
    const session = await getPrivateKeySession();
    if (!session) {
      return isAutomatic
        ? { ok: true, ciphertextCount: 0, sessionRequired: true }
        : { ok: false, error: "Introduce la contraseña para iniciar la sesión de descifrado." };
    }

    const { privateKey, expiresAt: sessionExpiresAt } = session;
    const plaintexts = [];
    for (const ciphertext of message.ciphertexts) {
      plaintexts.push(await decryptText(ciphertext, privateKey));
    }
    return {
      ok: true,
      plaintexts,
      ciphertextCount: plaintexts.length,
      sessionExpiresAt
    };
  }

  return undefined;
}

browser.runtime.onMessage.addListener((message, sender) =>
  handleMessage(message, sender).catch((error) => ({
    ok: false,
    error: error instanceof Error ? error.message : "Error inesperado."
  }))
);
