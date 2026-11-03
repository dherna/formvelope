const encryptButton = document.querySelector("#encrypt");
const encryptFormButton = document.querySelector("#encrypt-form");
const decryptButton = document.querySelector("#decrypt");
const decryptPageButton = document.querySelector("#decrypt-page");
const passphraseInput = document.querySelector("#passphrase");
const status = document.querySelector("#status");
const switchViewButton = document.querySelector("#switch-view");

async function getActiveTab() {
  const [tab] = await browser.tabs.query({
    active: true,
    currentWindow: true
  });
  if (!tab?.id) {
    throw new Error("No se encontró la pestaña activa.");
  }

  await browser.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["build/content.js"]
  });
  return tab.id;
}

switchViewButton.addEventListener("click", async () => {
  switchViewButton.disabled = true;
  const isSidebar = document.body.classList.contains("sidebar");
  try {
    if (isSidebar) {
      await browser.sidebarAction.close();
      await browser.action.openPopup();
    } else {
      await browser.sidebarAction.open();
      window.close();
    }
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudo cambiar de vista.";
    if (isSidebar) {
      try {
        await browser.sidebarAction.open();
      } catch {
        status.textContent += " No se pudo volver a abrir la barra lateral.";
      }
    }
    switchViewButton.disabled = false;
  }
});

encryptButton.addEventListener("click", async () => {
  encryptButton.disabled = true;
  status.textContent = "Cifrando...";

  try {
    const tabId = await getActiveTab();
    const result = await browser.tabs.sendMessage(tabId, {
      type: "encrypt-focused-field"
    });
    if (!result?.ok) {
      throw new Error(result?.error ?? "No se pudo cifrar el campo.");
    }

    status.textContent = "Campo cifrado. Revisa el contenido antes de enviarlo.";
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudo cifrar el campo.";
  } finally {
    encryptButton.disabled = false;
  }
});

encryptFormButton.addEventListener("click", async () => {
  encryptFormButton.disabled = true;
  status.textContent = "Cifrando campos del formulario...";

  try {
    const tabId = await getActiveTab();
    const result = await browser.tabs.sendMessage(tabId, {
      type: "encrypt-form-fields"
    });
    if (!result?.ok) {
      throw new Error(result?.error ?? "No se pudieron cifrar los campos.");
    }

    status.textContent = `Se cifraron ${result.count} campos multilínea.`;
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudieron cifrar los campos.";
  } finally {
    encryptFormButton.disabled = false;
  }
});

decryptPageButton.addEventListener("click", async () => {
  decryptPageButton.disabled = true;
  status.textContent = "Descifrando campos de la página...";
  let passphrase = passphraseInput.value;
  passphraseInput.value = "";

  try {
    const tabId = await getActiveTab();
    if (passphrase) {
      const unlockResult = await browser.runtime.sendMessage({
        type: "unlock-session",
        passphrase
      });
      if (!unlockResult?.ok) {
        throw new Error(unlockResult?.error ?? "No se pudo iniciar la sesión.");
      }
      passphrase = "";
    }

    const result = await browser.tabs.sendMessage(tabId, {
      type: "decrypt-page-fields"
    });
    if (!result?.ok) {
      throw new Error(result?.error ?? "No se pudieron descifrar los campos.");
    }
    status.textContent = result.ciphertextCount
      ? `Se descifraron ${result.ciphertextCount} fragmentos.`
      : "No se encontró contenido cifrado en esta página.";
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudieron descifrar los campos.";
  } finally {
    passphrase = "";
    passphraseInput.value = "";
    decryptPageButton.disabled = false;
  }
});

decryptButton.addEventListener("click", async () => {
  decryptButton.disabled = true;
  status.textContent = "Descifrando...";
  let passphrase = passphraseInput.value;
  passphraseInput.value = "";

  try {
    const tabId = await getActiveTab();
    const fieldResult = await browser.tabs.sendMessage(tabId, {
      type: "get-focused-text"
    });
    if (!fieldResult?.ok) {
      throw new Error(fieldResult?.error ?? "No se pudo leer el campo enfocado.");
    }

    const decryptResult = await browser.runtime.sendMessage({
      type: "decrypt-text",
      ciphertext: fieldResult.text,
      passphrase
    });
    if (!decryptResult?.ok) {
      throw new Error(decryptResult?.error ?? "No se pudo descifrar el texto.");
    }

    const replaceResult = await browser.tabs.sendMessage(tabId, {
      type: "replace-focused-text",
      text: decryptResult.plaintext
    });
    if (!replaceResult?.ok) {
      throw new Error(replaceResult?.error ?? "No se pudo actualizar el campo.");
    }
    status.textContent = "Campo descifrado.";
  } catch (error) {
    status.textContent = error instanceof Error
      ? error.message
      : "No se pudo descifrar el campo.";
  } finally {
    passphrase = "";
    passphraseInput.value = "";
    decryptButton.disabled = false;
  }
});
