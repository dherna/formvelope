if (!globalThis.formvelopeContentLoaded) {
  globalThis.formvelopeContentLoaded = true;
  let focusedTextField;

  const isTextEditor = (field) =>
    field instanceof HTMLTextAreaElement ||
    (field instanceof HTMLElement && field.isContentEditable);

  const readField = (field) =>
    field instanceof HTMLTextAreaElement ? field.value : field.innerText;

  function writeField(field, text) {
    if (field instanceof HTMLTextAreaElement) {
      field.value = text;
    } else {
      field.innerText = text;
    }
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function getArmoredMessages(text) {
    return [...text.matchAll(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g)]
      .map(([ciphertext]) => ciphertext);
  }

  function replaceArmoredMessages(text, plaintexts) {
    let result = "";
    let cursor = 0;
    let index = 0;
    const pattern = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g;
    for (const match of text.matchAll(pattern)) {
      result += text.slice(cursor, match.index) + plaintexts[index];
      cursor = match.index + match[0].length;
      index += 1;
    }
    return result + text.slice(cursor);
  }

  function appendPlaintext(fragment, text) {
    const lines = text.split(/\r\n?|\n/);
    lines.forEach((line, index) => {
      if (index > 0) {
        fragment.append(document.createElement("br"));
      }
      fragment.append(document.createTextNode(line));
    });
  }

  function isIgnoredElement(element) {
    return element.matches(
      "script, style, noscript, textarea, input, select, option, [contenteditable]"
    );
  }

  function getTextStream(root) {
    const blockTags = new Set([
      "ADDRESS", "BLOCKQUOTE", "DD", "DIV", "DL", "DT", "FIELDSET",
      "FIGCAPTION", "FIGURE", "FOOTER", "FORM", "H1", "H2", "H3",
      "H4", "H5", "H6", "HEADER", "HR", "LI", "MAIN", "OL", "P",
      "SECTION", "TABLE", "TBODY", "TD", "TFOOT", "TH", "THEAD", "TR", "UL"
    ]);
    const walker = document.createTreeWalker(
      root,
      NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          if (node instanceof Element) {
            if (node !== root && isIgnoredElement(node)) {
              return NodeFilter.FILTER_REJECT;
            }
            return node.tagName === "BR" || blockTags.has(node.tagName)
              ? NodeFilter.FILTER_ACCEPT
              : NodeFilter.FILTER_SKIP;
          }
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );
    const events = [];
    let text = "";
    let node = walker.nextNode();
    while (node) {
      let value = node.nodeValue ?? "";
      if (node instanceof Element && node.tagName === "BR") {
        value = "\n";
      } else if (node instanceof Element && blockTags.has(node.tagName)) {
        value = text && !text.endsWith("\n") ? "\n" : "";
      }
      events.push({ node, start: text.length, end: text.length + value.length });
      text += value;
      node = walker.nextNode();
    }
    return { events, text };
  }

  function findTextPosition(events, position) {
    const event = events.find(({ node, start, end }) =>
      node.nodeType === Node.TEXT_NODE && position >= start && position <= end
    );
    return event
      ? { node: event.node, offset: position - event.start }
      : undefined;
  }

  function collectStreamMatches(root, ciphertexts, edits) {
    const { events, text } = getTextStream(root);
    const pattern = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g;
    for (const match of text.matchAll(pattern)) {
      const start = findTextPosition(events, match.index);
      const end = findTextPosition(events, match.index + match[0].length);
      if (!start || !end) {
        continue;
      }
      const index = ciphertexts.length;
      ciphertexts.push(match[0]);
      edits.push({
        index,
        start,
        end
      });
    }
  }

  function renderDecryptedText(edit, plaintext) {
    if (!edit.start.node.isConnected || !edit.end.node.isConnected) {
      return;
    }
    const range = document.createRange();
    range.setStart(edit.start.node, edit.start.offset);
    range.setEnd(edit.end.node, edit.end.offset);
    range.deleteContents();
    const fragment = document.createDocumentFragment();
    appendPlaintext(fragment, plaintext);
    range.insertNode(fragment);
  }

  function collectPageCiphertexts() {
    const ciphertexts = [];
    const edits = [];
    const editors = [...document.querySelectorAll("textarea, [contenteditable]")]
      .filter(isTextEditor);
    for (const field of editors) {
      const originalText = readField(field);
      const messages = getArmoredMessages(originalText);
      if (messages.length === 0) {
        continue;
      }
      const startIndex = ciphertexts.length;
      ciphertexts.push(...messages);
      edits.push({
        apply(plaintexts) {
          writeField(
            field,
            replaceArmoredMessages(
              originalText,
              plaintexts.slice(startIndex, startIndex + messages.length)
            )
          );
        }
      });
    }

    const containers = [...document.querySelectorAll("td, th, pre")]
      .filter((container) =>
        !container.closest("[contenteditable]") &&
        !container.querySelector("td, th, pre")
      );
    for (const container of containers) {
      collectStreamMatches(container, ciphertexts, edits);
    }

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node = walker.nextNode();
    while (node) {
      if (
        !node.parentElement?.closest(
          "script, style, noscript, textarea, input, select, option, [contenteditable], td, th, pre"
        )
      ) {
        const messages = getArmoredMessages(node.nodeValue ?? "");
        if (messages.length > 0) {
          const startIndex = ciphertexts.length;
          ciphertexts.push(...messages);
          const textNode = node;
          for (let index = 0; index < messages.length; index += 1) {
            const ciphertextIndex = startIndex + index;
            const nodePattern = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g;
            const match = [...(textNode.nodeValue ?? "").matchAll(nodePattern)][index];
            if (!match) {
              continue;
            }
            edits.push({
              index: ciphertextIndex,
              start: { node: textNode, offset: match.index },
              end: { node: textNode, offset: match.index + match[0].length }
            });
          }
        }
      }
      node = walker.nextNode();
    }
    return { ciphertexts, edits };
  }

  async function decryptPageContent(automatic) {
    const { ciphertexts, edits } = collectPageCiphertexts();
    if (ciphertexts.length === 0) {
      return { ok: true, ciphertextCount: 0 };
    }

    const result = await browser.runtime.sendMessage({
      type: "decrypt-page-fields",
      automatic,
      ciphertexts
    });
    if (!result?.ok || !result.plaintexts) {
      return result;
    }

    for (const edit of edits.filter(({ apply }) => apply)) {
      edit.apply(result.plaintexts);
    }
    edits
      .filter(({ start }) => start)
      .sort((left, right) => right.index - left.index)
      .forEach((edit) => renderDecryptedText(edit, result.plaintexts[edit.index]));
    return { ...result, ciphertextCount: ciphertexts.length };
  }

  let automaticDecryptionTask;
  let automaticDecryptionTimer;
  let automaticDecryptionPending = false;
  function runAutomaticDecryption() {
    if (!automaticDecryptionTask) {
      automaticDecryptionTask = (async () => {
        let result;
        do {
          automaticDecryptionPending = false;
          result = await decryptPageContent(true);
        } while (automaticDecryptionPending);
        return result;
      })().finally(() => {
        automaticDecryptionTask = undefined;
      });
    } else {
      automaticDecryptionPending = true;
    }
    return automaticDecryptionTask;
  }

  function containsArmoredMessage(node) {
    const text = node.textContent ?? node.nodeValue ?? "";
    return text.includes("-----BEGIN PGP MESSAGE-----");
  }

  const pageObserver = new MutationObserver((mutations) => {
    const hasCiphertext = mutations.some((mutation) =>
      (mutation.type === "characterData" && containsArmoredMessage(mutation.target)) ||
      [...mutation.addedNodes].some(containsArmoredMessage)
    );
    if (!hasCiphertext) {
      return;
    }
    clearTimeout(automaticDecryptionTimer);
    automaticDecryptionTimer = setTimeout(() => {
      runAutomaticDecryption().catch((error) => {
        console.error("No se pudieron descifrar los campos de la página:", error);
      });
    }, 250);
  });
  pageObserver.observe(document.documentElement, {
    childList: true,
    subtree: true,
    characterData: true
  });

  browser.runtime.onMessage.addListener(async (message) => {
    if (message?.type === "encrypt-focused-field") {
      const field = document.activeElement;
      if (!isTextEditor(field)) {
        return {
          ok: false,
          error: "Enfoca un área de texto o un editor de texto compatible."
        };
      }

      focusedTextField = field;
      const text = readField(field);
      if (!text.trim()) {
        return { ok: false, error: "El campo está vacío." };
      }
      const result = await browser.runtime.sendMessage({
        type: "encrypt-text",
        text
      });
      if (!result?.ok) {
        return result ?? { ok: false, error: "No se pudo cifrar el texto." };
      }

      writeField(field, result.ciphertext);
      return { ok: true };
    }

    if (message?.type === "encrypt-form-fields") {
      const focusedField = document.activeElement;
      if (!isTextEditor(focusedField)) {
        return {
          ok: false,
          error: "Enfoca un área multilínea dentro del formulario que quieras cifrar."
        };
      }

      const form = focusedField.closest("form");
      if (!form) {
        return { ok: false, error: "El campo enfocado no pertenece a un formulario." };
      }

      const fields = [...form.querySelectorAll("textarea, [contenteditable]")]
        .filter((field) =>
          isTextEditor(field) &&
          !field.matches(":disabled, [readonly]") &&
          readField(field).trim() &&
          !isArmoredMessage(readField(field))
        );
      if (fields.length === 0) {
        return {
          ok: false,
          error: "No hay campos multilínea con texto para cifrar en este formulario."
        };
      }

      const result = await browser.runtime.sendMessage({
        type: "encrypt-texts",
        texts: fields.map(readField)
      });
      if (!result?.ok) {
        return result ?? { ok: false, error: "No se pudieron cifrar los campos." };
      }

      fields.forEach((field, index) => writeField(field, result.ciphertexts[index]));
      return { ok: true, count: fields.length };
    }

    if (message?.type === "get-focused-text") {
      const field = document.activeElement;
      if (!isTextEditor(field)) {
        return {
          ok: false,
          error: "Enfoca un área de texto o un editor de texto compatible."
        };
      }
      focusedTextField = field;
      return { ok: true, text: readField(field) };
    }

    if (message?.type === "replace-focused-text") {
      const field = focusedTextField;
      if (!isTextEditor(field)) {
        return {
          ok: false,
          error: "Enfoca un área de texto o un editor de texto compatible."
        };
      }
      if (typeof message.text !== "string") {
        return { ok: false, error: "El texto descifrado no es válido." };
      }

      writeField(field, message.text);
      return { ok: true };
    }

    if (message?.type === "decrypt-page-fields") {
      return decryptPageContent(false);
    }

    return undefined;
  });

  runAutomaticDecryption().catch((error) => {
    console.error("No se pudieron descifrar los campos de la página:", error);
  });
}
