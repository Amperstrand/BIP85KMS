import { deriveFromSemanticPath, deriveMasterNodeFromMnemonic } from "../src/core.js";

const form = document.getElementById("derive-form");
const output = document.getElementById("output");
const deriveBtn = document.getElementById("derive-btn");
const exampleBtn = document.getElementById("example-btn");
const loadDemoBtn = document.getElementById("load-demo-btn");
const resultContainer = document.getElementById("result-container");
const errorBox = document.getElementById("error-box");
const privateKeySection = document.getElementById("private-key-section");
const derivationPathCode = document.getElementById("derivation-path");
const publicKeyCode = document.getElementById("public-key");
const privateKeyCode = document.getElementById("private-key");
const mnemonicTextarea = document.getElementById("mnemonic");
const semanticPathTextarea = document.getElementById("semanticPath");
const mnemonicStatus = document.getElementById("mnemonic-status");
const semanticStatus = document.getElementById("semantic-status");
const getPrivateKeyCheckbox = document.getElementById("getPrivateKey");
const copyStatus = document.getElementById("copy-status");

const DEMO_MNEMONIC = Array(24).fill("bacon").join(" ");
const examplePath = [
  {
    "@type": "Organization",
    "name": "AcmeCorp"
  },
  {
    "@type": "SoftwareApplication",
    "name": "backup-system",
    "applicationCategory": "Utilities"
  },
  {
    "@type": "DigitalDocument",
    "name": "database.sql"
  }
];

function setFieldStatus(element, isValid, message) {
  element.textContent = message;
  element.classList.remove("valid", "invalid");
  if (typeof isValid === "boolean") {
    element.classList.add(isValid ? "valid" : "invalid");
  }
}

function validateMnemonic() {
  const words = mnemonicTextarea.value.trim().split(/\s+/).filter(Boolean);
  if (!words.length) {
    setFieldStatus(mnemonicStatus, undefined, "Awaiting mnemonic input.");
    return false;
  }
  const valid = [12, 15, 18, 21, 24].includes(words.length);
  setFieldStatus(
    mnemonicStatus,
    valid,
    valid ? `Valid: word count ${words.length} (basic pre-check)` : `Invalid: word count ${words.length}`
  );
  return valid;
}

function parseSemanticPath() {
  const semanticPathText = semanticPathTextarea.value.trim();
  if (!semanticPathText) {
    setFieldStatus(semanticStatus, undefined, "Awaiting semantic path input.");
    return null;
  }
  try {
    const parsed = JSON.parse(semanticPathText);
    const validStructure = Array.isArray(parsed) && parsed.length > 0 && parsed.every((segment) => segment && typeof segment === "object" && segment["@type"]);
    setFieldStatus(
      semanticStatus,
      validStructure,
      validStructure ? `Valid: semantic path (${parsed.length} segment${parsed.length === 1 ? "" : "s"})` : "Invalid: must be a non-empty JSON array where each segment has @type"
    );
    return validStructure ? parsed : null;
  } catch {
    setFieldStatus(semanticStatus, false, "Invalid: JSON parsing failed");
    return null;
  }
}

function setLoading(isLoading) {
  deriveBtn.classList.toggle("loading", isLoading);
  deriveBtn.disabled = isLoading;
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function hideError() {
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
}

function renderResult(result, includePrivateKey) {
  const visibleResult = includePrivateKey
    ? result
    : {
        age_public_key: result.age_public_key,
        derivationPath: result.derivationPath,
        semanticPath: result.semanticPath,
      };
  output.textContent = JSON.stringify(visibleResult, null, 2);
  derivationPathCode.textContent = result.derivationPath;
  publicKeyCode.textContent = result.age_public_key;
  privateKeyCode.textContent = result.age_private_key;
  privateKeySection.classList.toggle("hidden", !includePrivateKey);
  resultContainer.classList.remove("hidden");
}

function copyToClipboard(text, button) {
  if (!navigator.clipboard) {
    showError("Clipboard API is unavailable in this browser context.");
    return;
  }
  if (typeof navigator.clipboard.writeText !== "function") {
    showError("Clipboard write support is unavailable in this browser context.");
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    const originalText = button.textContent;
    button.textContent = "Copied!";
    copyStatus.textContent = `${originalText} copied to clipboard.`;
    setTimeout(() => {
      button.textContent = originalText;
    }, 2000);
  }).catch(() => {
    showError("Failed to copy to clipboard.");
  });
}

exampleBtn.addEventListener("click", () => {
  semanticPathTextarea.value = JSON.stringify(examplePath, null, 2);
  parseSemanticPath();
});

loadDemoBtn.addEventListener("click", () => {
  mnemonicTextarea.value = DEMO_MNEMONIC;
  semanticPathTextarea.value = JSON.stringify(examplePath, null, 2);
  validateMnemonic();
  parseSemanticPath();
});

mnemonicTextarea.addEventListener("input", validateMnemonic);
semanticPathTextarea.addEventListener("input", parseSemanticPath);

document.addEventListener("click", (event) => {
  const button = event.target.closest(".copy-btn");
  if (!button) {
    return;
  }
  const target = document.getElementById(button.dataset.copyTarget);
  if (!target) {
    return;
  }
  copyToClipboard(target.textContent, button);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setLoading(true);
  hideError();
  try {
    const mnemonic = mnemonicTextarea.value.trim();
    const getPrivateKey = getPrivateKeyCheckbox.checked;
    if (!mnemonic) {
      throw new Error("Please enter a mnemonic.");
    }
    if (!validateMnemonic()) {
      throw new Error("Mnemonic must contain 12, 15, 18, 21, or 24 words.");
    }
    const semanticPath = parseSemanticPath();
    if (!semanticPath) {
      throw new Error("Please provide a valid semantic path.");
    }
    const masterNode = deriveMasterNodeFromMnemonic(mnemonic);
    const result = deriveFromSemanticPath(masterNode, semanticPath);
    renderResult(result, getPrivateKey);
  } catch (error) {
    showError(`Error: ${error.message}`);
  } finally {
    setLoading(false);
  }
});
