import { deriveFromSemanticPath, deriveMasterNodeFromMnemonic, type SemanticSegment } from "../src/core";

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

const form = byId<HTMLFormElement>("derive-form");
const output = byId<HTMLElement>("output");
const deriveBtn = byId<HTMLButtonElement>("derive-btn");
const exampleBtn = byId<HTMLButtonElement>("example-btn");
const loadDemoBtn = byId<HTMLButtonElement>("load-demo-btn");
const resultContainer = byId<HTMLElement>("result-container");
const errorBox = byId<HTMLElement>("error-box");
const privateKeySection = byId<HTMLElement>("private-key-section");
const derivationPathCode = byId<HTMLElement>("derivation-path");
const publicKeyCode = byId<HTMLElement>("public-key");
const privateKeyCode = byId<HTMLElement>("private-key");
const mnemonicTextarea = byId<HTMLTextAreaElement>("mnemonic");
const semanticPathTextarea = byId<HTMLTextAreaElement>("semanticPath");
const mnemonicStatus = byId<HTMLElement>("mnemonic-status");
const semanticStatus = byId<HTMLElement>("semantic-status");
const getPrivateKeyCheckbox = byId<HTMLInputElement>("getPrivateKey");
const copyStatus = byId<HTMLElement>("copy-status");

const DEMO_MNEMONIC = Array(24).fill("bacon").join(" ");
const examplePath: SemanticSegment[] = [
  {
    "@type": "Organization",
    "name": "AcmeCorp",
  },
  {
    "@type": "SoftwareApplication",
    "name": "backup-system",
    "applicationCategory": "Utilities",
  },
  {
    "@type": "DigitalDocument",
    "name": "database.sql",
  },
];

function setFieldStatus(element: HTMLElement, isValid: boolean | undefined, message: string): void {
  element.textContent = message;
  element.classList.remove("valid", "invalid");
  if (typeof isValid === "boolean") {
    element.classList.add(isValid ? "valid" : "invalid");
  }
}

function validateMnemonic(): boolean {
  const words = mnemonicTextarea.value.trim().split(/\s+/).filter(Boolean);
  if (!words.length) {
    setFieldStatus(mnemonicStatus, undefined, "Awaiting mnemonic input.");
    return false;
  }
  const valid = [12, 15, 18, 21, 24].includes(words.length);
  setFieldStatus(
    mnemonicStatus,
    valid,
    valid ? `Valid: word count ${words.length} (basic pre-check)` : `Invalid: word count ${words.length}`,
  );
  return valid;
}

function parseSemanticPath(): SemanticSegment[] | null {
  const semanticPathText = semanticPathTextarea.value.trim();
  if (!semanticPathText) {
    setFieldStatus(semanticStatus, undefined, "Awaiting semantic path input.");
    return null;
  }
  try {
    const parsed = JSON.parse(semanticPathText);
    const validStructure =
      Array.isArray(parsed) && parsed.length > 0 && parsed.every((segment) => segment && typeof segment === "object" && segment["@type"]);
    setFieldStatus(
      semanticStatus,
      validStructure,
      validStructure
        ? `Valid: semantic path (${parsed.length} segment${parsed.length === 1 ? "" : "s"})`
        : "Invalid: must be a non-empty JSON array where each segment has @type",
    );
    return validStructure ? parsed : null;
  } catch {
    setFieldStatus(semanticStatus, false, "Invalid: JSON parsing failed");
    return null;
  }
}

function setLoading(isLoading: boolean): void {
  deriveBtn.classList.toggle("loading", isLoading);
  deriveBtn.disabled = isLoading;
}

function showError(message: string): void {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function hideError(): void {
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
}

function renderResult(result: Record<string, unknown>, includePrivateKey: boolean): void {
  const visibleResult = includePrivateKey
    ? result
    : {
        age_public_key: result.age_public_key,
        derivationPath: result.derivationPath,
        semanticPath: result.semanticPath,
      };
  output.textContent = JSON.stringify(visibleResult, null, 2);
  derivationPathCode.textContent = String(result.derivationPath);
  publicKeyCode.textContent = String(result.age_public_key);
  privateKeyCode.textContent = String(result.age_private_key);
  privateKeySection.classList.toggle("hidden", !includePrivateKey);
  resultContainer.classList.remove("hidden");
}

function copyToClipboard(text: string, button: HTMLElement): void {
  if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
    showError("Clipboard write support is unavailable in this browser context.");
    return;
  }
  navigator.clipboard
    .writeText(text)
    .then(() => {
      const originalText = button.textContent;
      button.textContent = "Copied!";
      copyStatus.textContent = `${originalText} copied to clipboard.`;
      setTimeout(() => {
        button.textContent = originalText;
      }, 2000);
    })
    .catch(() => {
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
  const target = event.target as HTMLElement;
  const button = target.closest(".copy-btn") as HTMLElement | null;
  if (!button) return;
  const copyTargetId = button.dataset.copyTarget;
  const copyTarget = copyTargetId ? document.getElementById(copyTargetId) : null;
  if (!copyTarget) return;
  copyToClipboard(copyTarget.textContent ?? "", button);
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
    showError(`Error: ${(error as Error).message}`);
  } finally {
    setLoading(false);
  }
});
