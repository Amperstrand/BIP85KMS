import { deriveFromMnemonic } from "../src/core.js";

const form = document.getElementById("derive-form");
const output = document.getElementById("output");

form.addEventListener("submit", (event) => {
  event.preventDefault();

  try {
    const mnemonic = document.getElementById("mnemonic").value.trim();
    const filename = document.getElementById("filename").value.trim();
    const keyVersion = Number(document.getElementById("keyVersion").value);
    const appId = document.getElementById("appId").value.trim();
    const getPrivateKey = document.getElementById("getPrivateKey").checked;

    const result = deriveFromMnemonic(mnemonic, keyVersion, appId, filename);
    output.textContent = JSON.stringify(
      getPrivateKey
        ? result
        : {
            age_public_key: result.age_public_key,
            iv: result.iv,
          },
      null,
      2
    );
  } catch (error) {
    output.textContent = `Error: ${error.message}`;
  }
});
