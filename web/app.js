import { deriveFromSemanticPath, deriveMasterNodeFromMnemonic } from "../src/core.js";

const form = document.getElementById("derive-form");
const output = document.getElementById("output");
const exampleBtn = document.getElementById("example-btn");
const semanticPathTextarea = document.getElementById("semanticPath");

// Load example semantic path
exampleBtn.addEventListener("click", () => {
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
  semanticPathTextarea.value = JSON.stringify(examplePath, null, 2);
});

// Form submission
form.addEventListener("submit", (event) => {
  event.preventDefault();

  try {
    const mnemonic = document.getElementById("mnemonic").value.trim();
    const getPrivateKey = document.getElementById("getPrivateKey").checked;
    const semanticPathText = semanticPathTextarea.value.trim();
    
    if (!semanticPathText) {
      throw new Error("Please enter a semantic path");
    }
    
    // Parse semantic path
    let semanticPath;
    try {
      semanticPath = JSON.parse(semanticPathText);
    } catch (e) {
      throw new Error("Invalid JSON: " + e.message);
    }
    
    if (!Array.isArray(semanticPath)) {
      throw new Error("Semantic path must be a JSON array");
    }
    
    if (semanticPath.length === 0) {
      throw new Error("Semantic path must contain at least one segment");
    }
    
    // Derive keys
    const masterNode = deriveMasterNodeFromMnemonic(mnemonic);
    const result = deriveFromSemanticPath(masterNode, semanticPath);
    
    // Display result
    output.textContent = JSON.stringify(
      getPrivateKey
        ? result
        : {
            age_public_key: result.age_public_key,
            derivationPath: result.derivationPath,
            semanticPath: result.semanticPath,
          },
      null,
      2
    );
  } catch (error) {
    output.textContent = `Error: ${error.message}`;
    output.style.color = "#d73a49";
    return;
  }
  
  output.style.color = "";
});

