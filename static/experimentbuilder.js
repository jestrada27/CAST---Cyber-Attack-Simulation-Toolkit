const moduleSelect = document.getElementById("moduleSelect");
const targetSelect = document.getElementById("targetSelect");
const builderForm = document.getElementById("experimentBuilderForm");
const loadingOverlay = document.getElementById("attackLoadingOverlay");
const targetPreview = document.getElementById("targetPreview");

const moduleFieldGroups = {
  "brute force": document.querySelectorAll(".bruteforce-only-field"),
  xss: document.querySelectorAll(".xss-only-field"),
  sqli: document.querySelectorAll(".sqli-only-field"),
  replay: document.querySelectorAll(".replay-only-field"),
  dns: document.querySelectorAll(".dns-only-field"),
};

function toggleModuleFields() {
  const selectedModule = moduleSelect ? moduleSelect.value : "";
  Object.entries(moduleFieldGroups).forEach(([moduleId, fields]) => {
    const showFields = selectedModule === moduleId;
    fields.forEach((field) => {
      field.hidden = !showFields;
    });
  });
}

function setText(id, label, value) {
  const node = document.getElementById(id);
  if (!node) {
    return;
  }
  node.textContent = value ? `${label}: ${value}` : "";
  node.hidden = !value;
}

function updateTargetPreview() {
  if (!targetSelect || !targetPreview) {
    return;
  }

  const selected = targetSelect.options[targetSelect.selectedIndex];
  if (!selected || !selected.value) {
    targetPreview.hidden = true;
    return;
  }

  setText("targetEndpoint", "endpoint", selected.dataset.endpoint);
  setText("targetEnvironment", "environment", selected.dataset.environment);
  setText("targetConsent", "consent", selected.dataset.consent);
  setText("targetServices", "services", selected.dataset.services);
  targetPreview.hidden = false;
}

if (moduleSelect) {
  moduleSelect.addEventListener("change", toggleModuleFields);
  toggleModuleFields();
}

if (targetSelect) {
  targetSelect.addEventListener("change", updateTargetPreview);
  updateTargetPreview();
}

if (builderForm && loadingOverlay) {
  builderForm.addEventListener("submit", () => {
    loadingOverlay.hidden = false;
    builderForm
      .querySelectorAll("button[type='submit']")
      .forEach((button) => {
        button.disabled = true;
      });
  });
}
