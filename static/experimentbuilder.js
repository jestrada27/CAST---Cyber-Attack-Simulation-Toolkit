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


function updateConfigUI(){
  switch (moduleSelect.value){
            case "sqli":
                DEBUGCONTAINER.replaceChildren(GenSQLConfig());
                break;
            case "brute force":
                DEBUGCONTAINER.replaceChildren(GenBruteForceConfig());
                break;
            case "dns":
                DEBUGCONTAINER.replaceChildren(GenDNSConfig());
                break;
            case "xss":
                DEBUGCONTAINER.replaceChildren(GenXSSConfig());
                break;
            case "replay":
                DEBUGCONTAINER.replaceChildren(GenReplayConfig());
                break;
            default:
              const div = document.createElement("div");
                div.textContent = "Select a module first";
                DEBUGCONTAINER.replaceChildren(div)
                break;
  }
}


if (moduleSelect) {
  moduleSelect.addEventListener("change", toggleModuleFields);
  moduleSelect.addEventListener("change", updateConfigUI);
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

const DEBUGCONTAINER = document.getElementById("config-div");
const configDetails = document.getElementById("config-details")
configDetails.addEventListener("toggle", (event) => {
  if (configDetails.open) {
    /* the element was toggled open */
    console.log("TESTIGN")
  } else {
    /* the element was toggled closed */
    console.log("TESTIGN")
  }
});
/*
DEBUGBUTTON.addEventListener("click", () => {
    switch (DEBUGCHOICES.value){
            case "SQL":
                DEBUGCONTAINER.appendChild(GenSQLConfig());
                break;
            case "BruteForce":
                DEBUGCONTAINER.appendChild(GenBruteForceConfig());
                break;
            case "DNS":
                DEBUGCONTAINER.appendChild(GenDNSConfig());
                break;
            case "XSS":
                DEBUGCONTAINER.appendChild(GenXSSConfig());
                break;
            case "Replay":
                DEBUGCONTAINER.appendChild(GenReplayConfig());
                break;
            default:
                console.log("Error, attack has no config generator")
                break;
        }
  });*/

//Maybe dont run here, instead save. Same idea though.
function RunAllAttacks(){
    for(config in attackconfigs){
        switch (config.attackType){
            case "SQL":
                HandleSQLConfig(config);
                break;
            case "BruteForce":
                HandleBruteForce(config);
                break;
            case "DNS":
                HandleDNS(config);
                break;
            case "XSS":
                HandleXSS(config);
                break;
            default:
                break;
        }
    }
}


function GenSQLConfig() {
  const div = document.createElement("div");
  div.className = "config-row";

  div.innerHTML = `
    <input class="input" type="text" name="url" placeholder="URL">
    
    <label class="checkbox">
      <input type="checkbox" name="forms"> Forms
    </label>

    <input class="input" type="text" name="inputfields" placeholder="Data fields">

    <select class="input" name="module_id">
      <option value="">Method</option>
      <option value="POST">POST</option>
      <option value="GET">GET</option>
      <option value="PUT">PUT</option>
      <option value="DELETE">DELETE</option>
    </select>

    <input class="input" type="file" name="config">

    <button type="button" class="accept-btn">✔</button>

    <button type="button" class="remove-btn">✕</button>
  `;

  div.querySelector(".accept-btn").addEventListener("click", () =>{

  });
  div.querySelector(".remove-btn").addEventListener("click", () => {
    div.remove()
  });

  return div;
}

function GenDNSConfig() {
  const div = document.createElement("div");
  div.className = "config-row";

  div.innerHTML = `
    <input class="input" type="file" name="pcap">

    <input class="input small" type="number" name="minqueries" min="1" max="100" placeholder="Min queries">

    <input class="input small" type="number" name="threshold" min="1" max="100" placeholder="Threshold">

    <input class="input small" type="number" name="top" min="1" max="100" placeholder="Top N">

    <button type="button" class="accept-btn">✔</button>

    <button type="button" class="remove-btn">✕</button>
  `;

  div.querySelector(".accept-btn").addEventListener("click", () =>{

  });
  div.querySelector(".remove-btn").addEventListener("click", () => {
    div.remove()
  });

  return div;
}

function GenXSSConfig(){
    //TODO:
    const div = document.createElement("div");
    div.textContent = "No additional config needed for xss";
    return div;
}

function GenReplayConfig(){
    const div = document.createElement("div");
    div.className = "config-row";

    div.innerHTML = `
      <input class="input" type="text" name="url" placeholder="URL">

      <button type="button" class="accept-btn">✔</button>

      <button type="button" class="remove-btn">✕</button>
    `;

    div.querySelector(".accept-btn").addEventListener("click", () =>{

    });
    div.querySelector(".remove-btn").addEventListener("click", () => {
      div.remove()
    });

    return div;
}

function GenBruteForceConfig(){
        const div = document.createElement("div");
  div.className = "config-row";

  div.innerHTML = `
    <input class="input" type="file" name="pcap">

    <input class="input small" placeholder="Run ID (uuid4)">

    <input class="input small" type="number" name="concurrency" min="1" max="100" placeholder="Concurrency">

    <input class="input small" type="number" name="attemptsPerUser" min="1" max="20" placeholder="Attempts per user">

    <input class="input" type="text" name="url" placeholder="Target URL">

    <input class="input small" type="number" name="delay" min="0" max="5" placeholder="Delay (in seconds)">

    <label class="checkbox">
      <input type="checkbox" name="dryrun"> Dryrun
    </label>

    <button type="button" class="accept-btn">✔</button>

    <button type="button" class="remove-btn">✕</button>
  `;

  div.querySelector(".accept-btn").addEventListener("click", () =>{

  });
  div.querySelector(".remove-btn").addEventListener("click", () => {
    div.remove()
  });

  return div;
}

function HandleSQL(config){
    //TODO: extract the input
    const t = config.querySelector("input");
    console.log(t.value);
}

function HandleBruteForce(config){

}

function HandleXSS(config){
    
}

function HandleDNS(config){
    

}