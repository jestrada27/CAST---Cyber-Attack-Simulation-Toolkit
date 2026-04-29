//This is where we store all the attack configs.
const attackconfigs = [];
const DEBUGCHOICES = document.getElementById("DEBUGCHOICES");
const DEBUGBUTTON = document.getElementById("DEBUGBUTTON");
const DEBUGCONTAINER = document.getElementById("DEBUGCONTAINER");


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
  });

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

    <select class="input" name="module_id" required>
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