"use strict";

(() => {
  const STATES = Object.freeze({
    BOOTSTRAP_LOADING:"BOOTSTRAP_LOADING", COMPOSE:"COMPOSE", AUTHORING:"AUTHORING",
    CONTRACT_READY:"CONTRACT_READY", PREPARATION_QUEUED:"PREPARATION_QUEUED",
    PREPARATION_RUNNING:"PREPARATION_RUNNING", PREPARATION_READY:"PREPARATION_READY",
    PREPARATION_BLOCKED:"PREPARATION_BLOCKED", PREPARATION_FAILED:"PREPARATION_FAILED",
    LAUNCHING:"LAUNCHING", LAUNCH_ACCEPTED:"LAUNCH_ACCEPTED", REQUEST_ERROR:"REQUEST_ERROR"
  });
  const allowed = Object.freeze({
    BOOTSTRAP_LOADING:["COMPOSE","REQUEST_ERROR"],
    COMPOSE:["AUTHORING","REQUEST_ERROR"], AUTHORING:["CONTRACT_READY","REQUEST_ERROR","COMPOSE"],
    CONTRACT_READY:["PREPARATION_QUEUED","REQUEST_ERROR","COMPOSE"],
    PREPARATION_QUEUED:["PREPARATION_RUNNING","PREPARATION_READY","PREPARATION_BLOCKED","PREPARATION_FAILED","REQUEST_ERROR","COMPOSE"],
    PREPARATION_RUNNING:["PREPARATION_RUNNING","PREPARATION_READY","PREPARATION_BLOCKED","PREPARATION_FAILED","REQUEST_ERROR","COMPOSE"],
    PREPARATION_READY:["LAUNCHING","REQUEST_ERROR","COMPOSE"],
    PREPARATION_BLOCKED:["PREPARATION_QUEUED","COMPOSE"], PREPARATION_FAILED:["PREPARATION_QUEUED","COMPOSE"],
    LAUNCHING:["LAUNCH_ACCEPTED","PREPARATION_READY","REQUEST_ERROR"], LAUNCH_ACCEPTED:["COMPOSE"],
    REQUEST_ERROR:["BOOTSTRAP_LOADING","COMPOSE","CONTRACT_READY","PREPARATION_READY"]
  });
  const ui = {
    state:STATES.BOOTSTRAP_LOADING, bootstrap:null, contract:null, preparation:null,
    pollController:null, pollTimer:null, pollCount:0, resumeState:null, prepareInFlight:false, flowEpoch:0
  };
  const byId = id => document.getElementById(id);
  const views = ["loading","compose","contract","preparation","authorize","accepted"];
  const csrf = document.querySelector('meta[name="admissible-ui-csrf"]').content;

  function announce(message){ byId("live-status").textContent=message; }
  function stepFor(state){
    if([STATES.COMPOSE,STATES.AUTHORING,STATES.BOOTSTRAP_LOADING].includes(state))return "compose";
    if([STATES.CONTRACT_READY,STATES.PREPARATION_QUEUED,STATES.PREPARATION_RUNNING,STATES.PREPARATION_BLOCKED,STATES.PREPARATION_FAILED].includes(state))return "contract";
    return "authorize";
  }
  function setState(next){
    if(next!==ui.state && !(allowed[ui.state]||[]).includes(next))throw new Error("INVALID_STATE_TRANSITION");
    ui.state=next;
    document.body.dataset.state=next;
    document.querySelectorAll(".steps li").forEach(item=>{
      if(item.dataset.step===stepFor(next))item.setAttribute("aria-current","step");else item.removeAttribute("aria-current");
    });
    views.forEach(name=>{byId(name+"-view").hidden=true;});
    const target = next===STATES.BOOTSTRAP_LOADING?"loading":next===STATES.COMPOSE||next===STATES.AUTHORING?"compose":next===STATES.CONTRACT_READY?"contract":next===STATES.PREPARATION_READY||next===STATES.LAUNCHING?"authorize":next===STATES.LAUNCH_ACCEPTED?"accepted":"preparation";
    byId(target+"-view").hidden=false;
    byId("author-button").disabled=next===STATES.AUTHORING;
    byId("author-button").textContent=next===STATES.AUTHORING?"Authoring contract…":"Author canonical contract";
    byId("launch-button").disabled=next===STATES.LAUNCHING;
    byId("launch-button").textContent=next===STATES.LAUNCHING?"Submitting authorization":"Launch mission";
    const preparing=next===STATES.PREPARATION_QUEUED||next===STATES.PREPARATION_RUNNING||ui.prepareInFlight;
    byId("prepare-button").disabled=preparing;
    byId("retry-preparation").disabled=preparing;
    document.querySelectorAll(".reset-flow").forEach(button=>{
      const locked=next===STATES.LAUNCHING;
      button.disabled=locked;
      if(locked)button.setAttribute("aria-disabled","true");else button.removeAttribute("aria-disabled");
    });
    announce(next.replaceAll("_"," ").toLowerCase());
  }
  function showError(code,message,resume){
    ui.resumeState=resume||ui.state; byId("status-message").textContent=message;
    byId("status-code").textContent=code||"REQUEST_ERROR"; byId("status-area").hidden=false;
  }
  function clearError(){byId("status-area").hidden=true;byId("status-message").textContent="";byId("status-code").textContent="";byId("retry-bootstrap").hidden=true;}
  function boundedMessage(status,body){
    if(!Number.isInteger(status))return {code:"LAUNCHER_UNAVAILABLE",message:"The local launcher is unavailable. Check that it is still running, then retry."};
    const code=body&&typeof body.error==="string"?body.error:"REQUEST_FAILED";
    const messages={AUTHORING_REJECTED:"The launcher rejected one or more contract fields.",PREFLIGHT_BUSY:"Another canonical preflight is already active.",PREPARATION_NOT_READY:"This preparation is not ready for authorization.",PREPARATION_IN_USE:"This preparation is already being authorized.",PREPARATION_CONSUMED:"This authorization preparation has already been used.",OWNER_AUTHORIZATION_REQUIRED:"Enter the owner authorization phrase.",OWNER_AUTHORIZATION_INVALID:"The owner authorization phrase was rejected.",OWNER_AUTHORIZATION_ENCODING_UNSUPPORTED:"The phrase cannot be transported with the required Latin-1 encoding.",OWNER_AUTHORIZATION_DIGEST_INVALID:"Enter the owner-supplied lowercase 64-hex digest.",RUN_CONFLICT:"The launcher reported a launch conflict.",LAUNCHER_CLOSED:"The local launcher is unavailable.",WRITE_UNAVAILABLE:"The launcher could not complete this request.",READ_UNAVAILABLE:"The launcher could not read preparation status."};
    return {code,message:messages[code]||(`The launcher returned a bounded ${status} response.`)};
  }
  async function api(path,options={}){
    if(!path.startsWith("/ui/api/v1/"))throw new Error("NON_UI_ROUTE_BLOCKED");
    const headers={Accept:"application/json",...(options.headers||{})};
    if(options.method&&options.method!=="GET"){headers["Content-Type"]="application/json";headers["X-Admissible-UI-CSRF"]=csrf;}
    const response=await fetch(path,{...options,headers,credentials:"omit",cache:"no-store",referrerPolicy:"no-referrer"});
    let body={};try{body=await response.json();}catch(_error){body={error:"INVALID_RESPONSE"};}
    if(!response.ok){const err=new Error("BOUNDED_API_ERROR");err.status=response.status;err.body=body;throw err;}
    return {status:response.status,body};
  }
  function appendFact(root,label,value){
    const row=document.createElement("div"),dt=document.createElement("dt"),dd=document.createElement("dd");
    dt.textContent=label;dd.textContent=value===null||value===undefined?"Not returned":String(value);row.append(dt,dd);root.append(row);
  }
  function renderBootstrap(boot){
    const root=byId("bootstrap-facts");root.replaceChildren();
    [["Service",boot.service],["Repository",boot.repository_display_path],["Required source HEAD",boot.required_source_head],["Authorization mode",boot.authorization_mode],["Owner phrase encoding",boot.owner_authorization_encoding],["Visual UI wire value",String(boot.visual_ui_available)],["Local state",boot.g2_ready?"Ready":"Unavailable"]].forEach(x=>appendFact(root,x[0],x[1]));
    const select=byId("template-id");select.replaceChildren();(boot.supported_authoring_template_ids||[]).forEach(id=>{const option=document.createElement("option");option.value=id;option.textContent=id;select.append(option);});
  }
  async function bootstrap(){
    clearError();setState(STATES.BOOTSTRAP_LOADING);
    try{const {body}=await api("/ui/api/v1/bootstrap");ui.bootstrap=body;renderBootstrap(body);setState(STATES.COMPOSE);}
    catch(error){setState(STATES.REQUEST_ERROR);const mapped=boundedMessage(error.status,error.body);showError(mapped.code,"The local launcher bootstrap is unavailable.",STATES.BOOTSTRAP_LOADING);byId("retry-bootstrap").hidden=false;}
  }
  function addMaterial(value=""){
    if(byId("material-list").children.length>=64)return;
    const row=document.createElement("div");row.className="material-row";
    const input=document.createElement("input");input.type="text";input.value=value;input.maxLength=4096;input.setAttribute("aria-label","Required material path");
    const remove=document.createElement("button");remove.type="button";remove.className="button quiet";remove.textContent="Remove";remove.addEventListener("click",()=>row.remove());row.append(input,remove);byId("material-list").append(row);
  }
  function validateCompose(){
    let valid=true;[["mission-text","mission-error","Enter the mission."],["gate-objective","objective-error","Enter the gate objective."],["completion-conditions","conditions-error","Enter completion conditions."],["commit-message","commit-error","Enter the intended commit message."]].forEach(([field,error,message])=>{const empty=!byId(field).value.trim();byId(error).textContent=empty?message:"";byId(field).setAttribute("aria-invalid",String(empty));if(empty)valid=false;});
    if(/[\r\n]/.test(byId("commit-message").value)){byId("commit-error").textContent="Use one commit-message line.";valid=false;}return valid;
  }
  function composeBody(){return {mission_text:byId("mission-text").value,gate_objective:byId("gate-objective").value,completion_conditions_text:byId("completion-conditions").value,required_material_paths:Array.from(byId("material-list").querySelectorAll("input")).map(x=>x.value).filter(Boolean),commit_message:byId("commit-message").value,model:byId("model").value,timeout_seconds:Number(byId("timeout-seconds").value),template_id:byId("template-id").value};}
  function renderContract(){
    const body=ui.contract.response,summary=body.contract_summary||{},ids=body.generated_ids||{},root=byId("contract-facts");root.replaceChildren();
    [["Contract ID",body.contract_id],["Canonical fingerprint",body.profile_fingerprint],["Profile ID",ids.profile_id||summary.profile_id],["Run ID",ids.run_id||summary.run_id],["Session ID",ids.session_id||summary.session_id],["Gate ID",ids.gate_id||summary.gate_id],["Mission ID",ids.mission_id||summary.mission_id],["Workspace source kind",summary.workspace_source_kind],["Verification mode",summary.verification_mode],["Authorization mode",body.authorization_mode],["Execution started",String(body.execution_started)]].forEach(x=>appendFact(root,x[0],x[1]));
    const intent=byId("intent-facts");intent.replaceChildren();[["Mission",ui.contract.input.mission_text],["Gate objective",ui.contract.input.gate_objective],["Completion conditions",ui.contract.input.completion_conditions_text],["Required materials",ui.contract.input.required_material_paths.join(", ")||"None"],["Intended commit",ui.contract.input.commit_message]].forEach(x=>appendFact(intent,x[0],x[1]));
  }
  async function author(event){
    event.preventDefault();clearError();if(!validateCompose())return;const input=composeBody();setState(STATES.AUTHORING);
    try{const {body}=await api("/ui/api/v1/contracts",{method:"POST",body:JSON.stringify(input)});ui.contract={input,response:body};renderContract();setState(STATES.CONTRACT_READY);}
    catch(error){const mapped=boundedMessage(error.status,error.body);setState(STATES.REQUEST_ERROR);showError(mapped.code,mapped.message,STATES.COMPOSE);setState(STATES.COMPOSE);}
  }
  function stopPolling(){if(ui.pollTimer!==null){clearTimeout(ui.pollTimer);ui.pollTimer=null;}if(ui.pollController){ui.pollController.abort();ui.pollController=null;}ui.pollCount=0;}
  function preparationCopy(state,body){
    const copy=byId("preparation-copy"),retry=byId("retry-preparation");retry.hidden=true;
    if(state===STATES.PREPARATION_QUEUED)copy.textContent="Canonical preflight is queued. Execution has not started.";
    else if(state===STATES.PREPARATION_RUNNING)copy.textContent="Canonical preflight is running. Execution has not started.";
    else if(state===STATES.PREPARATION_BLOCKED){copy.textContent=`Preflight is blocked. Execution has not started. ${JSON.stringify(body.blocked_summary||{})}`;}
    else{copy.textContent=`Preflight failed within the launcher boundary. Execution has not started. ${body.error_type||"PREFLIGHT_FAILED"}`;retry.hidden=false;}
  }
  async function prepare(){
    if(ui.prepareInFlight||ui.state===STATES.PREPARATION_QUEUED||ui.state===STATES.PREPARATION_RUNNING)return;
    ui.prepareInFlight=true;byId("prepare-button").disabled=true;byId("retry-preparation").disabled=true;
    clearError();stopPolling();
    const epoch=ui.flowEpoch;
    try{
      const cid=ui.contract.response.contract_id,{body}=await api(`/ui/api/v1/contracts/${encodeURIComponent(cid)}/preparations`,{method:"POST",body:"{}"});
      if(epoch!==ui.flowEpoch)return;
      ui.preparation={id:body.preparation_id,status:body};setState(STATES.PREPARATION_QUEUED);preparationCopy(ui.state,body);pollPreparation();
    }catch(error){
      if(epoch!==ui.flowEpoch||error.name==="AbortError")return;
      const mapped=boundedMessage(error.status,error.body);setState(STATES.REQUEST_ERROR);showError(mapped.code,mapped.message,STATES.CONTRACT_READY);setState(STATES.CONTRACT_READY);
    }finally{
      if(epoch===ui.flowEpoch){ui.prepareInFlight=false;const preparing=ui.state===STATES.PREPARATION_QUEUED||ui.state===STATES.PREPARATION_RUNNING;byId("prepare-button").disabled=preparing;byId("retry-preparation").disabled=preparing;}
      else ui.prepareInFlight=false;
    }
  }
  function renderPreparation(body){
    const root=byId("preparation-facts");root.replaceChildren();[["Preparation ID",body.preparation_id],["Payload fingerprint",body.payload_fingerprint],["Authorization mode",body.authorization_mode]].forEach(x=>appendFact(root,x[0],x[1]));
    byId("canonical-payload").textContent=JSON.stringify(body.authorization_payload,null,2);byId("safe-summary").textContent=JSON.stringify(body.safe_payload_summary,null,2);
    byId("mode-label").textContent=body.authorization_mode;byId("authorization-notice").textContent=body.authorization_semantics_notice;byId("encoding-notice").textContent=`Owner phrase transport is limited to ${ui.bootstrap.owner_authorization_encoding}.`;
    const slot=byId("digest-slot");slot.replaceChildren();
    if(body.authorization_mode==="PRECOMMITTED_DIGEST"){
      const wrap=document.createElement("div");wrap.className="field";const label=document.createElement("label");label.htmlFor="owner-digest";label.textContent="Owner-supplied authorization digest";
      const input=document.createElement("input");input.id="owner-digest";input.type="password";input.autocomplete="off";input.required=true;input.pattern="[0-9a-f]{64}";input.setAttribute("aria-describedby","digest-help digest-error");
      const help=document.createElement("p");help.id="digest-help";help.className="hint";help.textContent="Lowercase 64-hex. The launcher forwards this digest unchanged.";const error=document.createElement("p");error.id="digest-error";error.className="field-error";wrap.append(label,input,help,error);slot.append(wrap);
    }
  }
  async function pollPreparation(){
    if(ui.pollController||ui.state===STATES.LAUNCH_ACCEPTED)return;ui.pollController=new AbortController();ui.pollCount=0;
    const epoch=ui.flowEpoch;const controller=ui.pollController;
    const tick=async()=>{
      if(epoch!==ui.flowEpoch||!ui.pollController||ui.pollController!==controller||controller.signal.aborted||ui.pollCount>=120)return;ui.pollCount+=1;
      try{const {body}=await api(`/ui/api/v1/preparations/${encodeURIComponent(ui.preparation.id)}`,{signal:controller.signal});
        if(epoch!==ui.flowEpoch||ui.pollController!==controller)return;
        ui.preparation.status=body;
        if(body.state==="QUEUED"||body.state==="RUNNING"){setState(body.state==="QUEUED"?STATES.PREPARATION_QUEUED:STATES.PREPARATION_RUNNING);preparationCopy(ui.state,body);ui.pollTimer=setTimeout(tick,750);return;}
        stopPolling();if(body.state==="READY"){renderPreparation(body);setState(STATES.PREPARATION_READY);}else if(body.state==="BLOCKED"){setState(STATES.PREPARATION_BLOCKED);preparationCopy(ui.state,body);}else{setState(STATES.PREPARATION_FAILED);preparationCopy(ui.state,body);}
      }catch(error){if(error.name==="AbortError"||epoch!==ui.flowEpoch)return;stopPolling();const mapped=boundedMessage(error.status,error.body);setState(STATES.REQUEST_ERROR);showError(mapped.code,mapped.message,STATES.CONTRACT_READY);}
    };tick();
  }
  function clearSecrets(){const phrase=byId("owner-phrase"),digest=byId("owner-digest");phrase.value="";phrase.type="password";byId("toggle-phrase").textContent="Show";byId("toggle-phrase").setAttribute("aria-pressed","false");if(digest)digest.value="";}
  function validateAuthorization(){
    const phrase=byId("owner-phrase"),phraseError=byId("owner-phrase-error");phraseError.textContent="";
    if(!phrase.value){phraseError.textContent="Enter the owner authorization phrase.";return false;}if(phrase.value.length>4096){phraseError.textContent="The phrase exceeds the 4096-byte transport bound.";return false;}
    for(const ch of phrase.value){if(ch.codePointAt(0)>255){phraseError.textContent="Use only characters encodable as Latin-1.";return false;}}
    const digest=byId("owner-digest");if(digest&&!/^[0-9a-f]{64}$/.test(digest.value)){byId("digest-error").textContent="Enter exactly 64 lowercase hexadecimal characters.";return false;}return true;
  }
  function renderAccepted(body){const root=byId("accepted-facts");root.replaceChildren();appendFact(root,"Control-run ID",body.control_run_id);appendFact(root,"Initial control state",body.control_state);}
  async function launch(event){
    event.preventDefault();clearError();if(!validateAuthorization())return;setState(STATES.LAUNCHING);
    const headers={"X-Admissible-Owner-Authorization":byId("owner-phrase").value};const digest=byId("owner-digest");if(digest)headers["X-Admissible-Owner-Authorization-Digest"]=digest.value;
    try{const {status,body}=await api("/ui/api/v1/runs",{method:"POST",headers,body:JSON.stringify({contract_id:ui.contract.response.contract_id,preparation_id:ui.preparation.id})});if(status!==202){const err=new Error("LAUNCH_NOT_ACCEPTED");err.status=status;err.body=body;throw err;}stopPolling();renderAccepted(body);setState(STATES.LAUNCH_ACCEPTED);}
    catch(error){const mapped=boundedMessage(error.status,error.body);setState(STATES.PREPARATION_READY);showError(mapped.code,mapped.message,STATES.PREPARATION_READY);}
    finally{headers["X-Admissible-Owner-Authorization"]="";if(headers["X-Admissible-Owner-Authorization-Digest"])headers["X-Admissible-Owner-Authorization-Digest"]="";clearSecrets();}
  }
  function reset(){
    if(ui.state===STATES.LAUNCHING)return;
    ui.flowEpoch+=1;stopPolling();clearSecrets();clearError();ui.contract=null;ui.preparation=null;ui.prepareInFlight=false;
    if(ui.state!==STATES.COMPOSE)setState(STATES.COMPOSE);byId("mission-text").focus();
  }
  function snapshot(){
    const digest=byId("owner-digest");
    return {
      state:ui.state,
      contractId:ui.contract&&ui.contract.response?ui.contract.response.contract_id:null,
      preparationId:ui.preparation?ui.preparation.id:null,
      preparationState:ui.preparation&&ui.preparation.status?ui.preparation.status.state:null,
      pollCount:ui.pollCount,
      hasPollController:!!ui.pollController,
      hasPollTimer:ui.pollTimer!==null,
      prepareInFlight:ui.prepareInFlight,
      phraseValue:byId("owner-phrase").value,
      phraseType:byId("owner-phrase").type,
      digestValue:digest?digest.value:"",
      statusMessage:byId("status-message").textContent,
      statusCode:byId("status-code").textContent,
      prepareDisabled:byId("prepare-button").disabled,
      launchDisabled:byId("launch-button").disabled,
      resetDisabled:Array.from(document.querySelectorAll(".reset-flow")).map(button=>button.disabled),
      acceptedText:byId("accepted-facts").textContent,
      preparationCopy:byId("preparation-copy").textContent,
      canonicalPayload:byId("canonical-payload").textContent,
      intentFacts:byId("intent-facts").textContent,
      contractFacts:byId("contract-facts").textContent
    };
  }

  byId("compose-form").addEventListener("submit",author);byId("authorize-form").addEventListener("submit",launch);byId("prepare-button").addEventListener("click",prepare);byId("retry-preparation").addEventListener("click",prepare);byId("back-to-compose").addEventListener("click",reset);document.querySelectorAll(".reset-flow").forEach(button=>button.addEventListener("click",reset));byId("add-material").addEventListener("click",()=>addMaterial());byId("retry-bootstrap").addEventListener("click",bootstrap);byId("toggle-phrase").addEventListener("click",()=>{const input=byId("owner-phrase"),show=input.type==="password";input.type=show?"text":"password";byId("toggle-phrase").textContent=show?"Hide":"Show";byId("toggle-phrase").setAttribute("aria-pressed",String(show));});window.addEventListener("pagehide",stopPolling,{once:true});window.addEventListener("beforeunload",stopPolling,{once:true});
  addMaterial("README.md");
  Object.defineProperty(window,"AdmissibleG3Test",{value:Object.freeze({
    STATES,allowedTransitions:allowed,getState:()=>ui.state,reset,prepare,launch,bootstrap,author,stopPolling,snapshot,
    setField:(id,value)=>{byId(id).value=value;},
    click:(id)=>{byId(id).click();},
    submit:(id)=>{const form=byId(id);form.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}));}
  }),writable:false});
  bootstrap();
})();
