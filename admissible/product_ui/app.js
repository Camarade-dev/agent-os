"use strict";

(() => {
  const STATES = Object.freeze({
    BOOTSTRAP_LOADING:"BOOTSTRAP_LOADING", COMPOSE:"COMPOSE", AUTHORING:"AUTHORING",
    CONTRACT_READY:"CONTRACT_READY", PREPARATION_QUEUED:"PREPARATION_QUEUED",
    PREPARATION_RUNNING:"PREPARATION_RUNNING", PREPARATION_READY:"PREPARATION_READY",
    PREPARATION_BLOCKED:"PREPARATION_BLOCKED", PREPARATION_FAILED:"PREPARATION_FAILED",
    LAUNCHING:"LAUNCHING", LAUNCH_ACCEPTED:"LAUNCH_ACCEPTED", REQUEST_ERROR:"REQUEST_ERROR",
    RUN_ACCEPTED:"RUN_ACCEPTED", RUN_LOADING:"RUN_LOADING", RUN_QUEUED:"RUN_QUEUED",
    RUN_STARTING:"RUN_STARTING", RUN_RUNNING:"RUN_RUNNING",
    RUN_TERMINAL_LOADING_RESULT:"RUN_TERMINAL_LOADING_RESULT",
    RUN_RESULT_READY:"RUN_RESULT_READY", RUN_NO_AUTHORITATIVE_RESULT:"RUN_NO_AUTHORITATIVE_RESULT",
    RUN_START_FAILED:"RUN_START_FAILED", RUN_REQUEST_ERROR:"RUN_REQUEST_ERROR"
  });
  const allowed = Object.freeze({
    BOOTSTRAP_LOADING:["COMPOSE","REQUEST_ERROR"],
    COMPOSE:["AUTHORING","REQUEST_ERROR","PREPARATION_QUEUED"], AUTHORING:["CONTRACT_READY","REQUEST_ERROR","COMPOSE"],
    CONTRACT_READY:["PREPARATION_QUEUED","REQUEST_ERROR","COMPOSE"],
    PREPARATION_QUEUED:["PREPARATION_RUNNING","PREPARATION_READY","PREPARATION_BLOCKED","PREPARATION_FAILED","REQUEST_ERROR","COMPOSE"],
    PREPARATION_RUNNING:["PREPARATION_RUNNING","PREPARATION_READY","PREPARATION_BLOCKED","PREPARATION_FAILED","REQUEST_ERROR","COMPOSE"],
    PREPARATION_READY:["LAUNCHING","REQUEST_ERROR","COMPOSE"],
    PREPARATION_BLOCKED:["PREPARATION_QUEUED","COMPOSE"], PREPARATION_FAILED:["PREPARATION_QUEUED","COMPOSE"],
    LAUNCHING:["RUN_ACCEPTED","PREPARATION_READY","REQUEST_ERROR"],
    RUN_ACCEPTED:["RUN_LOADING","RUN_REQUEST_ERROR","COMPOSE"],
    RUN_LOADING:["RUN_QUEUED","RUN_STARTING","RUN_RUNNING","RUN_TERMINAL_LOADING_RESULT","RUN_START_FAILED","RUN_REQUEST_ERROR","COMPOSE"],
    RUN_QUEUED:["RUN_LOADING","RUN_QUEUED","RUN_STARTING","RUN_RUNNING","RUN_TERMINAL_LOADING_RESULT","RUN_START_FAILED","RUN_REQUEST_ERROR","COMPOSE"],
    RUN_STARTING:["RUN_LOADING","RUN_STARTING","RUN_RUNNING","RUN_TERMINAL_LOADING_RESULT","RUN_START_FAILED","RUN_REQUEST_ERROR","COMPOSE"],
    RUN_RUNNING:["RUN_LOADING","RUN_RUNNING","RUN_TERMINAL_LOADING_RESULT","RUN_START_FAILED","RUN_REQUEST_ERROR","COMPOSE"],
    RUN_TERMINAL_LOADING_RESULT:["RUN_TERMINAL_LOADING_RESULT","RUN_RESULT_READY","RUN_NO_AUTHORITATIVE_RESULT","RUN_REQUEST_ERROR","COMPOSE"],
    RUN_START_FAILED:["RUN_START_FAILED","RUN_RESULT_READY","RUN_NO_AUTHORITATIVE_RESULT","RUN_REQUEST_ERROR","COMPOSE"],
    RUN_RESULT_READY:["COMPOSE","PREPARATION_QUEUED"], RUN_NO_AUTHORITATIVE_RESULT:["COMPOSE"], RUN_REQUEST_ERROR:["COMPOSE"],
    LAUNCH_ACCEPTED:["COMPOSE"],
    REQUEST_ERROR:["BOOTSTRAP_LOADING","COMPOSE","CONTRACT_READY","PREPARATION_READY"]
  });
  const ui = {
    state:STATES.BOOTSTRAP_LOADING, bootstrap:null, contract:null, preparation:null, run:null, result:null,
    pollController:null, pollTimer:null, pollCount:0, statusAttempts:0, resultAttempts:0,
    requestInFlight:false, resultResolved:false, observationPhase:null,
    resumeState:null, prepareInFlight:false, flowEpoch:0,
    observationBudgetMs:0, observationDeadlineAt:null,
    recovery:null, recoveryInFlight:false
  };
  const POLL_INTERVAL_MS = 750;
  // Observation is bounded by a wall-clock deadline derived from the canonical
  // preparation authority, NOT by a poll count multiplied by the poll interval.
  // The interval is a request-rate choice; it must never decide how long an
  // authorized run may take.
  //
  // The ceiling below is a fixed client-side clamp that must cover the largest
  // run the launcher can authorize: its maximum native timeout, plus the
  // checkpoint commands, plus the behavioral verifier, plus a finalization
  // margin for evidence persistence and authoritative result assembly.
  const LAUNCHER_MAX_NATIVE_TIMEOUT_SECONDS = 3600;
  const MAX_CHECKPOINT_ALLOWANCE_SECONDS = 1800;   // protocol bound: 300 s per command
  const MAX_VERIFIER_TIMEOUT_SECONDS = 600;        // protocol bound on the frozen verifier
  const FINALIZATION_MARGIN_SECONDS = 300;
  const OBSERVATION_CEILING_MS = (
    LAUNCHER_MAX_NATIVE_TIMEOUT_SECONDS + MAX_CHECKPOINT_ALLOWANCE_SECONDS +
    MAX_VERIFIER_TIMEOUT_SECONDS + FINALIZATION_MARGIN_SECONDS
  ) * 1000;
  const MIN_OBSERVATION_MS = 60000;
  // Independent backstop. A wall clock that jumps backwards can defer the
  // deadline indefinitely, so observation is additionally bounded by attempt
  // count alone. Sized above the ceiling so it never truncates a run that the
  // deadline would still allow.
  const MAX_OBSERVATION_ATTEMPTS = Math.ceil(OBSERVATION_CEILING_MS / POLL_INTERVAL_MS) + 120;
  const MAX_FIRST_STATUS_DEFERRALS = 4;
  const MAX_RESULT_ATTEMPTS = 120;
  const FORBIDDEN_RESULT_FIELDS = new Set(["run_root","diagnostics"]);
  const byId = id => document.getElementById(id);
  const views = ["loading","compose","contract","preparation","authorize","accepted","result","no-result"];
  const csrf = document.querySelector('meta[name="admissible-ui-csrf"]').content;
  const hasOwn = (value,key) => !!value && Object.prototype.hasOwnProperty.call(value,key);
  const isObject = value => value!==null && typeof value==="object" && !Array.isArray(value);

  function announce(message){const live=byId("live-status");if(live)live.textContent=message;}
  function isRunState(state){return state.startsWith("RUN_");}
  function stepFor(state){
    if([STATES.COMPOSE,STATES.AUTHORING,STATES.BOOTSTRAP_LOADING].includes(state))return "compose";
    if([STATES.CONTRACT_READY,STATES.PREPARATION_QUEUED,STATES.PREPARATION_RUNNING,STATES.PREPARATION_BLOCKED,STATES.PREPARATION_FAILED].includes(state))return "contract";
    if([STATES.PREPARATION_READY,STATES.LAUNCHING].includes(state))return "authorize";
    if([STATES.RUN_RESULT_READY,STATES.RUN_NO_AUTHORITATIVE_RESULT].includes(state))return "result";
    return isRunState(state)?"run":"authorize";
  }
  function setState(next){
    if(next!==ui.state && !(allowed[ui.state]||[]).includes(next))throw new Error("INVALID_STATE_TRANSITION");
    ui.state=next;
    document.body.dataset.state=next;
    document.querySelectorAll(".steps li").forEach(item=>{
      if(item.dataset.step===stepFor(next))item.setAttribute("aria-current","step");else item.removeAttribute("aria-current");
    });
    views.forEach(name=>{const view=byId(name+"-view");if(view)view.hidden=true;});
    const target = next===STATES.BOOTSTRAP_LOADING?"loading":
      next===STATES.COMPOSE||next===STATES.AUTHORING?"compose":
      next===STATES.CONTRACT_READY?"contract":
      next===STATES.PREPARATION_READY||next===STATES.LAUNCHING?"authorize":
      next===STATES.RUN_RESULT_READY?"result":
      next===STATES.RUN_NO_AUTHORITATIVE_RESULT?"no-result":
      isRunState(next)?"accepted":"preparation";
    const targetView=byId(target+"-view");if(targetView)targetView.hidden=false;
    byId("author-button").disabled=next===STATES.AUTHORING;
    byId("author-button").textContent=next===STATES.AUTHORING?"Authoring contract...":"Author canonical contract";
    byId("launch-button").disabled=next===STATES.LAUNCHING;
    byId("launch-button").textContent=next===STATES.LAUNCHING?"Submitting authorization":"Launch mission";
    const preparing=next===STATES.PREPARATION_QUEUED||next===STATES.PREPARATION_RUNNING||ui.prepareInFlight;
    const v3=ui.contract&&ui.contract.response&&ui.contract.response.runtime_launchable===false;
    byId("prepare-button").disabled=preparing||v3;
    byId("retry-preparation").disabled=preparing;
    document.querySelectorAll(".reset-flow").forEach(button=>{
      const locked=next===STATES.LAUNCHING;
      button.disabled=locked;
      if(locked)button.setAttribute("aria-disabled","true");else button.removeAttribute("aria-disabled");
    });
    announce(next.replaceAll("_"," ").toLowerCase());
    if((next===STATES.RUN_RESULT_READY||next===STATES.RUN_NO_AUTHORITATIVE_RESULT) && targetView){
      const heading=targetView.querySelector("h2");if(heading){heading.focus();heading.scrollIntoView({block:"start"});}
    }
  }
  function isSafeBoundedIdentifier(value){
    return typeof value==="string" && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(value);
  }
  function boundedTechnicalCode(body,fallback){
    const primary=isSafeBoundedIdentifier(body&&body.error)?body.error:(isSafeBoundedIdentifier(fallback)?fallback:"REQUEST_ERROR");
    let line=primary;
    if(isSafeBoundedIdentifier(body&&body.error_code))line+=" / "+body.error_code;
    if(isSafeBoundedIdentifier(body&&body.field))line+=" ("+body.field+")";
    return line;
  }
  function showError(code,message,resume){
    ui.resumeState=resume||ui.state;byId("status-message").textContent=message;
    byId("status-code").textContent=code||"REQUEST_ERROR";byId("status-area").hidden=false;
  }
  function clearError(){byId("status-area").hidden=true;byId("status-message").textContent="";byId("status-code").textContent="";byId("retry-bootstrap").hidden=true;}
  function boundedMessage(status,body){
    if(!Number.isInteger(status))return {code:"LAUNCHER_UNAVAILABLE",message:"The local launcher is unavailable. Check that it is still running, then retry."};
    const errorToken=body&&typeof body.error==="string"?body.error:"REQUEST_FAILED";
    const messages={AUTHORING_REJECTED:"The launcher rejected one or more contract fields.",PREFLIGHT_BUSY:"Another canonical preflight is already active.",PREPARATION_NOT_READY:"This preparation is not ready for authorization.",PREPARATION_IN_USE:"This preparation is already being authorized.",PREPARATION_CONSUMED:"This authorization preparation has already been used.",OWNER_AUTHORIZATION_REQUIRED:"Enter the owner authorization phrase.",OWNER_AUTHORIZATION_INVALID:"The owner authorization phrase was rejected.",OWNER_AUTHORIZATION_ENCODING_UNSUPPORTED:"The phrase cannot be transported with the required Latin-1 encoding.",OWNER_AUTHORIZATION_DIGEST_INVALID:"Enter the owner-supplied lowercase 64-hex digest.",RUN_CONFLICT:"The launcher reported a launch conflict.",LAUNCHER_CLOSED:"The local launcher is unavailable.",WRITE_UNAVAILABLE:"The launcher could not complete this request.",READ_UNAVAILABLE:"The launcher could not read the accepted control run."};
    return {code:boundedTechnicalCode(body,errorToken),message:messages[errorToken]||(`The launcher returned a bounded ${status} response.`)};
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
  function appendReturnedFact(root,body,key,label){if(hasOwn(body,key))appendFact(root,label,body[key]);}
  const GATE_CLAUSE_NOTICE="These clauses are part of the authorized contract. They are not independently adjudicated unless linked to explicit verification evidence.";
  const CLAIM_NOTICE_KEYS=["authorship","coverage","adjudication","runtime"];
  const PLAN_NOTICE_KEYS=["authorship","coverage","non_execution","no_adjudication","independence","procedure_binding","runtime"];
  const BINDING_NOTICE_KEYS=["authorship","coverage","authority_relationship","no_evidence_existence","no_resolution_or_eligibility","no_obligation_or_claim_result","source_identity","procedure_reference_separation","human_rubric_limitation","runtime"];
  function normalizedGateClauses(value){
    if(!Array.isArray(value)||!value.length)return null;
    const seen=new Set(),clauses=[];
    for(const item of value){
      if(!isObject(item)||typeof item.clause_id!=="string"||!item.clause_id||seen.has(item.clause_id)||typeof item.text!=="string"||!item.text)return null;
      seen.add(item.clause_id);clauses.push({clause_id:item.clause_id,text:item.text});
    }
    return clauses;
  }
  function renderGateClauses(rootId,value,availability){
    const root=byId(rootId);if(!root)return;root.replaceChildren();
    const notice=document.createElement("p");notice.className="gate-clause-notice";notice.textContent=GATE_CLAUSE_NOTICE;root.append(notice);
    const clauses=normalizedGateClauses(value);
    if(!clauses){const absent=document.createElement("p");absent.className="gate-clause-unavailable";absent.textContent=availability==="INCONSISTENT"?"Authorized gate clause evidence is malformed or inconsistent.":"Authorized gate clauses are unavailable in the persisted evidence.";root.append(absent);return;}
    const list=document.createElement("ol");list.className="gate-clause-list";
    clauses.forEach(clause=>{const item=document.createElement("li"),id=document.createElement("span"),text=document.createElement("span");id.className="gate-clause-id";id.textContent=clause.clause_id;text.textContent=": "+clause.text;item.append(id,text);list.append(item);});root.append(list);
  }
  function normalizedClaimReview(authority,notices){
    if(!isObject(authority)||authority.authorship!=="OWNER_AUTHORED"||authority.coverage_status!=="NOT_ASSESSED"||!Array.isArray(authority.claims)||!authority.claims.length||!isObject(notices))return null;
    if(!CLAIM_NOTICE_KEYS.every(key=>typeof notices[key]==="string"&&notices[key]))return null;
    const seen=new Set(),claims=[];
    for(const claim of authority.claims){
      if(!isObject(claim)||Object.keys(claim).sort().join(",")!=="claim_id,depends_on,non_claims,obligation_level,statement"||typeof claim.claim_id!=="string"||!claim.claim_id||seen.has(claim.claim_id)||typeof claim.statement!=="string"||!claim.statement||!["MANDATORY","OPTIONAL","ADVISORY"].includes(claim.obligation_level)||!Array.isArray(claim.depends_on)||!claim.depends_on.every(x=>typeof x==="string")||!Array.isArray(claim.non_claims)||!claim.non_claims.every(x=>typeof x==="string"))return null;
      seen.add(claim.claim_id);claims.push(claim);
    }
    return {claims,notices};
  }
  function renderClaimReview(summary){
    const section=byId("contract-claims"),root=byId("contract-claim-review");if(!section||!root)return !hasOwn(summary,"claim_authority")&&!hasOwn(summary,"claim_review_notices");root.replaceChildren();
    if(!hasOwn(summary,"claim_authority")&&!hasOwn(summary,"claim_review_notices")){section.hidden=true;return true;}
    section.hidden=false;const review=normalizedClaimReview(summary.claim_authority,summary.claim_review_notices);
    if(!review){const failure=document.createElement("p");failure.className="claim-review-error";failure.textContent="Claim review data is malformed. No partial claim list is shown.";root.append(failure);return false;}
    CLAIM_NOTICE_KEYS.forEach(key=>{const notice=document.createElement("p");notice.className="claim-notice";notice.textContent=review.notices[key];root.append(notice);});
    const meta=document.createElement("dl");meta.className="detail-list";appendFact(meta,"Authorship",summary.claim_authority.authorship);appendFact(meta,"Coverage status",summary.claim_authority.coverage_status);root.append(meta);
    const list=document.createElement("ol");list.className="claim-list";review.claims.forEach(claim=>{const item=document.createElement("li"),title=document.createElement("p"),statement=document.createElement("p"),details=document.createElement("dl");title.className="claim-id";title.textContent=claim.claim_id;statement.className="claim-statement";statement.textContent=claim.statement;appendFact(details,"Obligation level",claim.obligation_level);appendFact(details,"Dependencies",claim.depends_on.join(", ")||"None");appendFact(details,"Non-claims",claim.non_claims.join("; ")||"None");item.append(title,statement,details);list.append(item);});root.append(list);return true;
  }
  function normalizedVerificationPlan(authority,notices){
    if(!isObject(authority)||authority.authorship!=="OWNER_AUTHORED"||authority.coverage_status!=="NOT_ASSESSED"||!Array.isArray(authority.verification_obligations)||!authority.verification_obligations.length||!isObject(notices))return null;
    if(!PLAN_NOTICE_KEYS.every(key=>typeof notices[key]==="string"&&notices[key]))return null;
    const obligations=[],seen=new Set(),exact="acceptance_predicate,claim_ids,declared_coverage,independence_requirements,negative_controls,non_claims,obligation_id,oracle_disclosed_to_subject,procedure_reference,reference_cases,strategy";
    for(const item of authority.verification_obligations){
      if(!isObject(item)||Object.keys(item).sort().join(",")!==exact||typeof item.obligation_id!=="string"||!item.obligation_id||seen.has(item.obligation_id)||!Array.isArray(item.claim_ids)||!item.claim_ids.length||!item.claim_ids.every(x=>typeof x==="string")||typeof item.strategy!=="string"||typeof item.procedure_reference!=="string"||typeof item.acceptance_predicate!=="string"||typeof item.declared_coverage!=="string"||!Array.isArray(item.non_claims)||!item.non_claims.every(x=>typeof x==="string")||typeof item.oracle_disclosed_to_subject!=="boolean"||!isObject(item.independence_requirements)||Object.keys(item.independence_requirements).sort().join(",")!=="artifact,information,model,organizational,process,temporal"||!Object.values(item.independence_requirements).every(x=>typeof x==="boolean")||!Array.isArray(item.negative_controls)||!item.negative_controls.every(x=>isObject(x)&&Object.keys(x).sort().join(",")==="control_id,description"&&typeof x.control_id==="string"&&typeof x.description==="string")||!Array.isArray(item.reference_cases)||!item.reference_cases.every(x=>typeof x==="string"))return null;
      seen.add(item.obligation_id);obligations.push(item);
    }
    return {obligations,notices};
  }
  function appendOrderedValues(root,label,values){
    const row=document.createElement("div"),dt=document.createElement("dt"),dd=document.createElement("dd"),list=document.createElement("ol");dt.textContent=label;
    if(values.length){values.forEach(value=>{const item=document.createElement("li");item.textContent=value;list.append(item);});dd.append(list);}else dd.textContent="None";
    row.append(dt,dd);root.append(row);
  }
  function renderVerificationPlanReview(summary){
    const section=byId("contract-verification-plan"),root=byId("contract-verification-plan-review");if(!section||!root)return !hasOwn(summary,"claim_verification_plan_authority")&&!hasOwn(summary,"verification_plan_review_notices");root.replaceChildren();
    if(!hasOwn(summary,"claim_verification_plan_authority")&&!hasOwn(summary,"verification_plan_review_notices")){section.hidden=true;return true;}
    section.hidden=false;const review=normalizedVerificationPlan(summary.claim_verification_plan_authority,summary.verification_plan_review_notices);
    if(!review){const failure=document.createElement("p");failure.className="plan-review-error";failure.textContent="Verification-plan review data is unavailable or inconsistent. No partial obligation list is shown.";root.append(failure);return false;}
    PLAN_NOTICE_KEYS.forEach(key=>{const notice=document.createElement("p");notice.className="plan-notice";notice.textContent=review.notices[key];root.append(notice);});
    const meta=document.createElement("dl");meta.className="detail-list";appendFact(meta,"Authorship",summary.claim_verification_plan_authority.authorship);appendFact(meta,"Coverage status",summary.claim_verification_plan_authority.coverage_status);root.append(meta);
    const list=document.createElement("ol");list.className="verification-obligation-list";review.obligations.forEach(obligation=>{const item=document.createElement("li"),title=document.createElement("p"),details=document.createElement("dl");title.className="obligation-id";title.textContent=obligation.obligation_id;appendOrderedValues(details,"Referenced claim IDs",obligation.claim_ids);appendFact(details,"Strategy",obligation.strategy);appendFact(details,"Procedure reference",obligation.procedure_reference);appendFact(details,"Acceptance predicate",obligation.acceptance_predicate);appendFact(details,"Declared coverage",obligation.declared_coverage);appendOrderedValues(details,"Non-claims",obligation.non_claims);appendFact(details,"Oracle disclosed to subject",String(obligation.oracle_disclosed_to_subject));Object.entries(obligation.independence_requirements).forEach(([key,value])=>appendFact(details,`Required independence: ${key}`,String(value)));appendOrderedValues(details,"Negative controls",obligation.negative_controls.map(control=>`${control.control_id}: ${control.description}`));appendOrderedValues(details,"Reference cases",obligation.reference_cases);item.append(title,details);list.append(item);});root.append(list);return true;
  }
  function normalizedEvidenceBindingReview(authority,notices){
    if(!isObject(authority)||authority.authorship!=="OWNER_AUTHORED"||authority.coverage_status!=="NOT_ASSESSED"||!Array.isArray(authority.bindings)||!authority.bindings.length||!isObject(notices))return null;
    if(!BINDING_NOTICE_KEYS.every(key=>typeof notices[key]==="string"&&notices[key]))return null;
    const bindings=[],bindingIds=new Set(),obligationIds=new Set(),exact="binding_id,obligation_id,source_authority_reference,source_authority_type";
    for(const binding of authority.bindings){
      if(!isObject(binding)||Object.keys(binding).sort().join(",")!==exact||typeof binding.binding_id!=="string"||!binding.binding_id||bindingIds.has(binding.binding_id)||typeof binding.obligation_id!=="string"||!binding.obligation_id||obligationIds.has(binding.obligation_id)||!["CHECKPOINT_COMMAND_AUTHORITY","FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY"].includes(binding.source_authority_type)||typeof binding.source_authority_reference!=="string"||!binding.source_authority_reference)return null;
      bindingIds.add(binding.binding_id);obligationIds.add(binding.obligation_id);bindings.push(binding);
    }
    return {bindings,notices};
  }
  function renderEvidenceBindingReview(summary){
    const section=byId("contract-evidence-bindings"),root=byId("contract-evidence-binding-review");if(!section||!root)return !hasOwn(summary,"verification_evidence_binding_authority")&&!hasOwn(summary,"verification_evidence_binding_review_notices");root.replaceChildren();
    const v5=summary.schema_version==="admissible_native_mission_profile_v5";
    if(!hasOwn(summary,"verification_evidence_binding_authority")&&!hasOwn(summary,"verification_evidence_binding_review_notices")&&!v5){section.hidden=true;return true;}
    section.hidden=false;const review=normalizedEvidenceBindingReview(summary.verification_evidence_binding_authority,summary.verification_evidence_binding_review_notices);
    if(!review){const failure=document.createElement("p");failure.className="binding-review-error";failure.textContent="Evidence-binding review data is unavailable or inconsistent. No partial binding list is shown.";root.append(failure);return false;}
    BINDING_NOTICE_KEYS.forEach(key=>{const notice=document.createElement("p");notice.className="binding-notice";notice.textContent=review.notices[key];root.append(notice);});
    const meta=document.createElement("dl");meta.className="detail-list";appendFact(meta,"Authorship",summary.verification_evidence_binding_authority.authorship);appendFact(meta,"Coverage status",summary.verification_evidence_binding_authority.coverage_status);root.append(meta);
    const list=document.createElement("ol");list.className="evidence-binding-list";review.bindings.forEach(binding=>{const item=document.createElement("li"),title=document.createElement("p"),details=document.createElement("dl");title.className="binding-id";title.textContent=binding.binding_id;appendFact(details,"Obligation ID",binding.obligation_id);appendFact(details,"Source authority type",binding.source_authority_type);appendFact(details,"Source authority reference",binding.source_authority_reference);item.append(title,details);list.append(item);});root.append(list);return true;
  }
  function renderBootstrap(boot){
    const root=byId("bootstrap-facts");root.replaceChildren();
    [["Service",boot.service],["Repository",boot.repository_display_path],["Required source HEAD",boot.required_source_head],["Authorization mode",boot.authorization_mode],["Owner phrase encoding",boot.owner_authorization_encoding],["Visual UI wire value",String(boot.visual_ui_available)],["Local state",boot.g2_ready?"Ready":"Unavailable"]].forEach(x=>appendFact(root,x[0],x[1]));
    const select=byId("template-id");select.replaceChildren();(boot.supported_authoring_template_ids||[]).forEach(id=>{const option=document.createElement("option");option.value=id;option.textContent=id;select.append(option);});
  }
  async function bootstrap(){
    clearError();setState(STATES.BOOTSTRAP_LOADING);
    try{const {body}=await api("/ui/api/v1/bootstrap");ui.bootstrap=body;renderBootstrap(body);setState(STATES.COMPOSE);await resumeRecovery();}
    catch(error){setState(STATES.REQUEST_ERROR);const mapped=boundedMessage(error.status,error.body);showError(mapped.code,"The local launcher bootstrap is unavailable.",STATES.BOOTSTRAP_LOADING);byId("retry-bootstrap").hidden=false;}
  }
  function addMaterial(value=""){
    if(byId("material-list").children.length>=64)return;
    const row=document.createElement("div");row.className="material-row";
    const input=document.createElement("input");input.type="text";input.value=value;input.maxLength=4096;input.setAttribute("aria-label","Required material path");
    const remove=document.createElement("button");remove.type="button";remove.className="button quiet";remove.textContent="Remove";remove.addEventListener("click",()=>row.remove());row.append(input,remove);byId("material-list").append(row);
  }
  function parsedClaims(){const field=byId("result-claims");if(!field)return undefined;const raw=field.value;if(!raw.trim())return undefined;try{return JSON.parse(raw);}catch(_error){return null;}}
  function parsedVerificationPlan(){const field=byId("claim-verification-plan");if(!field)return undefined;const raw=field.value;if(!raw.trim())return undefined;try{return JSON.parse(raw);}catch(_error){return null;}}
  function parsedEvidenceBindings(){const field=byId("verification-evidence-bindings");if(!field)return undefined;const raw=field.value;if(!raw.trim())return undefined;try{return JSON.parse(raw);}catch(_error){return null;}}
  function validateCompose(){
    let valid=true;[["mission-text","mission-error","Enter the mission."],["gate-objective","objective-error","Enter the gate objective."],["completion-conditions","conditions-error","Enter completion conditions."],["commit-message","commit-error","Enter the intended commit message."]].forEach(([field,error,message])=>{const empty=!byId(field).value.trim();byId(error).textContent=empty?message:"";byId(field).setAttribute("aria-invalid",String(empty));if(empty)valid=false;});
    if(/[\r\n]/.test(byId("commit-message").value)){byId("commit-error").textContent="Use one commit-message line.";valid=false;}const claims=parsedClaims(),claimsError=byId("claims-error");if(claimsError)claimsError.textContent=claims===null?"Enter valid JSON.":"";const plan=parsedVerificationPlan(),planError=byId("verification-plan-error");if(planError)planError.textContent=plan===null?"Enter valid JSON.":"";const bindings=parsedEvidenceBindings(),bindingsError=byId("evidence-bindings-error");if(bindingsError)bindingsError.textContent=bindings===null?"Enter valid JSON.":"";if(claims===null||plan===null||bindings===null)valid=false;return valid;
  }
  function composeBody(){const body={mission_text:byId("mission-text").value,gate_objective:byId("gate-objective").value,completion_conditions_text:byId("completion-conditions").value,required_material_paths:Array.from(byId("material-list").querySelectorAll("input")).map(x=>x.value).filter(Boolean),commit_message:byId("commit-message").value,model:byId("model").value,timeout_seconds:Number(byId("timeout-seconds").value),template_id:byId("template-id").value},claims=parsedClaims(),plan=parsedVerificationPlan(),bindings=parsedEvidenceBindings();if(claims!==undefined)body.result_claims=claims;if(plan!==undefined)body.claim_verification_plan=plan;if(bindings!==undefined)body.verification_evidence_bindings=bindings;return body;}
  function renderContract(){
    const body=ui.contract.response,summary=body.contract_summary||{},ids=body.generated_ids||{},root=byId("contract-facts");root.replaceChildren();
    [["Contract ID",body.contract_id],["Canonical fingerprint",body.profile_fingerprint],["Profile ID",ids.profile_id||summary.profile_id],["Run ID",ids.run_id||summary.run_id],["Session ID",ids.session_id||summary.session_id],["Gate ID",ids.gate_id||summary.gate_id],["Mission ID",ids.mission_id||summary.mission_id],["Workspace source kind",summary.workspace_source_kind],["Verification mode",summary.verification_mode],["Authorization mode",body.authorization_mode],["Execution started",String(body.execution_started)]].forEach(x=>appendFact(root,x[0],x[1]));
    const intent=byId("intent-facts");intent.replaceChildren();[["Mission",ui.contract.input.mission_text],["Gate objective",ui.contract.input.gate_objective],["Completion conditions",ui.contract.input.completion_conditions_text],["Required materials",ui.contract.input.required_material_paths.join(", ")||"None"],["Intended commit",ui.contract.input.commit_message]].forEach(x=>appendFact(intent,x[0],x[1]));
    renderGateClauses("contract-gate-clauses",summary.gate_clauses,"INCONSISTENT");
    const claimsValid=renderClaimReview(summary),planValid=renderVerificationPlanReview(summary),bindingsValid=renderEvidenceBindingReview(summary),launchable=body.runtime_launchable!==false;byId("prepare-button").hidden=!launchable;byId("prepare-button").disabled=!launchable||!claimsValid||!planValid||!bindingsValid;
  }
  async function author(event){
    event.preventDefault();clearError();if(!validateCompose())return;const input=composeBody();setState(STATES.AUTHORING);
    try{const {body}=await api("/ui/api/v1/contracts",{method:"POST",body:JSON.stringify(input)});ui.contract={input,response:body};renderContract();setState(STATES.CONTRACT_READY);}
    catch(error){const mapped=boundedMessage(error.status,error.body);setState(STATES.REQUEST_ERROR);showError(mapped.code,mapped.message,STATES.COMPOSE);setState(STATES.COMPOSE);}
  }
  function stopPolling(){
    if(ui.pollTimer!==null){clearTimeout(ui.pollTimer);ui.pollTimer=null;}
    if(ui.pollController){ui.pollController.abort();ui.pollController=null;}
    ui.pollCount=0;ui.requestInFlight=false;ui.observationPhase=null;ui.observationDeadlineAt=null;
  }
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
    clearError();stopPolling();const epoch=ui.flowEpoch;
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
    const stale=byId("recovery-authority");if(stale)stale.remove();
    const root=byId("preparation-facts");root.replaceChildren();[["Preparation ID",body.preparation_id],["Payload fingerprint",body.payload_fingerprint],["Authorization mode",body.authorization_mode]].forEach(x=>appendFact(root,x[0],x[1]));
    byId("canonical-payload").textContent=JSON.stringify(body.authorization_payload,null,2);byId("safe-summary").textContent=JSON.stringify(body.safe_payload_summary,null,2);
    byId("mode-label").textContent=body.authorization_mode;byId("authorization-notice").textContent=body.authorization_semantics_notice;byId("encoding-notice").textContent=`Owner phrase transport is limited to ${ui.bootstrap.owner_authorization_encoding}.`;
    const summary=ui.contract&&ui.contract.response&&isObject(ui.contract.response.contract_summary)?ui.contract.response.contract_summary:{};renderGateClauses("authorization-gate-clauses",summary.gate_clauses,"INCONSISTENT");
    const slot=byId("digest-slot");slot.replaceChildren();
    if(body.authorization_mode==="PRECOMMITTED_DIGEST"){
      const wrap=document.createElement("div");wrap.className="field";const label=document.createElement("label");label.htmlFor="owner-digest";label.textContent="Owner-supplied authorization digest";
      const input=document.createElement("input");input.id="owner-digest";input.type="password";input.autocomplete="off";input.required=true;input.pattern="[0-9a-f]{64}";input.setAttribute("aria-describedby","digest-help digest-error");
      const help=document.createElement("p");help.id="digest-help";help.className="hint";help.textContent="Lowercase 64-hex. The launcher forwards this digest unchanged.";const error=document.createElement("p");error.id="digest-error";error.className="field-error";wrap.append(label,input,help,error);slot.append(wrap);
    }
  }
  async function pollPreparation(){
    if(ui.pollController||ui.state===STATES.RUN_ACCEPTED)return;ui.pollController=new AbortController();ui.pollCount=0;
    const epoch=ui.flowEpoch;const controller=ui.pollController;
    const tick=async()=>{
      if(epoch!==ui.flowEpoch||!ui.pollController||ui.pollController!==controller||controller.signal.aborted||ui.pollCount>=120)return;ui.pollCount+=1;
      try{const {body}=await api(`/ui/api/v1/preparations/${encodeURIComponent(ui.preparation.id)}`,{signal:controller.signal});
        if(epoch!==ui.flowEpoch||ui.pollController!==controller)return;
        ui.preparation.status=body;
        if(body.state==="QUEUED"||body.state==="RUNNING"){setState(body.state==="QUEUED"?STATES.PREPARATION_QUEUED:STATES.PREPARATION_RUNNING);preparationCopy(ui.state,body);ui.pollTimer=setTimeout(tick,750);return;}
        stopPolling();if(body.state==="READY"){renderPreparation(body);if(ui.recovery)renderRecoveryAuthority(body);setState(STATES.PREPARATION_READY);}else if(body.state==="BLOCKED"){setState(STATES.PREPARATION_BLOCKED);preparationCopy(ui.state,body);}else{setState(STATES.PREPARATION_FAILED);preparationCopy(ui.state,body);}
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
  function controlRunPath(id){
    return `/ui/api/v1/runs/${encodeURIComponent(id)}`;
  }
  function authoritativeResultPath(id){
    return `${controlRunPath(id)}/result`;
  }
  function runCopy(state){
    const copies={
      RUN_ACCEPTED:["Accepted","The launcher accepted the request. Observation begins shortly; HTTP 202 is not a verified result."],
      RUN_LOADING:["Reading control state","Reading the authoritative control-plane state for this run."],
      RUN_QUEUED:["QUEUED","The process has not started."],
      RUN_STARTING:["STARTING","The control plane is starting the application."],
      RUN_RUNNING:["RUNNING","The application is running; completion is unknown."],
      RUN_TERMINAL_LOADING_RESULT:["TERMINAL","The application returned. This control state is not a success verdict. Retrieving the authoritative result."],
      RUN_START_FAILED:["START_FAILED","The invocation failed to start or complete its startup boundary. Retrieving any authoritative result that exists."],
      RUN_REQUEST_ERROR:["Observation stopped","The accepted run could not be observed within the bounded read lifecycle."]
    };
    return copies[state]||[state,"No product verdict exists yet."];
  }
  function renderRun(body,state=ui.state){
    const value=byId("run-state-value"),copy=byId("run-state-copy"),facts=byId("accepted-facts");
    const content=runCopy(state);if(value)value.textContent=content[0];if(copy)copy.textContent=content[1];if(!facts)return;
    facts.replaceChildren();
    if(ui.run)appendFact(facts,"Control-run ID",ui.run.controlRunId);
    if(ui.run&&ui.run.recoveryChild)appendFact(facts,"Recovery from run",ui.run.recoveryParentControlRunId);
    appendReturnedFact(facts,body,"authoritative_session_id","Authoritative session ID");
    appendReturnedFact(facts,body,"control_state","Control state");
    appendReturnedFact(facts,body,"started_at","Started at");
    appendReturnedFact(facts,body,"ended_at","Ended at");
    appendReturnedFact(facts,body,"application_return_code","Application return code (transport only)");
    appendReturnedFact(facts,body,"start_error_type","Start error type");
    appendReturnedFact(facts,body,"terminal_evidence","Terminal evidence");
  }
  function renderAccepted(body){renderRun({control_state:body.control_state},STATES.RUN_ACCEPTED);}
  function safeDisplayValue(value){
    if(value===null)return "null";
    if(Array.isArray(value)||isObject(value))return JSON.stringify(sanitizeResultValue(value),null,2);
    return String(value);
  }
  function sanitizeResultValue(value){
    if(Array.isArray(value))return value.map(sanitizeResultValue);
    if(!isObject(value))return value;
    const safe={};Object.keys(value).forEach(key=>{if(!FORBIDDEN_RESULT_FIELDS.has(key)&&value[key]!==undefined)safe[key]=sanitizeResultValue(value[key]);});return safe;
  }
  function appendObjectFacts(root,value){
    if(Array.isArray(value)){const pre=document.createElement("pre");pre.className="evidence-json";pre.textContent=safeDisplayValue(value);root.append(pre);return;}
    Object.keys(value).forEach(key=>{
      if(FORBIDDEN_RESULT_FIELDS.has(key)||value[key]===undefined)return;
      const row=document.createElement("div"),dt=document.createElement("dt"),dd=document.createElement("dd");
      dt.textContent=key;dd.textContent=safeDisplayValue(value[key]);row.append(dt,dd);root.append(row);
    });
  }
  function addEvidenceSection(root,title,value,open=true){
    if(value===undefined)return;
    const details=document.createElement("details");details.open=open;const summary=document.createElement("summary");summary.textContent=title;details.append(summary);
    if(isObject(value)){const list=document.createElement("dl");list.className="evidence-facts";appendObjectFacts(list,value);details.append(list);}
    else{const pre=document.createElement("pre");pre.className="evidence-json";pre.textContent=safeDisplayValue(value);details.append(pre);}
    root.append(details);
  }
  function addClassification(root,label,value,primary=false,tone=""){
    if(value===undefined)return;
    const item=document.createElement("div");item.className="classification-item"+(primary?" primary":"");if(tone)item.dataset.tone=tone;
    const name=document.createElement("span");name.className="classification-label";name.textContent=label;const text=document.createElement("span");text.className="classification-value";text.textContent=safeDisplayValue(value);item.append(name,text);root.append(item);
  }
  function resultTone(verdict,presentation){
    if(verdict==="REFUSED"||presentation==="REFUSED")return "refused";
    if(verdict==="ADMITTED_OBSERVED"||verdict==="ADMITTED_VERIFIED"||presentation==="ADMITTED")return "admitted";
    if(presentation==="INCOMPLETE"||presentation==="INCONSISTENT")return "incomplete";
    return "";
  }
  function addGlance(root,title,value,keys){
    if(!isObject(value))return;
    const card=document.createElement("section");card.className="evidence-card";const heading=document.createElement("h3");heading.textContent=title;card.append(heading);
    keys.forEach(key=>{if(!hasOwn(value,key))return;const line=document.createElement("p"),name=document.createElement("span"),text=document.createElement("span");name.className="evidence-key";name.textContent=key+": ";text.textContent=safeDisplayValue(value[key]);line.append(name,text);card.append(line);});root.append(card);
  }
  function renderResult(body){
    const result=sanitizeResultValue(body),admission=isObject(result.result_admission_state)?result.result_admission_state:{},complete=isObject(result.evidence_completeness)?result.evidence_completeness:{},boundary=isObject(result.failing_boundary)?result.failing_boundary:{},classification=byId("result-classification");
    const clauseView=isObject(result.authorized_gate_clauses)?result.authorized_gate_clauses:{};renderGateClauses("result-gate-clauses",clauseView.clauses,clauseView.present);
    classification.replaceChildren();const tone=resultTone(admission.verdict,result.presentation_status);
    if(hasOwn(admission,"verdict"))addClassification(classification,"Product verdict",admission.verdict,true,tone);
    if(hasOwn(admission,"verification_mode"))addClassification(classification,"Verification mode",admission.verification_mode);
    if(hasOwn(complete,"state"))addClassification(classification,"Evidence completeness",complete.state);
    if(hasOwn(boundary,"boundary")&&boundary.boundary!==null&&boundary.boundary!=="NONE")addClassification(classification,"Failing boundary",boundary.boundary);
    if(hasOwn(result,"presentation_status"))addClassification(classification,"Presentation",result.presentation_status,false,tone);
    const summary=[];
    if(hasOwn(admission,"verdict"))summary.push(`Product verdict: ${safeDisplayValue(admission.verdict)}.`);
    if(hasOwn(admission,"verification_mode"))summary.push(`Verification mode: ${safeDisplayValue(admission.verification_mode)}.`);
    if(hasOwn(complete,"state"))summary.push(`Evidence completeness: ${safeDisplayValue(complete.state)}.`);
    if(hasOwn(boundary,"boundary")&&boundary.boundary!==null&&boundary.boundary!=="NONE")summary.push(`Failing boundary: ${safeDisplayValue(boundary.boundary)}.`);
    byId("result-summary").textContent=summary.join(" ")||"The authoritative result transport returned no classification fields.";
    byId("non-authority-notice").textContent=hasOwn(result,"non_authority_notice")?safeDisplayValue(result.non_authority_notice):"";
    const glance=byId("evidence-glance");glance.replaceChildren();const materialGit=isObject(result.material_git_result)?result.material_git_result:{};
    addGlance(glance,"Git result",materialGit.git,["present","final_git_head","commits_added","source_repository_mutated"]);
    addGlance(glance,"Required materials",materialGit.material,["present","result","eligible","material_paths_compliant"]);
    addGlance(glance,"Checkpoint",result.checkpoint_result,["present","result","attempted","checkpoint_fingerprint"]);
    addGlance(glance,"Behavioral verification",result.behavioral_verifier_result,["present","result","exit_code","evidence_fingerprint"]);
    const essential=byId("essential-evidence");essential.replaceChildren();
    const identity={control_run_id:ui.run.controlRunId};
    if(ui.run.status&&hasOwn(ui.run.status,"authoritative_session_id"))identity.authoritative_session_id=ui.run.status.authoritative_session_id;
    if(hasOwn(result,"run_id"))identity.run_id=result.run_id;
    addEvidenceSection(essential,"Run identity",identity,true);
    if(hasOwn(materialGit,"git"))addEvidenceSection(essential,"Git and workspace result",materialGit.git,true);
    if(hasOwn(materialGit,"material"))addEvidenceSection(essential,"Required materials",materialGit.material,true);
    if(hasOwn(result,"checkpoint_result"))addEvidenceSection(essential,"Checkpoint result",result.checkpoint_result,true);
    if(hasOwn(result,"behavioral_verifier_result"))addEvidenceSection(essential,"Independent behavioral verification",result.behavioral_verifier_result,true);
    const completenessBoundary={};if(hasOwn(result,"evidence_completeness"))completenessBoundary.evidence_completeness=result.evidence_completeness;if(hasOwn(result,"failing_boundary"))completenessBoundary.failing_boundary=result.failing_boundary;
    if(Object.keys(completenessBoundary).length)addEvidenceSection(essential,"Completeness and failing boundary",completenessBoundary,true);
    const supplemental=byId("supplemental-evidence");supplemental.replaceChildren();const process={};
    if(hasOwn(result,"execution_state"))process.execution_state=result.execution_state;
    ["application_return_code","start_error_type","terminal_evidence","started_at","ended_at"].forEach(key=>{if(ui.run.status&&hasOwn(ui.run.status,key))process[key]=ui.run.status[key];});
    if(Object.keys(process).length)addEvidenceSection(supplemental,"Process facts",process,false);
    const inventory={};if(hasOwn(result,"timeline"))inventory.timeline=result.timeline;if(hasOwn(result,"artifacts"))inventory.artifacts=result.artifacts;if(Object.keys(inventory).length)addEvidenceSection(supplemental,"Evidence inventory",inventory,false);
    const notices={};["transport_schema_version","transport_redactions","read_notes","human_disposition"].forEach(key=>{if(hasOwn(result,key))notices[key]=result[key];});if(Object.keys(notices).length)addEvidenceSection(supplemental,"Notices and transport",notices,false);
    renderRecoveryOffer(result);
  }
  function renderNoResult(body){
    const root=byId("no-result-facts");root.replaceChildren();if(ui.run)appendFact(root,"Control-run ID",ui.run.controlRunId);
    appendReturnedFact(root,body,"control_state","Returned control state");appendReturnedFact(root,body,"application_return_code","Application return code (transport only)");appendReturnedFact(root,body,"terminal_evidence","Terminal evidence");appendReturnedFact(root,body,"start_error_type","Start error type");
  }
  // --- Governed backend-drift rerun (REFUSED: post_run_backend_drift) --------
  // The browser only mirrors the server truth for display; the launcher
  // re-classifies eligibility from the authoritative result on every POST.
  const RECOVERY_REASON="post_run_backend_drift";
  function recoveryEligible(result){
    if(!isObject(result))return false;
    const admission=isObject(result.result_admission_state)?result.result_admission_state:{};
    const boundary=isObject(result.failing_boundary)?result.failing_boundary:{};
    return admission.verdict==="REFUSED"
      &&admission.verdict_is_authoritative===true
      &&Array.isArray(boundary.reasons)
      &&boundary.reasons.includes(RECOVERY_REASON);
  }
  function renderRecoveryOffer(result){
    const existing=byId("recovery-offer");if(existing)existing.remove();
    const view=byId("result-view");if(!view||!ui.run)return;
    if(ui.run.recoveryChild||!recoveryEligible(result))return;
    const section=document.createElement("section");section.id="recovery-offer";section.className="evidence-card";
    const heading=document.createElement("h3");heading.textContent="REFUSED";section.append(heading);
    ["Backend changed during execution.",
     "The candidate workspace and evidence were preserved.",
     "A new owner authorization is required before rerunning."].forEach(text=>{
      const line=document.createElement("p");line.textContent=text;section.append(line);
    });
    const origin=document.createElement("p");origin.className="hint";origin.textContent=`Recovery from run ${ui.run.controlRunId}`;section.append(origin);
    const actions=document.createElement("div");actions.className="actions";
    const button=document.createElement("button");button.type="button";button.className="button primary";button.textContent="Prepare governed rerun";
    button.id="prepare-recovery";
    button.addEventListener("click",prepareRecovery);
    actions.append(button);section.append(actions);
    view.append(section);
  }
  function adoptRecovery(view,parentTruth){
    if(!isObject(view)||typeof view.child_contract_id!=="string"||!view.child_contract_id
      ||typeof view.preparation_id!=="string"||!view.preparation_id){
      showError("RECOVERY_VIEW_INVALID","The launcher returned an unusable recovery view.",ui.state);
      return;
    }
    stopPolling();
    ui.recovery={view,parentControlRunId:typeof view.parent_control_run_id==="string"?view.parent_control_run_id:"",parentTruth:isObject(parentTruth)?parentTruth:null};
    ui.contract={input:null,response:{contract_id:view.child_contract_id}};
    ui.preparation={id:view.preparation_id,status:null};
    ui.run=null;ui.result=null;ui.resultResolved=false;
    setState(STATES.PREPARATION_QUEUED);
    preparationCopy(STATES.PREPARATION_QUEUED,{});
    pollPreparation();
  }
  async function prepareRecovery(){
    if(ui.recoveryInFlight||!ui.run)return;
    ui.recoveryInFlight=true;
    const offerButton=byId("prepare-recovery");if(offerButton)offerButton.disabled=true;
    clearError();
    const epoch=ui.flowEpoch;
    const parentId=ui.run.controlRunId;
    const parentTruth=ui.result&&isObject(ui.result.authorization)?sanitizeResultValue(ui.result.authorization):null;
    try{
      const {body}=await api(`/ui/api/v1/runs/${encodeURIComponent(parentId)}/recovery`,{method:"POST",body:"{}"});
      if(epoch!==ui.flowEpoch)return;
      adoptRecovery(body,parentTruth);
    }catch(error){
      if(epoch!==ui.flowEpoch)return;
      const mapped=boundedMessage(error.status,error.body);
      showError(mapped.code,"The launcher did not accept the governed rerun request.",ui.state);
      const retry=byId("prepare-recovery");if(retry)retry.disabled=false;
    }finally{
      ui.recoveryInFlight=false;
    }
  }
  async function resumeRecovery(){
    // Browser refresh: pending launcher-resident recoveries are reconstructed
    // from the recovery GET routes. This state is not restart-durable.
    if(ui.state!==STATES.COMPOSE)return;
    const epoch=ui.flowEpoch;
    let pending=null;
    try{
      const {body}=await api("/ui/api/v1/recoveries");
      const list=Array.isArray(body.recoveries)?body.recoveries:[];
      pending=list.find(item=>isObject(item)&&(item.state==="PREPARING"||item.state==="AWAITING_OWNER_AUTHORIZATION"))||null;
    }catch(_error){return;}
    if(!pending||epoch!==ui.flowEpoch||ui.state!==STATES.COMPOSE)return;
    let parentTruth=null;
    try{
      const parent=await api(authoritativeResultPath(pending.parent_control_run_id));
      if(parent.body&&isObject(parent.body.authorization))parentTruth=sanitizeResultValue(parent.body.authorization);
    }catch(_error){}
    if(epoch!==ui.flowEpoch||ui.state!==STATES.COMPOSE)return;
    adoptRecovery(pending,parentTruth);
  }
  function recoveryBackendDelta(parent,payload){
    const parentIdentity=typeof parent.backend_identity==="string"&&parent.backend_identity?parent.backend_identity:null;
    const freshFingerprint=typeof payload.backend_attestation_fingerprint==="string"&&payload.backend_attestation_fingerprint?payload.backend_attestation_fingerprint:null;
    const pieces=["The parent refusal proved the backend changed during the parent run."];
    pieces.push(parentIdentity?`Persisted parent backend identity: ${parentIdentity}.`:"The parent evidence records no backend identity.");
    pieces.push(freshFingerprint?`The child run is authorized only against the fresh attestation fingerprint ${freshFingerprint}.`:"The fresh preparation returned no attestation fingerprint.");
    return pieces.join(" ");
  }
  function renderRecoveryAuthority(body){
    const existing=byId("recovery-authority");if(existing)existing.remove();
    const view=byId("authorize-view");if(!view||!ui.recovery)return;
    const payload=isObject(body.authorization_payload)?body.authorization_payload:{};
    const record=isObject(ui.recovery.view)?ui.recovery.view:{};
    const parent={};
    if(isObject(ui.recovery.parentTruth))Object.keys(ui.recovery.parentTruth).forEach(key=>{parent[key]=ui.recovery.parentTruth[key];});
    if(typeof parent.backend_identity!=="string"&&typeof record.parent_backend_identity==="string")parent.backend_identity=record.parent_backend_identity;
    const section=document.createElement("section");section.id="recovery-authority";section.className="authority-inspector";
    const heading=document.createElement("h3");heading.textContent=`Recovery from run ${ui.recovery.parentControlRunId}`;section.append(heading);
    const note=document.createElement("p");note.className="hint";
    note.textContent="The original refusal remains authoritative and immutable. This child uses a fresh contract, a fresh preparation and a fresh backend attestation; no authority from the parent run is reused.";
    section.append(note);
    const facts=document.createElement("dl");facts.className="fact-grid";
    appendFact(facts,"Recovery ID",record.recovery_id);
    appendFact(facts,"Fresh preparation ID",body.preparation_id);
    appendFact(facts,"Fresh payload fingerprint",body.payload_fingerprint);
    appendFact(facts,"Parent backend identity (persisted)",typeof parent.backend_identity==="string"&&parent.backend_identity?parent.backend_identity:"Not recorded in parent evidence");
    appendFact(facts,"Child backend executable (fresh)",payload.executable);
    appendFact(facts,"Child backend attestation class (fresh)",payload.backend_attestation_class);
    appendFact(facts,"Child backend attestation fingerprint (fresh)",payload.backend_attestation_fingerprint);
    const parentModel=parent.authorized_model===null||parent.authorized_model===undefined?"Not recorded":String(parent.authorized_model);
    const childModel=payload.selected_model===undefined?"Not returned":String(payload.selected_model);
    appendFact(facts,"Model (parent, then child)",`${parentModel}, then ${childModel}`);
    appendFact(facts,"Backend delta",recoveryBackendDelta(parent,payload));
    section.append(facts);
    view.append(section);
  }
  function observationError(code,message){
    stopPolling();if(ui.state!==STATES.RUN_REQUEST_ERROR)setState(STATES.RUN_REQUEST_ERROR);renderRun(ui.run&&ui.run.status?ui.run.status:{},STATES.RUN_REQUEST_ERROR);showError(code,message,STATES.RUN_REQUEST_ERROR);
  }
  function scheduleObservation(tick){ui.pollTimer=setTimeout(tick,POLL_INTERVAL_MS);}
  function boundedSeconds(value,maximum){
    return Number.isInteger(value)&&value>0&&value<=maximum?value:0;
  }
  function derivedObservationBudgetMs(payload){
    // Derived ONLY from the launcher-authored canonical preparation payload.
    // Browser-authored compose fields are never consulted: the owner's typed
    // timeout is an authoring request, not the authority the launcher accepted.
    if(!isObject(payload))return OBSERVATION_CEILING_MS;
    const profile=isObject(payload.mission_profile)?payload.mission_profile:{};
    const native=boundedSeconds(payload.timeout_seconds,LAUNCHER_MAX_NATIVE_TIMEOUT_SECONDS)
      ||boundedSeconds(profile.timeout_seconds,LAUNCHER_MAX_NATIVE_TIMEOUT_SECONDS)
      ||LAUNCHER_MAX_NATIVE_TIMEOUT_SECONDS;
    let checkpoint=0;
    const commands=Array.isArray(profile.checkpoint_commands)?profile.checkpoint_commands:[];
    commands.forEach(command=>{if(isObject(command))checkpoint+=boundedSeconds(command.timeout_seconds,MAX_CHECKPOINT_ALLOWANCE_SECONDS);});
    const verification=isObject(profile.verification)?profile.verification:{};
    const verifier=boundedSeconds(verification.verifier_timeout_seconds,MAX_VERIFIER_TIMEOUT_SECONDS);
    const seconds=native+checkpoint+verifier+FINALIZATION_MARGIN_SECONDS;
    // Clamp to the fixed safe client ceiling; never unbounded, never below the floor.
    return Math.min(OBSERVATION_CEILING_MS,Math.max(MIN_OBSERVATION_MS,seconds*1000));
  }
  function startRunObservation(){
    if(ui.pollController||!ui.run||ui.resultResolved)return;
    ui.pollController=new AbortController();ui.statusAttempts=0;ui.resultAttempts=0;ui.observationPhase="status";
    const epoch=ui.flowEpoch,controller=ui.pollController,firstStatusAt=Date.now()+POLL_INTERVAL_MS;
    // Captured once, when observation starts. The budget is the numeric value
    // retained from the canonical preparation authority before HTTP 202.
    const budgetMs=Number.isFinite(ui.observationBudgetMs)&&ui.observationBudgetMs>0?ui.observationBudgetMs:OBSERVATION_CEILING_MS;
    const observationDeadlineAt=Date.now()+budgetMs;
    ui.observationDeadlineAt=observationDeadlineAt;
    let firstStatusDeferrals=0;
    const active=()=>epoch===ui.flowEpoch&&ui.pollController===controller&&!controller.signal.aborted&&!ui.resultResolved;
    const tick=async()=>{
      ui.pollTimer=null;if(!active()||ui.requestInFlight)return;
      // The pre-first-attempt guard is also clock-coupled, so it carries its own
      // count bound: a backward-moving clock must not defer the first status read
      // forever, and the re-arm delay stays clamped to one poll interval.
      if(ui.observationPhase==="status"&&ui.statusAttempts===0&&firstStatusDeferrals<MAX_FIRST_STATUS_DEFERRALS&&Date.now()<firstStatusAt){firstStatusDeferrals+=1;ui.pollTimer=setTimeout(tick,Math.max(1,Math.min(POLL_INTERVAL_MS,firstStatusAt-Date.now())));return;}
      if(ui.observationPhase==="status"&&ui.statusAttempts>=MAX_OBSERVATION_ATTEMPTS){observationError("OBSERVATION_LIMIT_REACHED","Run observation stopped at its bounded attempt backstop. No product verdict was inferred.");return;}
      if(ui.observationPhase==="status"&&Date.now()>=observationDeadlineAt){observationError("OBSERVATION_LIMIT_REACHED","Run observation stopped at its bounded deadline. No product verdict was inferred.");return;}
      if(ui.observationPhase==="result"&&ui.resultAttempts>=MAX_RESULT_ATTEMPTS){observationError("RESULT_OBSERVATION_LIMIT_REACHED","Authoritative result retrieval stopped after its bounded retry limit. No product verdict was inferred.");return;}
      ui.requestInFlight=true;
      try{
        if(ui.observationPhase==="status"){
          ui.statusAttempts+=1;if(ui.state===STATES.RUN_ACCEPTED||ui.state===STATES.RUN_QUEUED||ui.state===STATES.RUN_STARTING||ui.state===STATES.RUN_RUNNING)setState(STATES.RUN_LOADING);
          const {body}=await api(controlRunPath(ui.run.controlRunId),{signal:controller.signal});if(!active())return;ui.run.status=body;
          const next={QUEUED:STATES.RUN_QUEUED,STARTING:STATES.RUN_STARTING,RUNNING:STATES.RUN_RUNNING,START_FAILED:STATES.RUN_START_FAILED,TERMINAL:STATES.RUN_TERMINAL_LOADING_RESULT}[body.control_state];
          if(!next){observationError("UNRECOGNIZED_CONTROL_STATE","The launcher returned an unrecognized control state. No state or verdict was inferred.");return;}
          setState(next);renderRun(body,next);
          if(body.control_state==="TERMINAL"||body.control_state==="START_FAILED")ui.observationPhase="result";else scheduleObservation(tick);
        }else{
          ui.resultAttempts+=1;
          try{
            const {body}=await api(authoritativeResultPath(ui.run.controlRunId),{signal:controller.signal});if(!active())return;
            ui.result=body;renderResult(body);ui.resultResolved=true;stopPolling();setState(STATES.RUN_RESULT_READY);
          }catch(error){
            if(error.name==="AbortError"||!active())return;
            if(error.status===409&&error.body&&error.body.error==="RESULT_NOT_READY"){scheduleObservation(tick);return;}
            if(error.status===410&&error.body&&error.body.error==="NO_AUTHORITATIVE_RESULT"){renderNoResult(error.body);ui.resultResolved=true;stopPolling();setState(STATES.RUN_NO_AUTHORITATIVE_RESULT);return;}
            const mapped=boundedMessage(error.status,error.body);observationError(mapped.code,"The authoritative result could not be read within the bounded observation lifecycle.");
          }
        }
      }catch(error){
        if(error.name==="AbortError"||!active())return;
        const mapped=boundedMessage(error.status,error.body);observationError(mapped.code,"The accepted control run could not be read within the bounded observation lifecycle.");
      }finally{if(epoch===ui.flowEpoch)ui.requestInFlight=false;}
      if(active()&&ui.observationPhase==="result"&&ui.pollTimer===null)scheduleObservation(tick);
    };
    scheduleObservation(tick);
  }
  async function launch(event){
    event.preventDefault();clearError();if(!validateAuthorization())return;setState(STATES.LAUNCHING);
    const headers={"X-Admissible-Owner-Authorization":byId("owner-phrase").value};const digest=byId("owner-digest");if(digest)headers["X-Admissible-Owner-Authorization-Digest"]=digest.value;
    try{
      const {status,body}=await api("/ui/api/v1/runs",{method:"POST",headers,body:JSON.stringify({contract_id:ui.contract.response.contract_id,preparation_id:ui.preparation.id})});if(status!==202){const err=new Error("LAUNCH_NOT_ACCEPTED");err.status=status;err.body=body;throw err;}
      stopPolling();headers["X-Admissible-Owner-Authorization"]="";if(headers["X-Admissible-Owner-Authorization-Digest"])headers["X-Admissible-Owner-Authorization-Digest"]="";clearSecrets();
      // Reduce the canonical preparation authority to a single number BEFORE the
      // payload custody is released, so nothing but the numeric budget survives.
      ui.observationBudgetMs=derivedObservationBudgetMs(ui.preparation&&ui.preparation.status?ui.preparation.status.authorization_payload:null);
      const fromRecovery=ui.recovery!==null;
      ui.contract=null;ui.preparation=null;ui.run={controlRunId:body.control_run_id,initialControlState:body.control_state,status:{control_state:body.control_state},recoveryChild:fromRecovery,recoveryParentControlRunId:fromRecovery?ui.recovery.parentControlRunId:null};ui.recovery=null;ui.result=null;ui.resultResolved=false;
      renderAccepted(body);setState(STATES.RUN_ACCEPTED);startRunObservation();
    }catch(error){const mapped=boundedMessage(error.status,error.body);setState(STATES.PREPARATION_READY);showError(mapped.code,mapped.message,STATES.PREPARATION_READY);}
    finally{headers["X-Admissible-Owner-Authorization"]="";if(headers["X-Admissible-Owner-Authorization-Digest"])headers["X-Admissible-Owner-Authorization-Digest"]="";clearSecrets();}
  }
  function reset(){
    if(ui.state===STATES.LAUNCHING)return;
    ui.flowEpoch+=1;stopPolling();clearSecrets();clearError();ui.contract=null;ui.preparation=null;ui.run=null;ui.result=null;ui.resultResolved=false;ui.statusAttempts=0;ui.resultAttempts=0;ui.prepareInFlight=false;ui.observationBudgetMs=0;ui.observationDeadlineAt=null;ui.recovery=null;ui.recoveryInFlight=false;
    const staleOffer=byId("recovery-offer");if(staleOffer)staleOffer.remove();
    const staleAuthority=byId("recovery-authority");if(staleAuthority)staleAuthority.remove();
    if(ui.state!==STATES.COMPOSE)setState(STATES.COMPOSE);byId("mission-text").focus();
  }
  function legacyState(){return ui.state===STATES.RUN_ACCEPTED?STATES.LAUNCH_ACCEPTED:ui.state;}
  function snapshot(){
    const digest=byId("owner-digest"),legacyAccepted=ui.state===STATES.RUN_ACCEPTED;
    return {
      state:legacyState(),contractId:ui.contract&&ui.contract.response?ui.contract.response.contract_id:null,preparationId:ui.preparation?ui.preparation.id:null,
      preparationState:ui.preparation&&ui.preparation.status?ui.preparation.status.state:null,pollCount:ui.pollCount,
      hasPollController:legacyAccepted?false:!!ui.pollController,hasPollTimer:legacyAccepted?false:ui.pollTimer!==null,prepareInFlight:ui.prepareInFlight,
      phraseValue:byId("owner-phrase").value,phraseType:byId("owner-phrase").type,digestValue:digest?digest.value:"",
      statusMessage:byId("status-message").textContent,statusCode:byId("status-code").textContent,prepareDisabled:byId("prepare-button").disabled,
      launchDisabled:byId("launch-button").disabled,resetDisabled:Array.from(document.querySelectorAll(".reset-flow")).map(button=>button.disabled),
      acceptedText:byId("accepted-facts").textContent,preparationCopy:byId("preparation-copy").textContent,canonicalPayload:byId("canonical-payload").textContent,
      intentFacts:byId("intent-facts").textContent,contractFacts:byId("contract-facts").textContent
    };
  }
  function g4Snapshot(){return Object.freeze({state:ui.state,controlRunId:ui.run?ui.run.controlRunId:null,initialControlState:ui.run?ui.run.initialControlState:null,controlState:ui.run&&ui.run.status?ui.run.status.control_state:null,statusAttempts:ui.statusAttempts,resultAttempts:ui.resultAttempts,requestInFlight:ui.requestInFlight,hasAbortOwner:!!ui.pollController,hasTimer:ui.pollTimer!==null,resultResolved:ui.resultResolved,observationBudgetMs:ui.observationBudgetMs,observationDeadlineAt:ui.observationDeadlineAt,maxObservationAttempts:MAX_OBSERVATION_ATTEMPTS,observationCeilingMs:OBSERVATION_CEILING_MS,hasPreparation:ui.preparation!==null,runText:byId("accepted-facts")?byId("accepted-facts").textContent:"",resultText:byId("result-view")?byId("result-view").textContent:"",noResultText:byId("no-result-view")?byId("no-result-view").textContent:"",errorText:byId("status-area")?byId("status-area").textContent:""});}

  byId("compose-form").addEventListener("submit",author);byId("authorize-form").addEventListener("submit",launch);byId("prepare-button").addEventListener("click",prepare);byId("retry-preparation").addEventListener("click",prepare);byId("back-to-compose").addEventListener("click",reset);document.querySelectorAll(".reset-flow").forEach(button=>button.addEventListener("click",reset));byId("add-material").addEventListener("click",()=>addMaterial());byId("retry-bootstrap").addEventListener("click",bootstrap);byId("toggle-phrase").addEventListener("click",()=>{const input=byId("owner-phrase"),show=input.type==="password";input.type=show?"text":"password";byId("toggle-phrase").textContent=show?"Hide":"Show";byId("toggle-phrase").setAttribute("aria-pressed",String(show));});window.addEventListener("pagehide",stopPolling,{once:true});window.addEventListener("beforeunload",stopPolling,{once:true});
  addMaterial("README.md");
  Object.defineProperty(window,"AdmissibleG3Test",{value:Object.freeze({
    STATES,allowedTransitions:allowed,getState:legacyState,reset,prepare,launch,bootstrap,author,stopPolling,snapshot,
    setField:(id,value)=>{byId(id).value=value;},click:(id)=>{byId(id).click();},submit:(id)=>{const form=byId(id);form.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}));}
  }),writable:false});
  function attachedById(id){const node=byId(id);return node&&node.parentNode?node:null;}
  Object.defineProperty(window,"AdmissibleG5Test",{value:Object.freeze({
    getRecovery:()=>ui.recovery?Object.freeze({parentControlRunId:ui.recovery.parentControlRunId,recoveryId:ui.recovery.view&&typeof ui.recovery.view.recovery_id==="string"?ui.recovery.view.recovery_id:null,hasParentTruth:!!ui.recovery.parentTruth}):null,
    recoveryInFlight:()=>ui.recoveryInFlight,
    offerPresent:()=>!!attachedById("recovery-offer"),
    offerText:()=>{const node=attachedById("recovery-offer");return node?node.textContent:"";},
    offerDisabled:()=>{const node=attachedById("prepare-recovery");return node?node.disabled:null;},
    recoveryFactsText:()=>{const node=attachedById("recovery-authority");return node?node.textContent:"";},
    clickOffer:()=>{const node=attachedById("prepare-recovery");if(node)node.click();},
    runIsRecoveryChild:()=>!!(ui.run&&ui.run.recoveryChild)
  }),writable:false,configurable:true});
  Object.defineProperty(window,"AdmissibleG4Test",{value:Object.freeze({STATES,getState:()=>ui.state,snapshot:g4Snapshot}),writable:false,configurable:true});
  bootstrap();
})();
