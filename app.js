(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const categories = ["PERSON","EMAIL","PHONE","CNIC","IBAN","CARD","SECRET","SSN","IP","DOB","ACCOUNT"];
  const labels = {PERSON:"Names",EMAIL:"Email addresses",PHONE:"Phone numbers",CNIC:"CNIC",IBAN:"IBAN",CARD:"Payment cards",SECRET:"Passwords & API keys",SSN:"Social Security no.",IP:"IP addresses",DOB:"Dates of birth",ACCOUNT:"Account numbers"};
  const state = { mode:"automatic", detections:[], selected:new Set(), mapping:new Map(), counters:{}, prompts:0, items:0, protectedText:"", scannedText:"" };
  const example = "My name is Ahmed Khan. Please send the invoice to ahmed@example.com and call 0300-1234567. My CNIC is 35202-1234567-1. Draft a professional client proposal.";
  const escapeRegExp = s => s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
  const luhn = value => { const d=value.replace(/\D/g,""); if(!/^\d{13,19}$/.test(d))return false;let sum=0,alt=false;for(let i=d.length-1;i>=0;i--){let n=+d[i];if(alt){n*=2;if(n>9)n-=9;}sum+=n;alt=!alt;}return sum%10===0; };
  const ibanValid = raw => {const s=raw.replace(/\s/g,"").toUpperCase();if(!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s))return false;const r=s.slice(4)+s.slice(0,4);let rem=0;for(const ch of r){const v=/\d/.test(ch)?ch:String(ch.charCodeAt(0)-55);for(const d of v)rem=(rem*10+Number(d))%97;}return rem===1;};
  const rules = [
    {category:"SECRET",confidence:.98,priority:100,re:/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g},
    {category:"SECRET",confidence:.95,priority:100,re:/\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abp]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g},
    {category:"SECRET",confidence:.9,priority:100,re:/\bBearer\s+([A-Za-z0-9._~+\/-]{20,}=*)/g,group:1},
    {category:"SECRET",confidence:.9,priority:95,re:/\b(?:password|passwd|pwd|passcode)\s*(?:is|=|:)\s*["']?([^\s"']{4,})/gi,group:1},
    {category:"CARD",confidence:.95,priority:90,re:/(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g,validate:v=>luhn(v)},
    {category:"IBAN",confidence:.95,priority:90,re:/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g,validate:ibanValid},
    {category:"CNIC",confidence:.95,priority:85,re:/(?<!\d)\d{5}-\d{7}-\d(?!\d)/g},
    {category:"SSN",confidence:.85,priority:80,re:/(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)/g},
    {category:"EMAIL",confidence:.97,priority:80,re:/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g},
    {category:"DOB",confidence:.9,priority:70,re:/\b(?:dob|date of birth|born on|birthday)\s*(?:is|:|=)?\s*(\d{1,4}[\/.-]\d{1,2}[\/.-]\d{1,4}|\d{1,2}\s+[A-Z][a-z]+\s+\d{4})/gi,group:1},
    {category:"ACCOUNT",confidence:.85,priority:65,re:/\b(?:account(?:\s*(?:number|no\.?|#))?|acct)\s*(?:is|=|:|#)?\s*(\d{8,16})(?!\d)/gi,group:1},
    {category:"PHONE",confidence:.9,priority:60,re:/(?<![\w+])(?:\+|00)\d{1,3}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}(?!\d)/g},
    {category:"PHONE",confidence:.85,priority:60,re:/(?<!\d)03\d{2}[\s-]?\d{7}(?!\d)/g},
    {category:"PHONE",confidence:.75,priority:55,re:/(?<!\d)\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)/g},
    {category:"IP",confidence:.75,priority:50,re:/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g},
    {category:"PERSON",confidence:.8,priority:40,re:/(?:[Mm]y name is|[Nn]ame:|[Pp]atient(?: name)?:?|\bMrs?\.?|\bMs\.?|\bDr\.?)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})/g,group:1}
  ];
  function detect(text) {
    const found=[];const enabled=new Set([...document.querySelectorAll(".category-option input:checked")].map(x=>x.value));
    const allow=$("allowlistInput").value.split(/\r?\n/).map(x=>x.trim().toLowerCase()).filter(Boolean);
    const add=(start,end,category,confidence,priority,value)=>{if((category!=="CUSTOM"&&!enabled.has(category))||allow.includes(value.toLowerCase()))return;found.push({start,end,category,confidence,priority,value});};
    for(const rule of rules){const re=new RegExp(rule.re.source,rule.re.flags.includes("d")?rule.re.flags:rule.re.flags+"d");for(const m of text.matchAll(re)){const span=m.indices[rule.group||0];const value=text.slice(span[0],span[1]);if(rule.validate&&!rule.validate(value))continue;add(span[0],span[1],rule.category,rule.confidence,rule.priority,value);}}
    $("keywordsInput").value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean).forEach(k=>{const re=new RegExp(escapeRegExp(k),"gi");for(const m of text.matchAll(re))add(m.index,m.index+m[0].length,"CUSTOM",1,95,m[0]);});
    found.sort((a,b)=>b.priority-a.priority||b.confidence-a.confidence||(b.end-b.start)-(a.end-a.start)||a.start-b.start);
    const chosen=[];for(const d of found)if(!chosen.some(x=>d.start<x.end&&x.start<d.end))chosen.push(d);
    return chosen.sort((a,b)=>a.start-b.start);
  }
  function renderCategories(){ $("categoryGrid").innerHTML=categories.map(c=>`<label class="category-option"><input type="checkbox" value="${c}" checked> ${labels[c]}</label>`).join(""); }
  function renderDetections(){const list=$("detectionList");$("resultCount").textContent=`${state.detections.length} found`;$("reviewSummary").textContent=state.detections.length?`${state.detections.length} potential sensitive item(s) detected`:"No sensitive data detected";
    if(!state.detections.length){list.className="detection-list empty-state";list.innerHTML='<div class="empty-symbol">✓</div><strong>No matches found</strong><p>Try another prompt or adjust your detection settings.</p>';return;}
    list.className="detection-list";list.innerHTML=state.detections.map((d,i)=>`<label class="detection-item"><input type="checkbox" data-index="${i}" ${state.selected.has(i)?"checked":""}><span class="detection-value">${escapeHTML(d.value)}</span><span class="detection-category">${d.category}</span></label>`).join("");
    list.querySelectorAll("input").forEach(input=>input.addEventListener("change",()=>{const i=+input.dataset.index;input.checked?state.selected.add(i):state.selected.delete(i);updateSelected();}));
    updateSelected();
  }
  function escapeHTML(s){return s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
  function updateSelected(){$("selectedSummary").textContent=`${state.selected.size} item${state.selected.size===1?"":"s"} selected`;$("protectBtn").disabled=!state.selected.size;}
  function scan(){const text=$("promptInput").value;if(!text.trim()){toast("Add a prompt before scanning.");return;}state.scannedText=text;state.detections=detect(text);state.selected=new Set(state.detections.map((_,i)=>i));renderDetections();toast(state.detections.length?`${state.detections.length} sensitive item(s) found.`:"No matching sensitive information found.");if(state.mode==="automatic"&&state.detections.length){state.selected=new Set(state.detections.map((_,i)=>i));protect();}}
  function placeholder(d){const key=d.category+"\u0000"+d.value;if(state.mapping.has(key))return state.mapping.get(key);const n=state.counters[d.category]=(state.counters[d.category]||0)+1;const p=`[${d.category}_${n}]`;state.mapping.set(key,p);return p;}
  function protect(){if(!$("promptInput").value.trim()){toast("Add a prompt first.");return;}if(state.scannedText!==$("promptInput").value){scan();if(!state.selected.size)return;}
    const selected=state.detections.filter((d,i)=>state.selected.has(i)).sort((a,b)=>a.start-b.start);if(!selected.length)return;
    let out="",last=0;for(const d of selected){out+=$("promptInput").value.slice(last,d.start)+placeholder(d);last=d.end;}out+=$("promptInput").value.slice(last);
    state.protectedText=out;state.prompts++;state.items+=selected.length;$("promptCount").textContent=state.prompts;$("itemCount").textContent=state.items;
    $("protectedOutput").textContent=out;$("copyProtected").disabled=false;$("downloadProtected").disabled=false;$("restoreBtn").disabled=false;
    $("reviewSummary").textContent=`Protected ${selected.length} selected item(s)`;toast("Your prompt has been protected locally.");
  }
  function restore(){const input=$("responseInput").value;if(!input.trim()){toast("Paste an AI response first.");return;}let output=input;for(const [key,token] of state.mapping){const value=key.split("\u0000")[1];output=output.split(token).join(value);} $("restoredOutput").textContent=output;$("restoredWrap").hidden=false;toast("Response restored using this session's local mapping.");}
  async function copy(text){try{await navigator.clipboard.writeText(text);toast("Copied to clipboard.");}catch{const t=document.createElement("textarea");t.value=text;document.body.appendChild(t);t.select();document.execCommand("copy");t.remove();toast("Copied to clipboard.");}}
  function download(text,name){const blob=new Blob([text],{type:"text/plain;charset=utf-8"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);}
  let toastTimer;function toast(message){const el=$("toast");el.textContent=message;el.classList.add("show");clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.classList.remove("show"),2600);}
  renderCategories();
  $("promptInput").addEventListener("input",()=>{$("charCount").textContent=`${$("promptInput").value.length.toLocaleString()} characters`;});
  $("loadExample").addEventListener("click",()=>{$("promptInput").value=example;$("promptInput").dispatchEvent(new Event("input"));scan();});
  $("scanBtn").addEventListener("click",scan);$("protectBtn").addEventListener("click",protect);
  $("clearBtn").addEventListener("click",()=>{$("promptInput").value="";$("promptInput").dispatchEvent(new Event("input"));state.detections=[];state.selected.clear();state.scannedText="";renderDetections();toast("Prompt cleared. Existing session mappings remain available for restoration.");});
  document.querySelectorAll(".segment").forEach(b=>b.addEventListener("click",()=>{document.querySelectorAll(".segment").forEach(x=>x.classList.toggle("active",x===b));state.mode=b.dataset.mode;toast(state.mode==="automatic"?"Automatic mode selected. Scan and protect with one action.":"Review mode selected. Confirm detections before protecting.");}));
  $("copyProtected").addEventListener("click",()=>copy(state.protectedText));$("downloadProtected").addEventListener("click",()=>download(state.protectedText,"veilai-protected-prompt.txt"));
  $("restoreBtn").addEventListener("click",restore);$("copyRestored").addEventListener("click",()=>copy($("restoredOutput").textContent));
  $("responseInput").addEventListener("input",()=>{$("restoreBtn").disabled=!$("responseInput").value.trim()||!state.mapping.size;});
  $("helpBtn").addEventListener("click",()=>toast("Write a prompt, scan, select detections, protect, then paste the AI reply to restore placeholders."));
  $("scanBtn").addEventListener("dblclick",()=>{if(state.mode==="automatic")protect();});
})();