const $ = id => document.getElementById(id);
const STORAGE_KEY = "passwordvault_mobile_encrypted_v1";
const ITERATIONS = 600000;
let entries = [];
let masterKey = null;
let currentSalt = null;
let locked = true;
let inactivityTimer = null;
let lastActivity = Date.now();
let authMode = "create";

function b64encode(bytes) {
  let binary = "";
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_");
}
function b64decode(value) {
  const base = value.replace(/-/g,"+").replace(/_/g,"/");
  const binary = atob(base);
  return Uint8Array.from(binary,c => c.charCodeAt(0));
}
function concat(...arrays) {
  const result = new Uint8Array(arrays.reduce((n,a)=>n+a.length,0));
  let offset=0;
  for(const a of arrays){result.set(a,offset);offset+=a.length;}
  return result;
}
function equalBytes(a,b) {
  if(a.length!==b.length)return false;
  let diff=0;
  for(let i=0;i<a.length;i++)diff|=a[i]^b[i];
  return diff===0;
}
function timestampBytes() {
  const seconds = BigInt(Math.floor(Date.now()/1000));
  const result = new Uint8Array(8);
  for(let i=7;i>=0;i--)result[i]=Number((seconds>>BigInt((7-i)*8))&255n);
  return result;
}
async function deriveKeys(password,salt) {
  const material=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations:ITERATIONS},material,256));
  const signing=await crypto.subtle.importKey("raw",bits.slice(0,16),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);
  const encryption=await crypto.subtle.importKey("raw",bits.slice(16,32),{name:"AES-CBC"},false,["encrypt","decrypt"]);
  bits.fill(0);
  return {signing,encryption};
}
async function encryptVault(data,keys) {
  const iv=crypto.getRandomValues(new Uint8Array(16));
  const plain=new TextEncoder().encode(JSON.stringify(data));
  const cipher=new Uint8Array(await crypto.subtle.encrypt({name:"AES-CBC",iv},keys.encryption,plain));
  const body=concat(new Uint8Array([0x80]),timestampBytes(),iv,cipher);
  const signature=new Uint8Array(await crypto.subtle.sign("HMAC",keys.signing,body));
  return b64encode(concat(body,signature));
}
async function decryptVault(token,keys) {
  const raw=b64decode(token);
  if(raw.length<73 || raw[0]!==0x80)throw new Error("Formato archivio non valido.");
  const body=raw.slice(0,-32),signature=raw.slice(-32);
  const expected=new Uint8Array(await crypto.subtle.sign("HMAC",keys.signing,body));
  if(!equalBytes(signature,expected))throw new Error("Password errata o archivio danneggiato.");
  const iv=raw.slice(9,25),cipher=raw.slice(25,-32);
  const plain=await crypto.subtle.decrypt({name:"AES-CBC",iv},keys.encryption,cipher);
  const parsed=JSON.parse(new TextDecoder().decode(plain));
  if(!Array.isArray(parsed))throw new Error("Contenuto archivio non valido.");
  return parsed;
}
function getStored() {
  const raw=localStorage.getItem(STORAGE_KEY);
  return raw?JSON.parse(raw):null;
}
function setStored(data) {
  localStorage.setItem(STORAGE_KEY,JSON.stringify(data));
}
async function saveVault() {
  const token=await encryptVault(entries,masterKey);
  setStored({salt:b64encode(currentSalt),vault:token});
}
function setAuthMode(mode) {
  authMode=mode;
  $("authTitle").textContent=mode==="create"?"Il tuo archivio, protetto.":"Bentornato.";
  $("authText").textContent=mode==="create"?"Crea una password principale per iniziare.":"Inserisci la password principale per sbloccare.";
  $("confirmWrap").classList.toggle("hidden",mode!=="create");
  $("authSubmit").textContent=mode==="create"?"Crea archivio":"Sblocca archivio";
  $("authError").textContent="";
}
async function authSubmit(event) {
  event.preventDefault();
  $("authError").textContent="";
  const password=$("masterPassword").value;
  try {
    if(authMode==="create") {
      if(password.length<8)throw new Error("Usa almeno 8 caratteri.");
      if(password!==$("confirmPassword").value)throw new Error("Le password non coincidono.");
      currentSalt=crypto.getRandomValues(new Uint8Array(16));
      masterKey=await deriveKeys(password,currentSalt);
      entries=[];
      await saveVault();
    } else {
      const stored=getStored();
      if(!stored)throw new Error("Nessun archivio trovato. Importa il file .dat.");
      currentSalt=b64decode(stored.salt);
      masterKey=await deriveKeys(password,currentSalt);
      entries=await decryptVault(stored.vault,masterKey);
    }
    locked=false;
    $("masterPassword").value="";
    $("confirmPassword").value="";
    showVault();
    resetInactivity();
  } catch(error) {
    masterKey=null;
    $("authError").textContent=error.message||"Impossibile aprire l'archivio.";
  }
}
function showVault() {
  $("authScreen").classList.add("hidden");
  $("vaultScreen").classList.remove("hidden");
  $("lockBtn").classList.remove("hidden");
  renderEntries();
}
function renderEntries() {
  const query=$("search").value.trim().toLowerCase();
  const filtered=entries.map((item,index)=>({...item,index})).filter(item=>(item.site||"").toLowerCase().includes(query));
  $("entryCount").textContent=entries.length+" password salvate";
  const root=$("entries");
  root.replaceChildren();
  if(!filtered.length) {
    const empty=document.createElement("div");
    empty.className="empty";
    empty.textContent=entries.length?"Nessun risultato.":"Non hai ancora salvato password.";
    root.append(empty);return;
  }
  filtered.forEach(item=>{
    const card=document.createElement("article");card.className="entry";
    const top=document.createElement("div");top.className="entry-top";
    const name=document.createElement("div");name.className="entry-name";name.textContent=item.site||"Senza nome";
    const actions=document.createElement("div");actions.className="entry-actions";
    const copy=document.createElement("button");copy.className="small-btn";copy.textContent="Copia";
    copy.addEventListener("click",()=>copyPassword(item.password));
    const del=document.createElement("button");del.className="small-btn";del.textContent="Elimina";
    del.addEventListener("click",async()=>{if(confirm("Eliminare questa password?")){entries.splice(item.index,1);await saveVault();renderEntries();}});
    actions.append(copy,del);top.append(name,actions);
    const row=document.createElement("div");row.className="entry-password";
    const input=document.createElement("input");input.type="password";input.readOnly=true;input.value=item.password||"";
    const show=document.createElement("button");show.className="small-btn";show.textContent="Mostra";
    show.addEventListener("click",()=>{input.type=input.type==="password"?"text":"password";show.textContent=input.type==="password"?"Mostra":"Nascondi";});
    row.append(input,show);card.append(top,row);root.append(card);
  });
}
async function copyPassword(value) {
  try {await navigator.clipboard.writeText(value);alert("Password copiata.");}
  catch {const t=document.createElement("textarea");t.value=value;document.body.append(t);t.select();document.execCommand("copy");t.remove();alert("Password copiata.");}
}
function randomIndex(max) {
  const limit=Math.floor(256/max)*max;
  const byte=new Uint8Array(1);
  do{crypto.getRandomValues(byte);}while(byte[0]>=limit);
  return byte[0]%max;
}
function generatePassword(length=20) {
  const groups=["ABCDEFGHJKLMNPQRSTUVWXYZ","abcdefghijkmnopqrstuvwxyz","23456789","!@#$%^&*()-_=+[]{}"];
  const all=groups.join("");
  const result=groups.map(g=>g[randomIndex(g.length)]);
  while(result.length<length)result.push(all[randomIndex(all.length)]);
  for(let i=result.length-1;i>0;i--){const j=randomIndex(i+1);[result[i],result[j]]=[result[j],result[i]];}
  return result.join("");
}
function lockVault() {
  if(locked)return;
  masterKey=null;entries=[];currentSalt=null;locked=true;
  clearTimeout(inactivityTimer);
  $("vaultScreen").classList.add("hidden");
  $("lockBtn").classList.add("hidden");
  $("authScreen").classList.remove("hidden");
  $("search").value="";
  $("entries").replaceChildren();
  $("masterPassword").value="";
  $("confirmPassword").value="";
  const stored=getStored();
  setAuthMode(stored?"unlock":"create");
}
function resetInactivity() {
  lastActivity=Date.now();
  clearTimeout(inactivityTimer);
  const minutes=Number($("autoLock").value);
  if(!locked&&minutes>0)inactivityTimer=setTimeout(lockVault,minutes*60000);
}
function downloadVault() {
  const data=getStored();
  if(!data)return;
  const blob=new Blob([JSON.stringify(data)],{type:"application/json"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");a.href=url;a.download="vault.dat";a.click();
  URL.revokeObjectURL(url);
}
async function importFile(file) {
  try {
    const data=JSON.parse(await file.text());
    if(typeof data.salt!=="string"||typeof data.vault!=="string")throw new Error("Il file non è un archivio PasswordVault valido.");
    b64decode(data.salt);b64decode(data.vault);
    localStorage.setItem(STORAGE_KEY,JSON.stringify(data));
    lockVault();
    setAuthMode("unlock");
    alert("Archivio importato. Inserisci la password principale.");
  } catch(error) {alert(error.message||"Importazione non riuscita.");}
}
async function changeMasterPassword() {
  const next=prompt("Inserisci la nuova password principale (almeno 8 caratteri):");
  if(next===null)return;
  if(next.length<8){alert("La password deve contenere almeno 8 caratteri.");return;}
  const confirmNext=prompt("Conferma la nuova password:");
  if(next!==confirmNext){alert("Le password non coincidono.");return;}
  try {
    currentSalt=crypto.getRandomValues(new Uint8Array(16));
    masterKey=await deriveKeys(next,currentSalt);
    await saveVault();
    alert("Password principale aggiornata.");
  } catch(error) {alert("Errore: "+error.message);}
}
$("authForm").addEventListener("submit",authSubmit);
$("entryForm").addEventListener("submit",async event=>{
  event.preventDefault();
  const site=$("site").value.trim(),password=$("newPassword").value;
  if(!site||!password)return;
  entries.push({site,password});
  await saveVault();
  $("site").value="";$("newPassword").value="";
  renderEntries();resetInactivity();
});
$("generateBtn").addEventListener("click",()=>$("newPassword").value=generatePassword(20));
$("search").addEventListener("input",renderEntries);
$("lockBtn").addEventListener("click",lockVault);
$("lockNowBtn").addEventListener("click",lockVault);
$("exportBtn").addEventListener("click",downloadVault);
$("changeMasterBtn").addEventListener("click",changeMasterPassword);
$("importBtn").addEventListener("click",()=>$("importFile").click());
$("importVaultBtn").addEventListener("click",()=>$("importFile").click());
$("importFile").addEventListener("change",event=>{const file=event.target.files[0];if(file)importFile(file);event.target.value="";});
["pointerdown","keydown","touchstart"].forEach(type=>document.addEventListener(type,()=>{if(!locked)resetInactivity();},{passive:true}));
document.addEventListener("visibilitychange",()=>{if(document.hidden&&!locked&&Date.now()-lastActivity>60000)lockVault();});
if("serviceWorker" in navigator)window.addEventListener("load",()=>navigator.serviceWorker.register("./sw.js").catch(()=>{}));
if(!window.crypto?.subtle){$("authError").textContent="Questo browser non supporta la cifratura sicura. Usa Safari o Chrome aggiornato tramite HTTPS."; }
const storedAtStart=getStored();
setAuthMode(storedAtStart?"unlock":"create");

