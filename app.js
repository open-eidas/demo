// Démo Open eIDAS — horodatage RFC 3161 en direct contre le staging public.
//
// Tout se passe dans le navigateur : le hash est calculé localement
// (Web Crypto), la requête part directement vers l'API du staging, et le
// jeton renvoyé est intégralement parsé et vérifié côté client avec
// pkijs/asn1js (chargés depuis jsDelivr). Rien ne transite par un serveur
// intermédiaire.

const API_BASE = "https://api.staging.open-eidas.eu";

let pkijs, asn1js;
let currentFile = null;
let currentDigestHex = null;
let currentTokenDer = null;

async function loadCrypto() {
  if (pkijs) return;
  [pkijs, asn1js] = await Promise.all([
    import("https://cdn.jsdelivr.net/npm/pkijs/+esm"),
    import("https://cdn.jsdelivr.net/npm/asn1js/+esm"),
  ]);
  pkijs.setEngine(
    "browser",
    new pkijs.CryptoEngine({ name: "browser", crypto, subtle: crypto.subtle })
  );
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64ToBuffer(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

/// Une vue (`Uint8Array`/`valueHexView`) partage le buffer complet de son
/// parent : `.buffer` seul renvoie tout ce buffer, pas la portion visée par
/// la vue. Toujours re-découper explicitement avant de re-parser une
/// sous-structure ASN.1.
function sliceView(view) {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
}

async function sha256(buffer) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
}

async function requestTimestamp(digestHex) {
  const res = await fetch(`${API_BASE}/api/v1/timestamp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash: digestHex, algorithm: "sha256" }),
  });
  const body = await res.json();
  if (!res.ok || !body.granted) {
    throw new Error(body.error || `réponse ${res.status} de la TSA`);
  }
  return body;
}

/// Extrait à la main les six premiers champs de TSTInfo (RFC 3161 §2.4.2) :
/// pkijs.TSTInfo rejette la valeur réelle du serveur sur un bug connu de
/// validation de schéma (cf. PeculiarVentures/ASN1.js#37), donc on
/// n'utilise que le parseur ASN.1 générique, jamais la classe stricte.
function parseTstInfoFields(tstInfoBuf) {
  const seq = asn1js.fromBER(tstInfoBuf).result.valueBlock.value;
  const messageImprint = seq[2].valueBlock.value;
  return {
    policyOid: seq[1].valueBlock.toString(),
    hashAlgOid: messageImprint[0].valueBlock.value[0].valueBlock.toString(),
    messageImprintHex: bytesToHex(messageImprint[1].valueBlock.valueHexView),
    serialHex: bytesToHex(seq[3].valueBlock.valueHexView),
    genTime: seq[4].toDate(),
  };
}

/// Remonte du certificat signataire vers une racine auto-signée, un
/// maillon à la fois, en retrouvant à chaque étape le certificat dont le
/// sujet correspond exactement à l'émetteur du précédent (comparaison
/// DER, pas `isEqual` de pkijs, pour rester indépendant de sa version).
/// `false` si la chaîne est rompue, si un maillon manque, ou si la boucle
/// dépasse le nombre de certificats fournis sans atteindre de racine.
async function verifyCertificateChain(signerCert, certs) {
  const derOf = (name) => new Uint8Array(name.toSchema().toBER(false));
  const sameName = (a, b) => bytesToHex(derOf(a)) === bytesToHex(derOf(b));

  let current = signerCert;
  const used = new Set([current]);
  for (let i = 0; i < certs.length; i++) {
    if (sameName(current.subject, current.issuer)) {
      return current.verify();
    }
    const issuer = certs.find((c) => !used.has(c) && sameName(c.subject, current.issuer));
    if (!issuer) return false;
    if (!(await current.verify(issuer))) return false;
    used.add(issuer);
    current = issuer;
  }
  return false;
}

/// Vérifie la signature CMS (SignedData) du jeton contre le certificat
/// désigné par le SignerInfo (`sid`), puis la chaîne de certificats
/// jointe. `SignedData.prototype.verify()` de pkijs échoue sur ce contenu
/// (id-ct-TSTInfo, pas id-data) : on vérifie donc la signature à la main
/// via Web Crypto, en s'appuyant sur `signedAttrs.encodedValue` — les
/// octets exacts, déjà ré-étiquetés SET, que pkijs a mis de côté au
/// moment du parsing pour cet usage précis.
async function verifyToken(tokenBuf, expectedDigestHex) {
  const asn1 = asn1js.fromBER(tokenBuf);
  const tsResp = new pkijs.TimeStampResp({ schema: asn1.result });
  if (tsResp.status.status !== 0) {
    throw new Error("statut refusé par la TSA (PKIStatus != granted)");
  }

  const cmsContent = new pkijs.ContentInfo({ schema: tsResp.timeStampToken.toSchema() });
  const signedData = new pkijs.SignedData({ schema: cmsContent.content });

  const tstInfoBuf = sliceView(signedData.encapContentInfo.eContent.valueBlock.valueHexView);
  const tstInfo = parseTstInfoFields(tstInfoBuf);

  const digestMatches = tstInfo.messageImprintHex === expectedDigestHex;

  const signerInfo = signedData.signerInfos[0];
  const signerSerialHex = bytesToHex(signerInfo.sid.serialNumber.valueBlock.valueHexView);
  const signerCert = signedData.certificates.find(
    (c) => bytesToHex(c.serialNumber.valueBlock.valueHexView) === signerSerialHex
  );
  if (!signerCert) throw new Error("certificat signataire absent du jeton");

  const messageDigestAttr = signerInfo.signedAttrs.attributes.find(
    (a) => a.type === "1.2.840.113549.1.9.4"
  );
  const attrDigestHex = bytesToHex(messageDigestAttr.values[0].valueBlock.valueHexView);
  const actualContentDigestHex = bytesToHex(await sha256(tstInfoBuf));
  const contentDigestMatches = attrDigestHex === actualContentDigestHex;

  const spkiDer = signerCert.subjectPublicKeyInfo.toSchema().toBER(false);
  const publicKey = await crypto.subtle.importKey(
    "spki",
    spkiDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const signatureValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signerInfo.signature.valueBlock.valueHexView,
    signerInfo.signedAttrs.encodedValue
  );

  // Chaîne : reconstruite en remontant du signataire vers la racine par
  // correspondance émetteur/sujet — jamais par position dans `certificates`
  // (un SET CMS n'a pas d'ordre garanti ; le présumer a produit un vrai bug
  // ici : `.verify()` appelée sans argument sur un certificat qui n'était
  // pas auto-signé plante avec « Please provide issuer certificate »).
  const chainValid = await verifyCertificateChain(signerCert, signedData.certificates);

  const now = new Date();
  const genTimeWithinValidity =
    tstInfo.genTime >= signerCert.notBefore.value && tstInfo.genTime <= signerCert.notAfter.value;
  const certCurrentlyValid = now >= signerCert.notBefore.value && now <= signerCert.notAfter.value;

  return {
    tstInfo,
    digestMatches,
    contentDigestMatches,
    signatureValid,
    chainValid,
    genTimeWithinValidity,
    certCurrentlyValid,
    signerSubject: signerCert.subject.typesAndValues.map((t) => t.value.valueBlock.value).join(", "),
    allOk:
      digestMatches &&
      contentDigestMatches &&
      signatureValid &&
      chainValid &&
      genTimeWithinValidity,
  };
}

// --- UI ---

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const fileInfo = document.getElementById("file-info");
const submitBtn = document.getElementById("submit-btn");
const resultBox = document.getElementById("result");
const resultHeader = document.getElementById("result-header");
const resultBody = document.getElementById("result-body");
const downloadBtn = document.getElementById("download-btn");

function setFile(file) {
  currentFile = file;
  currentDigestHex = null;
  currentTokenDer = null;
  resultBox.classList.remove("visible");
  fileInfo.textContent = file ? `Fichier sélectionné : ${file.name} (${file.size} octets)` : "";
  submitBtn.disabled = !file;
}

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragover");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) setFile(fileInput.files[0]);
});

function showResult(ok, html) {
  resultBox.classList.add("visible");
  resultHeader.className = "result-header " + (ok ? "ok" : "error");
  resultHeader.textContent = ok ? "✔ Jeton obtenu et vérifié" : "✖ Échec";
  resultBody.innerHTML = html;
}

submitBtn.addEventListener("click", async () => {
  if (!currentFile) return;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Horodatage en cours…';
  downloadBtn.hidden = true;

  try {
    await loadCrypto();

    const fileBuf = await currentFile.arrayBuffer();
    const digestBytes = await sha256(fileBuf);
    currentDigestHex = bytesToHex(digestBytes);

    const { token, gen_time } = await requestTimestamp(currentDigestHex);
    currentTokenDer = base64ToBuffer(token);

    const v = await verifyToken(currentTokenDer, currentDigestHex);

    const rows = [
      ["Fichier", `${currentFile.name} — SHA-256 <code>${currentDigestHex}</code>`],
      ["Horodaté le", v.tstInfo.genTime.toISOString() + " (déclaré serveur : " + gen_time + ")"],
      ["Politique", v.tstInfo.policyOid],
      ["Signataire", v.signerSubject],
      [
        "Empreinte du jeton = empreinte du fichier",
        v.digestMatches ? "✔ oui" : "✖ NON — le jeton ne correspond pas à ce fichier",
      ],
      ["Intégrité du contenu signé", v.contentDigestMatches ? "✔ intacte" : "✖ altérée"],
      ["Signature cryptographique (RSA/SHA-256)", v.signatureValid ? "✔ valide" : "✖ invalide"],
      [
        "Chaîne de certification (TSU → CA → racine)",
        v.chainValid ? "✔ valide" : "✖ rompue",
      ],
      [
        "Certificat signataire valide à l'horodatage",
        v.genTimeWithinValidity ? "✔ oui" : "✖ non",
      ],
    ];
    const dl = rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
    showResult(
      v.allOk,
      `<dl>${dl}</dl><p style="margin-top:0.9rem;color:var(--text-subtle);">Vérification effectuée entièrement dans ce navigateur (pkijs + Web Crypto), à partir du certificat inclus dans le jeton — sans appel serveur supplémentaire.</p>`
    );
    downloadBtn.hidden = false;
  } catch (err) {
    showResult(false, `<p>${err.message || err}</p>`);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Horodater à nouveau";
  }
});

downloadBtn.addEventListener("click", () => {
  if (!currentTokenDer || !currentFile) return;
  const blob = new Blob([currentTokenDer], { type: "application/timestamp-reply" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${currentFile.name}.tsr`;
  a.click();
  URL.revokeObjectURL(url);
});
