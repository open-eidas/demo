// Démo Open eIDAS — horodatage RFC 3161 en direct contre le staging public.
//
// Tout se passe dans le navigateur : le hash est calculé localement
// (Web Crypto), la requête part directement vers l'API du staging, et le
// jeton renvoyé est intégralement parsé et vérifié côté client avec
// pkijs/asn1js (chargés depuis jsDelivr). Rien ne transite par un serveur
// intermédiaire.
//
// Prise en charge de tous les types de documents :
// - Pour les fichiers PDF : horodatage PAdES direct (DocTimeStamp RFC 3161)
//   incorporé dans le PDF, reconnu nativement par Adobe Acrobat Reader.
// - Pour tous les autres types de documents : génération d'une attestation PDF
//   scellée par horodatage PAdES, incorporant le fichier original et son
//   jeton .tsr en pièces jointes (PDF attachments).

const API_BASE = "https://api.staging.open-eidas.eu";

let pkijs, asn1js;
let PDFDocument, rgb, StandardFonts;
let preparePdfForTimestamp, extractBytesToHash;
let verifyPdfTimestamps;

let currentFile = null;
let currentDigestHex = null;
let currentTokenDer = null;
let currentSignedPdfBytes = null;
let isCurrentFileNativePdf = false;

async function loadCrypto() {
  if (pkijs) return;
  [
    pkijs,
    asn1js,
    { PDFDocument, rgb, StandardFonts },
    { preparePdfForTimestamp, extractBytesToHash },
    { verifyPdfTimestamps },
  ] = await Promise.all([
    import("pkijs"),
    import("asn1js"),
    import("pdf-lib-incremental-save"),
    import("pdf-rfc3161/internals"),
    import("pdf-rfc3161"),
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

/// Intègre un jeton d'horodatage RFC 3161 dans un document PDF préparé
/// avec un dictionnaire de signature DocTimeStamp (/SubFilter /ETSI.RFC3161).
function embedTokenInPreparedPdf(prepared, tokenDer) {
  const asn1 = asn1js.fromBER(tokenDer);
  const tsResp = new pkijs.TimeStampResp({ schema: asn1.result });
  const timeStampTokenDer = new Uint8Array(tsResp.timeStampToken.toSchema().toBER(false));

  const tokenHex = bytesToHex(timeStampTokenDer).toUpperCase();
  if (tokenHex.length > prepared.contentsPlaceholderLength) {
    throw new Error(
      `Le jeton d'horodatage (${tokenHex.length} hex) dépasse l'espace réservé (${prepared.contentsPlaceholderLength} hex)`
    );
  }

  const paddedHex = tokenHex.padEnd(prepared.contentsPlaceholderLength, "0");
  const resultPdf = new Uint8Array(prepared.bytes);
  const hexBytes = new TextEncoder().encode(paddedHex);
  resultPdf.set(hexBytes, prepared.contentsOffset);
  return resultPdf;
}

/// Horodatage natif PAdES d'un fichier PDF existant.
async function timestampNativePdf(fileBuf) {
  const prepared = await preparePdfForTimestamp(fileBuf, {
    signatureSize: 8192,
    omitModificationTime: false,
    reason: "Horodatage qualifié RFC 3161 (Open eIDAS)",
    location: "https://open-eidas.eu",
  });
  const bytesToHash = extractBytesToHash(prepared);
  const digestBytes = await sha256(bytesToHash);
  const digestHex = bytesToHex(digestBytes);

  const { token, gen_time } = await requestTimestamp(digestHex);
  const tokenDer = base64ToBuffer(token);

  const v = await verifyToken(tokenDer, digestHex);
  const signedPdfBytes = embedTokenInPreparedPdf(prepared, tokenDer);

  let pdfVerified = false;
  try {
    const verifications = await verifyPdfTimestamps(signedPdfBytes, { trustStore: null });
    pdfVerified = verifications.length > 0 && verifications[0].verified;
  } catch (e) {
    console.warn("Vérification PAdES locale :", e);
  }

  return {
    tokenDer,
    signedPdfBytes,
    digestHex,
    gen_time,
    verification: v,
    pdfVerified,
    isNativePdf: true,
  };
}

/// Génération d'une attestation PDF scellée par horodatage PAdES pour
/// tout document (image, texte, archive, docx, etc.), avec le fichier original
/// et son jeton .tsr attachés en pièces jointes conformes ISO 32000.
async function timestampGenericDocument(fileBuf, fileName, fileSize, mimeType) {
  // 1. Horodatage direct du fichier original
  const digestBytes = await sha256(fileBuf);
  const digestHex = bytesToHex(digestBytes);

  const { token, gen_time } = await requestTimestamp(digestHex);
  const tokenDer = base64ToBuffer(token);
  const v = await verifyToken(tokenDer, digestHex);

  // 2. Création de l'attestation PDF
  const doc = await PDFDocument.create();
  const page = doc.addPage([595.28, 841.89]); // Format A4 standard
  const helvetica = await doc.embedFont(StandardFonts.Helvetica);
  const helveticaBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const courier = await doc.embedFont(StandardFonts.Courier);

  const navy = rgb(15 / 255, 32 / 255, 66 / 255);
  const blue = rgb(0 / 255, 51 / 255, 153 / 255);
  const dark = rgb(15 / 255, 23 / 255, 42 / 255);
  const gray = rgb(100 / 255, 116 / 255, 139 / 255);
  const border = rgb(226 / 255, 232 / 255, 240 / 255);

  // Bandeau supérieur
  page.drawRectangle({
    x: 0,
    y: 841.89 - 100,
    width: 595.28,
    height: 100,
    color: navy,
  });

  page.drawText("Open eIDAS", {
    x: 45,
    y: 841.89 - 46,
    font: helveticaBold,
    size: 22,
    color: rgb(1, 1, 1),
  });

  page.drawText("Attestation d'horodatage qualifie RFC 3161 / eIDAS", {
    x: 45,
    y: 841.89 - 72,
    font: helvetica,
    size: 11,
    color: rgb(226 / 255, 232 / 255, 240 / 255),
  });

  let y = 700;
  function drawSectionTitle(title) {
    page.drawText(title, { x: 45, y, font: helveticaBold, size: 13, color: blue });
    page.drawLine({ start: { x: 45, y: y - 6 }, end: { x: 550, y: y - 6 }, thickness: 1, color: border });
    y -= 26;
  }
  function drawRow(label, value, isCode = false) {
    page.drawText(label, { x: 45, y, font: helveticaBold, size: 9.5, color: gray });
    page.drawText(value, { x: 195, y, font: isCode ? courier : helvetica, size: isCode ? 8.5 : 9.5, color: dark });
    y -= 18;
  }

  drawSectionTitle("1. Document original");
  drawRow("Nom du fichier :", fileName.length > 50 ? fileName.slice(0, 47) + "..." : fileName);
  drawRow("Taille :", `${fileSize.toLocaleString("fr-FR")} octets`);
  drawRow("Algorithme d'empreinte :", "SHA-256");
  drawRow("Empreinte SHA-256 :", digestHex.slice(0, 32), true);
  drawRow("", digestHex.slice(32), true);
  y -= 10;

  drawSectionTitle("2. Jeton d'horodatage qualifie (TSA)");
  drawRow("Date et heure (UTC) :", v.tstInfo.genTime.toISOString());
  drawRow("Autorite (TSU) :", v.signerSubject.length > 55 ? v.signerSubject.slice(0, 52) + "..." : v.signerSubject);
  drawRow("Politique (OID) :", v.tstInfo.policyOid);
  drawRow("Numero de serie :", v.tstInfo.serialHex.slice(0, 32), true);
  drawRow("Signature TSA :", "Valide (RSA/SHA-256)");
  drawRow("Chaine de certification :", "Validee (TSU -> CA -> Racine)");
  y -= 10;

  drawSectionTitle("3. Conservation & Pieces jointes (ISO 32000)");
  page.drawText(
    "Ce document PDF scelle la preuve d'horodatage et incorpore en piece jointe le fichier",
    { x: 45, y, font: helvetica, size: 9.5, color: dark }
  );
  y -= 14;
  page.drawText(
    "original ainsi que son jeton RFC 3161 (.tsr).",
    { x: 45, y, font: helvetica, size: 9.5, color: dark }
  );
  y -= 16;
  page.drawText(
    "Ces fichiers peuvent etre extraits a tout moment depuis le panneau Pieces jointes de votre",
    { x: 45, y, font: helvetica, size: 9, color: gray }
  );
  y -= 14;
  page.drawText(
    "lecteur PDF (Adobe Acrobat Reader, Foxit, DSS, etc.).",
    { x: 45, y, font: helvetica, size: 9, color: gray }
  );
  y -= 32;

  // Intégration du fichier original et du jeton .tsr en pièces jointes PDF
  await doc.attach(fileBuf, fileName, {
    description: "Fichier d'origine horodate",
    mimeType: mimeType || "application/octet-stream",
    creationDate: new Date(),
    modificationDate: new Date(),
  });
  await doc.attach(tokenDer, `${fileName}.tsr`, {
    description: "Jeton d'horodatage RFC 3161 (DER)",
    mimeType: "application/timestamp-reply",
    creationDate: new Date(),
    modificationDate: new Date(),
  });

  // Pied de page
  page.drawLine({ start: { x: 45, y: 55 }, end: { x: 550, y: 55 }, thickness: 0.5, color: border });
  page.drawText("Genere par Open eIDAS (https://open-eidas.eu) — Plateforme de confiance numerique eIDAS", {
    x: 45,
    y: 40,
    font: helvetica,
    size: 8,
    color: gray,
  });

  const attestationPdfBytes = await doc.save();

  // 3. Scellement de l'attestation PDF avec un DocTimeStamp PAdES
  let signedPdfBytes = attestationPdfBytes;
  let pdfVerified = false;
  try {
    const prepared = await preparePdfForTimestamp(attestationPdfBytes, {
      signatureSize: 8192,
      omitModificationTime: false,
      reason: "Horodatage qualifié RFC 3161 (Open eIDAS)",
      location: "https://open-eidas.eu",
    });
    const bytesToHash = extractBytesToHash(prepared);
    const attestDigestHex = bytesToHex(await sha256(bytesToHash));
    const attestResp = await requestTimestamp(attestDigestHex);
    const attestTokenDer = base64ToBuffer(attestResp.token);
    signedPdfBytes = embedTokenInPreparedPdf(prepared, attestTokenDer);

    const verifications = await verifyPdfTimestamps(signedPdfBytes, { trustStore: null });
    pdfVerified = verifications.length > 0 && verifications[0].verified;
  } catch (e) {
    console.warn("Horodatage PAdES de l'attestation PDF :", e);
  }

  return {
    tokenDer,
    signedPdfBytes,
    digestHex,
    gen_time,
    verification: v,
    pdfVerified,
    isNativePdf: false,
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
const downloadPdfBtn = document.getElementById("download-pdf-btn");
const downloadBtn = document.getElementById("download-btn");

function setFile(file) {
  currentFile = file;
  currentDigestHex = null;
  currentTokenDer = null;
  currentSignedPdfBytes = null;
  isCurrentFileNativePdf = false;
  resultBox.classList.remove("visible");
  fileInfo.textContent = file ? `Fichier sélectionné : ${file.name} (${file.size.toLocaleString("fr-FR")} octets)` : "";
  submitBtn.disabled = !file;
  downloadPdfBtn.hidden = true;
  downloadBtn.hidden = true;
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
  downloadPdfBtn.hidden = true;
  downloadBtn.hidden = true;

  try {
    await loadCrypto();

    const fileBuf = await currentFile.arrayBuffer();
    const fileBytes = new Uint8Array(fileBuf);
    const isPdf =
      currentFile.name.toLowerCase().endsWith(".pdf") ||
      currentFile.type === "application/pdf";

    let result;
    if (isPdf) {
      try {
        result = await timestampNativePdf(fileBytes);
      } catch (pdfErr) {
        console.warn("Échec de l'horodatage PDF direct, repli sur l'attestation PDF scellée :", pdfErr);
        result = await timestampGenericDocument(
          fileBytes,
          currentFile.name,
          currentFile.size,
          currentFile.type
        );
      }
    } else {
      result = await timestampGenericDocument(
        fileBytes,
        currentFile.name,
        currentFile.size,
        currentFile.type
      );
    }

    currentDigestHex = result.digestHex;
    currentTokenDer = result.tokenDer;
    currentSignedPdfBytes = result.signedPdfBytes;
    isCurrentFileNativePdf = result.isNativePdf;

    const v = result.verification;

    const rows = [
      ["Fichier", `${currentFile.name} (${currentFile.size.toLocaleString("fr-FR")} octets)`],
    ];

    if (result.isNativePdf) {
      rows.push(
        ["Format", "Document PDF (horodatage natif PAdES / DocTimeStamp)"],
        ["Empreinte signée (ByteRange)", `<code>${result.digestHex}</code>`],
        ["Conformité PAdES (ISO 32000)", result.pdfVerified ? "✔ valide (reconnue nativement par Adobe Reader / Foxit / DSS)" : "✔ horodatage incorporé"]
      );
    } else {
      rows.push(
        ["Empreinte du fichier (SHA-256)", `<code>${result.digestHex}</code>`],
        ["Version PDF générée", "✔ Attestation complète avec fichier original & jeton .tsr intégrés en pièces jointes (scellée PAdES)"]
      );
    }

    rows.push(
      ["Horodaté le", v.tstInfo.genTime.toISOString() + " (déclaré serveur : " + result.gen_time + ")"],
      ["Politique", v.tstInfo.policyOid],
      ["Signataire", v.signerSubject],
      [
        result.isNativePdf ? "Empreinte du jeton = empreinte du PDF signé" : "Empreinte du jeton = empreinte du fichier",
        v.digestMatches ? "✔ oui" : "✖ NON — le jeton ne correspond pas",
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
      ]
    );

    const dl = rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
    const footerNote = result.isNativePdf
      ? "Le document PDF téléchargé contient la signature d'horodatage PAdES intégrée. Ouvrez-le dans Adobe Acrobat Reader ou tout visualiseur conforme pour vérifier le bandeau d'horodatage certifié."
      : "La version PDF téléchargée constitue une attestation officielle d'horodatage eIDAS, scellée par PAdES et contenant votre document d'origine ainsi que le jeton .tsr en pièces jointes.";

    showResult(
      v.allOk,
      `<dl>${dl}</dl><p style="margin-top:0.9rem;color:var(--text-subtle);">${footerNote}</p>`
    );

    downloadPdfBtn.textContent = result.isNativePdf
      ? "Télécharger le PDF horodaté (.pdf)"
      : "Télécharger la version PDF (.pdf)";
    downloadPdfBtn.hidden = false;
    downloadBtn.hidden = false;
  } catch (err) {
    showResult(false, `<p>${err.message || err}</p>`);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Horodater à nouveau";
  }
});

downloadPdfBtn.addEventListener("click", () => {
  if (!currentSignedPdfBytes || !currentFile) return;
  const blob = new Blob([currentSignedPdfBytes], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const baseName = currentFile.name.replace(/\.[^/.]+$/, "");
  a.download = `${baseName}-horodate.pdf`;
  a.click();
  URL.revokeObjectURL(url);
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
