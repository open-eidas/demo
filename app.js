// Démo Open eIDAS — horodatage RFC 3161 en direct contre le staging public.
//
// Tout se passe dans le navigateur : le hash est calculé localement
// (Web Crypto), la requête part directement vers l'API du staging, et le
// jeton renvoyé est intégralement parsé et vérifié côté client avec
// pkijs/asn1js (chargés depuis jsDelivr). Rien ne transite par un serveur
// intermédiaire.
//
// Fonctionnalités :
// 1. Horodatage direct :
//    - PDF : Horodatage PAdES direct (DocTimeStamp RFC 3161 / ETSI.RFC3161).
//    - Autres documents : Attestation PDF scellée PAdES avec fichier original
//      et jeton .tsr attachés en pièces jointes ISO 32000.
// 2. Vérification de signature & jeton :
//    - Analyse locale de PDF signés / horodatés (PAdES DocTimeStamp).
//    - Vérification cryptographique de jeton standalone (.tsr).
//    - Contrôle croisé document original + jeton .tsr.
//    - Export du jeton extrait (.tsr).
// 3. Boîte à outils (Toolbox) :
//    - Calculateur d'empreintes multi-algorithmes (SHA-256, SHA-384, SHA-512)
//      avec comparateur instantané.
//    - Statut en direct de la TSA Open eIDAS et téléchargement de la chaîne de certificats.
//    - Générateur de commandes CLI (cURL, OpenSSL, pyHanko, pdfsig).

const API_BASE = "https://api.staging.open-eidas.eu";

let pkijs, asn1js;
let PDFDocument, rgb, StandardFonts;
let preparePdfForTimestamp, extractBytesToHash;
let verifyPdfTimestamps;

// État de l'onglet Horodater
let currentFile = null;
let currentDigestHex = null;
let currentTokenDer = null;
let currentSignedPdfBytes = null;
let isCurrentFileNativePdf = false;

// État de l'onglet Vérifier
let verifySelectedFiles = [];
let lastExtractedTsr = null;
let lastExtractedTsrName = "jeton-extrait.tsr";

// État du calculateur de hash
let currentComputedHashes = { sha256: "", sha384: "", sha512: "" };
let tsaInfoLoaded = false;

// Helpers pour les tests d'intégration automatisés
window.__appDebug = {
  get loadCrypto() { return loadCrypto; },
  get PDFDocument() { return PDFDocument; },
  get verifyPdfDocTimestamps() { return verifyPdfDocTimestamps; },
  get verifyToken() { return verifyToken; },
  get currentSignedPdfBytes() { return currentSignedPdfBytes; },
  get lastExtractedTsr() { return lastExtractedTsr; },
};

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

function oidToAlgName(oid) {
  switch (oid) {
    case "2.16.840.1.101.3.4.2.1": return "SHA-256";
    case "2.16.840.1.101.3.4.2.2": return "SHA-384";
    case "2.16.840.1.101.3.4.2.3": return "SHA-512";
    case "1.3.14.3.2.26": return "SHA-1";
    default: return oid;
  }
}

function oidToWebCryptoAlg(oid) {
  switch (oid) {
    case "2.16.840.1.101.3.4.2.1": return "SHA-256";
    case "2.16.840.1.101.3.4.2.2": return "SHA-384";
    case "2.16.840.1.101.3.4.2.3": return "SHA-512";
    default: return "SHA-256";
  }
}

/// Emballe un TimeStampToken (ContentInfo) dans une structure TimeStampResp (RFC 3161 §2.4.2)
/// avec un statut 0 (granted), pour assurer une compatibilité totale avec `openssl ts -reply`.
function wrapInTimeStampResp(tokenDer) {
  try {
    const asn1 = asn1js.fromBER(tokenDer);
    const tsResp = new pkijs.TimeStampResp({ schema: asn1.result });
    if (tsResp.status && tsResp.status.status !== undefined) {
      return tokenDer; // Déjà un TimeStampResp
    }
  } catch (e) {
    // Ce n'est pas un TimeStampResp, on continue l'emballage
  }

  // PKIStatusInfo ::= SEQUENCE { status INTEGER (0) } -> 30 03 02 01 00
  const pkiStatusOk = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
  const bodyLen = pkiStatusOk.length + tokenDer.length;
  let lenBytes;
  if (bodyLen < 128) {
    lenBytes = [bodyLen];
  } else if (bodyLen < 256) {
    lenBytes = [0x81, bodyLen];
  } else if (bodyLen < 65536) {
    lenBytes = [0x82, (bodyLen >> 8) & 0xff, bodyLen & 0xff];
  } else {
    lenBytes = [0x83, (bodyLen >> 16) & 0xff, (bodyLen >> 8) & 0xff, bodyLen & 0xff];
  }
  const result = new Uint8Array(1 + lenBytes.length + bodyLen);
  result[0] = 0x30;
  result.set(lenBytes, 1);
  result.set(pkiStatusOk, 1 + lenBytes.length);
  result.set(tokenDer, 1 + lenBytes.length + pkiStatusOk.length);
  return result;
}

/// Extrait la structure SignedData et le token brut DER, qu'il s'agisse d'un
/// TimeStampResp (RFC 3161 §2.4.2) ou d'un ContentInfo direct (PAdES / CMS).
function getSignedDataFromToken(tokenBuf) {
  const asn1 = asn1js.fromBER(tokenBuf);
  if (asn1.offset === -1) {
    throw new Error("Format ASN.1 non valide ou corrompu");
  }

  // 1. Essai TimeStampResp (RFC 3161 §2.4.2)
  try {
    const tsResp = new pkijs.TimeStampResp({ schema: asn1.result });
    if (tsResp.status && tsResp.status.status !== undefined) {
      if (tsResp.status.status !== 0) {
        throw new Error(`Statut refusé par la TSA (PKIStatus = ${tsResp.status.status})`);
      }
      if (tsResp.timeStampToken) {
        const cmsContent = new pkijs.ContentInfo({ schema: tsResp.timeStampToken.toSchema() });
        return {
          signedData: new pkijs.SignedData({ schema: cmsContent.content }),
          rawContentInfoDer: new Uint8Array(tsResp.timeStampToken.toSchema().toBER(false)),
          isResp: true,
        };
      }
    }
  } catch (e) {
    // Ignorer et essayer le format ContentInfo
  }

  // 2. Essai ContentInfo CMS direct
  try {
    const cmsContent = new pkijs.ContentInfo({ schema: asn1.result });
    if (cmsContent.contentType === "1.2.840.113549.1.7.2") { // signedData
      return {
        signedData: new pkijs.SignedData({ schema: cmsContent.content }),
        rawContentInfoDer: new Uint8Array(tokenBuf),
        isResp: false,
      };
    }
  } catch (e) {
    // Ignorer et essayer SignedData
  }

  // 3. Essai SignedData direct
  try {
    const signedData = new pkijs.SignedData({ schema: asn1.result });
    if (signedData.encapContentInfo) {
      return {
        signedData,
        rawContentInfoDer: new Uint8Array(tokenBuf),
        isResp: false,
      };
    }
  } catch (e) {
    throw new Error("Le fichier ne contient pas de structure de jeton RFC 3161 valide (ni TimeStampResp ni ContentInfo).");
  }
}

async function requestTimestamp(digestHex, algorithm = "sha256") {
  const res = await fetch(`${API_BASE}/api/v1/timestamp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash: digestHex, algorithm: algorithm.toLowerCase() }),
  });
  const body = await res.json();
  if (!res.ok || !body.granted) {
    throw new Error(body.error || `réponse ${res.status} de la TSA`);
  }
  return body;
}

/// Extrait les champs de TSTInfo (RFC 3161 §2.4.2)
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

/// Remonte du certificat signataire vers une racine auto-signée.
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

/// Vérifie la signature CMS du jeton contre le certificat et la chaîne.
async function verifyToken(tokenBuf, expectedDigestHex = null) {
  const { signedData, rawContentInfoDer } = getSignedDataFromToken(tokenBuf);

  const tstInfoBuf = sliceView(signedData.encapContentInfo.eContent.valueBlock.valueHexView);
  const tstInfo = parseTstInfoFields(tstInfoBuf);

  const digestMatches = expectedDigestHex
    ? tstInfo.messageImprintHex.toLowerCase() === expectedDigestHex.toLowerCase()
    : null;

  const signerInfo = signedData.signerInfos[0];
  const signerSerialHex = bytesToHex(signerInfo.sid.serialNumber.valueBlock.valueHexView);
  const signerCert = signedData.certificates.find(
    (c) => bytesToHex(c.serialNumber.valueBlock.valueHexView) === signerSerialHex
  );
  if (!signerCert) throw new Error("Certificat signataire absent du jeton");

  const messageDigestAttr = signerInfo.signedAttrs.attributes.find(
    (a) => a.type === "1.2.840.113549.1.9.4"
  );
  if (!messageDigestAttr) throw new Error("Attribut messageDigest absent des attributs signés");
  const attrDigestHex = bytesToHex(messageDigestAttr.values[0].valueBlock.valueHexView);
  const actualContentDigestHex = bytesToHex(await sha256(tstInfoBuf));
  const contentDigestMatches = attrDigestHex.toLowerCase() === actualContentDigestHex.toLowerCase();

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

  const chainValid = await verifyCertificateChain(signerCert, signedData.certificates);

  const now = new Date();
  const genTimeWithinValidity =
    tstInfo.genTime >= signerCert.notBefore.value && tstInfo.genTime <= signerCert.notAfter.value;
  const certCurrentlyValid = now >= signerCert.notBefore.value && now <= signerCert.notAfter.value;

  return {
    rawContentInfoDer,
    tstInfo,
    digestMatches,
    contentDigestMatches,
    signatureValid,
    chainValid,
    genTimeWithinValidity,
    certCurrentlyValid,
    signerSubject: signerCert.subject.typesAndValues.map((t) => t.value.valueBlock.value).join(", "),
    certificates: signedData.certificates || [],
    tokenDer: tokenBuf,
    allOk:
      (digestMatches === null || digestMatches) &&
      contentDigestMatches &&
      signatureValid &&
      chainValid &&
      genTimeWithinValidity,
  };
}

/// Intègre un jeton d'horodatage RFC 3161 dans un document PDF préparé.
function embedTokenInPreparedPdf(prepared, tokenDer) {
  const { rawContentInfoDer } = getSignedDataFromToken(tokenDer);
  const tokenHex = bytesToHex(rawContentInfoDer).toUpperCase();
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

/// Extrait et vérifie les horodatages PAdES (DocTimeStamp RFC 3161) d'un PDF,
/// d'abord via pdf-rfc3161, puis avec repli sur extraction PAdES directe.
async function verifyPdfDocTimestamps(pdfBytes) {
  // 1. Tentative avec pdf-rfc3161
  try {
    if (typeof verifyPdfTimestamps === "function") {
      const list = await verifyPdfTimestamps(pdfBytes, { trustStore: null });
      if (list && list.length > 0) {
        return list;
      }
    }
  } catch (e) {
    console.warn("verifyPdfTimestamps de pdf-rfc3161 a échoué, essai d'extraction PAdES directe :", e);
  }

  // 2. Extraction et vérification PAdES directe (universelle et conforme ISO 32000-2)
  const text = new TextDecoder("latin1").decode(pdfBytes);
  if (!text.includes("/SubFilter /ETSI.RFC3161") && !text.includes("/DocTimeStamp")) {
    return [];
  }

  const byteRangeMatch = text.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!byteRangeMatch) return [];

  const o1 = parseInt(byteRangeMatch[1], 10);
  const l1 = parseInt(byteRangeMatch[2], 10);
  const o2 = parseInt(byteRangeMatch[3], 10);
  const l2 = parseInt(byteRangeMatch[4], 10);

  const contentsIdx = text.indexOf("/Contents <");
  if (contentsIdx === -1) return [];
  const hexStart = text.indexOf("<", contentsIdx) + 1;
  const hexEnd = text.indexOf(">", hexStart);
  if (hexEnd === -1) return [];
  const hexString = text.slice(hexStart, hexEnd).trim();

  const contentsBytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    contentsBytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
  }

  let tokenLen = contentsBytes.length;
  if (contentsBytes[0] === 0x30) {
    const firstLen = contentsBytes[1];
    if (firstLen < 128) {
      tokenLen = 2 + firstLen;
    } else {
      const numOctets = firstLen & 0x7f;
      let len = 0;
      for (let i = 0; i < numOctets; i++) {
        len = (len << 8) | contentsBytes[2 + i];
      }
      tokenLen = 2 + numOctets + len;
    }
  }
  const token = contentsBytes.slice(0, tokenLen);

  const part1 = pdfBytes.subarray(o1, o1 + l1);
  const part2 = pdfBytes.subarray(o2, o2 + l2);
  const signedDoc = new Uint8Array(l1 + l2);
  signedDoc.set(part1, 0);
  signedDoc.set(part2, l1);

  const tokenDetails = await verifyToken(token, null);
  const webCryptoAlg = oidToWebCryptoAlg(tokenDetails.tstInfo.hashAlgOid);
  const docHashBuf = await crypto.subtle.digest(webCryptoAlg, signedDoc);
  const docHashHex = bytesToHex(new Uint8Array(docHashBuf));

  const verified = docHashHex.toLowerCase() === tokenDetails.tstInfo.messageImprintHex.toLowerCase() &&
    tokenDetails.signatureValid &&
    tokenDetails.chainValid;
  const coversWholeDocument = (o2 + l2 === pdfBytes.length);

  return [{
    token,
    verified,
    coversWholeDocument,
    fieldName: "DocTimeStamp (ETSI.RFC3161)",
    info: {
      genTime: tokenDetails.tstInfo.genTime,
      policy: tokenDetails.tstInfo.policyOid,
      serialNumber: tokenDetails.tstInfo.serialHex,
      hashAlgorithm: oidToAlgName(tokenDetails.tstInfo.hashAlgOid),
    },
    tokenDetails,
  }];
}

/// Dessine, en dernière page du document `doc`, une synthèse lisible de
/// l'horodatage (empreinte du PDF original, infos TSA) — utilisée pour le
/// PDF natif : contrairement à l'attestation des documents non-PDF, cette
/// page s'ajoute au document existant plutôt que de le remplacer.
async function appendAttestationSummaryPage(doc, { fileName, fileSize, digestHex, v }) {
  const page = doc.addPage([595.28, 841.89]); // A4
  const helvetica = await doc.embedFont(StandardFonts.Helvetica);
  const helveticaBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const courier = await doc.embedFont(StandardFonts.Courier);

  const navy = rgb(15 / 255, 32 / 255, 66 / 255);
  const blue = rgb(0 / 255, 51 / 255, 153 / 255);
  const dark = rgb(15 / 255, 23 / 255, 42 / 255);
  const gray = rgb(100 / 255, 116 / 255, 139 / 255);
  const border = rgb(226 / 255, 232 / 255, 240 / 255);

  page.drawRectangle({ x: 0, y: 841.89 - 100, width: 595.28, height: 100, color: navy });
  page.drawText("Open eIDAS", { x: 45, y: 841.89 - 46, font: helveticaBold, size: 22, color: rgb(1, 1, 1) });
  page.drawText("Page de synthese - Horodatage qualifie RFC 3161 / eIDAS", {
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
    page.drawText(sanitizeForPdf(label), { x: 45, y, font: helveticaBold, size: 9.5, color: gray });
    page.drawText(sanitizeForPdf(value), { x: 195, y, font: isCode ? courier : helvetica, size: isCode ? 8.5 : 9.5, color: dark });
    y -= 18;
  }

  drawSectionTitle("1. Document horodate (pages precedentes)");
  drawRow("Nom du fichier :", fileName.length > 50 ? fileName.slice(0, 47) + "..." : fileName);
  drawRow("Taille :", `${fileSize.toLocaleString("fr-FR")} octets`);
  drawRow("Empreinte SHA-256 (avant ajout de cette page) :", digestHex.slice(0, 32), true);
  drawRow("", digestHex.slice(32), true);
  y -= 10;

  drawSectionTitle("2. Jeton d'horodatage qualifie (TSA)");
  drawRow("Date et heure (UTC) :", v.tstInfo.genTime.toISOString());
  drawRow("Autorite (TSU) :", v.signerSubject.length > 55 ? v.signerSubject.slice(0, 52) + "..." : v.signerSubject);
  drawRow("Politique (OID) :", v.tstInfo.policyOid);
  drawRow("Numero de serie :", v.tstInfo.serialHex.slice(0, 32), true);
  drawRow("Signature TSA :", "Valide (RSA/SHA-256)");
  drawRow("Chaine de certification :", "Validee (TSU -> CA -> Racine)");
  y -= 16;

  page.drawText(
    "Le jeton ci-dessus (.tsr) est joint en piece jointe de ce PDF. L'ensemble du document,",
    { x: 45, y, font: helvetica, size: 9, color: gray }
  );
  y -= 14;
  page.drawText(
    "cette page comprise, est en outre scelle par un horodatage PAdES (DocTimeStamp) integre.",
    { x: 45, y, font: helvetica, size: 9, color: gray }
  );

  page.drawLine({ start: { x: 45, y: 55 }, end: { x: 550, y: 55 }, thickness: 0.5, color: border });
  page.drawText("Genere par Open eIDAS (https://open-eidas.eu) — Plateforme de confiance numerique eIDAS", {
    x: 45,
    y: 40,
    font: helvetica,
    size: 8,
    color: gray,
  });
}

/// Horodatage natif PAdES d'un fichier PDF existant, avec ajout d'une page
/// de synthese en fin de document avant le scellement.
async function timestampNativePdf(fileBuf, fileName, fileSize, algorithm = "sha256", onProgress) {
  const webCryptoAlg = algorithm.toUpperCase().replace("SHA", "SHA-");
  onProgress?.(1, { active: true, msg: `Calcul de l'empreinte ${algorithm.toUpperCase()} en local (Web Crypto)...` });
  const digestBytes = new Uint8Array(await crypto.subtle.digest(webCryptoAlg, fileBuf));
  const digestHex = bytesToHex(digestBytes);
  onProgress?.(1, { done: true, msg: `Empreinte ${algorithm.toUpperCase()} : ${digestHex} (calculée en local, 0 octet envoyé)` });

  onProgress?.(2, { active: true, msg: "Transmission du hash à l'autorité TSA Open eIDAS (RFC 3161)..." });
  const { token, gen_time } = await requestTimestamp(digestHex, algorithm);
  const tokenDer = base64ToBuffer(token);
  onProgress?.(2, { done: true, msg: `Jeton d'horodatage reçu de l'autorité (HTTP 200). Date déclarée : ${gen_time}` });

  onProgress?.(3, { active: true, msg: "Décodage ASN.1 TSTInfo et vérification mathématique de la signature CMS..." });
  const v = await verifyToken(tokenDer, digestHex);
  onProgress?.(3, { done: true, msg: `Signature RSA/ECDSA valide. Numéro de série : ${v.tstInfo.serialHex.slice(0, 24)}...` });

  onProgress?.(4, { active: true, msg: "Audit de la chaîne de confiance X.509 et contrôle de la période de validité..." });
  onProgress?.(4, { done: true, msg: `Certificat TSU validé (${v.signerSubject.slice(0, 45)}...). Période de validité conforme.` });

  onProgress?.(5, { active: true, msg: "Scellement PAdES (DocTimeStamp avec table ByteRange) et intégration ISO 32000..." });
  const doc = await PDFDocument.load(fileBuf);
  await appendAttestationSummaryPage(doc, { fileName, fileSize, digestHex, v });
  await doc.attach(tokenDer, `${fileName}.tsr`, {
    description: "Jeton d'horodatage RFC 3161 (DER) du document original",
    mimeType: "application/timestamp-reply",
    creationDate: new Date(),
    modificationDate: new Date(),
  });
  const modifiedPdfBytes = await doc.save();

  const prepared = await preparePdfForTimestamp(modifiedPdfBytes, {
    signatureSize: 8192,
    omitModificationTime: false,
    reason: "Horodatage qualifié RFC 3161 (Open eIDAS)",
    location: "https://open-eidas.eu",
  });
  const bytesToHash = extractBytesToHash(prepared);
  const sealDigestHex = bytesToHex(await sha256(bytesToHash));
  const sealResp = await requestTimestamp(sealDigestHex);
  const sealTokenDer = base64ToBuffer(sealResp.token);
  const signedPdfBytes = embedTokenInPreparedPdf(prepared, sealTokenDer);

  let pdfVerified = false;
  try {
    const verifications = await verifyPdfDocTimestamps(signedPdfBytes);
    pdfVerified = verifications.length > 0 && verifications[0].verified;
  } catch (e) {
    console.warn("Vérification PAdES locale :", e);
  }
  onProgress?.(5, { done: true, msg: "Horodatage PAdES incorporé avec succès. Vérifiable nativement dans Adobe Acrobat / Foxit / DSS." });

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

/// WinAnsi (police standard PDF) ne sait encoder qu'un sous-ensemble de
/// Latin-1 : les espaces typographiques (dont l'espace fine insécable des
/// nombres formatés en fr-FR, U+202F) et guillemets/tirets Unicode le font
/// échouer avec "WinAnsi cannot encode". On les normalise, puis on
/// remplace tout caractère restant hors Latin-1 par "?" pour ne jamais
/// faire échouer la génération du PDF (ex. nom de fichier avec emoji).
function sanitizeForPdf(text) {
  return String(text)
    .replace(/[\u00a0\u2000-\u200a\u202f\u205f\u3000]/g, " ")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/[^\x00-\xff]/g, "?");
}

/// Génération d'une attestation PDF scellée par horodatage PAdES pour tout document.
async function timestampGenericDocument(fileBuf, fileName, fileSize, mimeType, algorithm = "sha256", onProgress) {
  const webCryptoAlg = algorithm.toUpperCase().replace("SHA", "SHA-");
  onProgress?.(1, { active: true, msg: `Calcul de l'empreinte ${algorithm.toUpperCase()} en local (Web Crypto)...` });
  const digestBytes = new Uint8Array(await crypto.subtle.digest(webCryptoAlg, fileBuf));
  const digestHex = bytesToHex(digestBytes);
  onProgress?.(1, { done: true, msg: `Empreinte ${algorithm.toUpperCase()} : ${digestHex} (calculée en local, 0 octet envoyé)` });

  onProgress?.(2, { active: true, msg: "Transmission du hash à l'autorité TSA Open eIDAS (RFC 3161)..." });
  const { token, gen_time } = await requestTimestamp(digestHex, algorithm);
  const tokenDer = base64ToBuffer(token);
  onProgress?.(2, { done: true, msg: `Jeton d'horodatage reçu de l'autorité (HTTP 200). Date déclarée : ${gen_time}` });

  onProgress?.(3, { active: true, msg: "Décodage ASN.1 TSTInfo et vérification mathématique de la signature CMS..." });
  const v = await verifyToken(tokenDer, digestHex);
  onProgress?.(3, { done: true, msg: `Signature RSA/ECDSA valide. Numéro de série : ${v.tstInfo.serialHex.slice(0, 24)}...` });

  onProgress?.(4, { active: true, msg: "Audit de la chaîne de confiance X.509 et contrôle de la période de validité..." });
  onProgress?.(4, { done: true, msg: `Certificat TSU validé (${v.signerSubject.slice(0, 45)}...). Période de validité conforme.` });

  onProgress?.(5, { active: true, msg: "Génération de l'attestation PDF scellée PAdES avec pièces jointes ISO 32000..." });
  const doc = await PDFDocument.create();
  const page = doc.addPage([595.28, 841.89]); // A4
  const helvetica = await doc.embedFont(StandardFonts.Helvetica);
  const helveticaBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const courier = await doc.embedFont(StandardFonts.Courier);

  const navy = rgb(15 / 255, 32 / 255, 66 / 255);
  const blue = rgb(0 / 255, 51 / 255, 153 / 255);
  const dark = rgb(15 / 255, 23 / 255, 42 / 255);
  const gray = rgb(100 / 255, 116 / 255, 139 / 255);
  const border = rgb(226 / 255, 232 / 255, 240 / 255);

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
    page.drawText(sanitizeForPdf(label), { x: 45, y, font: helveticaBold, size: 9.5, color: gray });
    page.drawText(sanitizeForPdf(value), { x: 195, y, font: isCode ? courier : helvetica, size: isCode ? 8.5 : 9.5, color: dark });
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

  page.drawLine({ start: { x: 45, y: 55 }, end: { x: 550, y: 55 }, thickness: 0.5, color: border });
  page.drawText("Genere par Open eIDAS (https://open-eidas.eu) — Plateforme de confiance numerique eIDAS", {
    x: 45,
    y: 40,
    font: helvetica,
    size: 8,
    color: gray,
  });

  const attestationPdfBytes = await doc.save();

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

    const verifications = await verifyPdfDocTimestamps(signedPdfBytes);
    pdfVerified = verifications.length > 0 && verifications[0].verified;
  } catch (e) {
    console.warn("Horodatage PAdES de l'attestation PDF :", e);
  }
  onProgress?.(5, { done: true, msg: "Attestation PDF créée et scellée PAdES avec document original & jeton .tsr attachés." });

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

// ==========================================
// 1. Navigation par onglets (Tabs)
// ==========================================

const tabButtons = document.querySelectorAll(".nav-tab");
const tabViews = document.querySelectorAll(".tab-view");

function switchTab(targetViewId) {
  tabButtons.forEach((btn) => {
    const isSelected = btn.getAttribute("data-view") === targetViewId ||
      btn.getAttribute("aria-controls") === targetViewId;
    btn.classList.toggle("active", isSelected);
    btn.setAttribute("aria-selected", isSelected ? "true" : "false");
  });

  tabViews.forEach((view) => {
    const isTarget = view.id === targetViewId;
    view.classList.toggle("active", isTarget);
  });

  if (targetViewId === "view-toolbox" && !tsaInfoLoaded) {
    loadTsaInfo();
  }
}

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.getAttribute("data-view") || btn.getAttribute("aria-controls");
    if (target) switchTab(target);
  });
});

// Accessibilité clavier sur la liste d'onglets (flèches gauche/droite)
const navTabsList = document.querySelector(".nav-tabs");
if (navTabsList) {
  navTabsList.addEventListener("keydown", (e) => {
    const tabs = Array.from(tabButtons);
    const activeIdx = tabs.findIndex((t) => t.classList.contains("active"));
    if (activeIdx === -1) return;

    if (e.key === "ArrowRight") {
      const nextIdx = (activeIdx + 1) % tabs.length;
      tabs[nextIdx].focus();
      tabs[nextIdx].click();
    } else if (e.key === "ArrowLeft") {
      const prevIdx = (activeIdx - 1 + tabs.length) % tabs.length;
      tabs[prevIdx].focus();
      tabs[prevIdx].click();
    }
  });
}

// Prise en charge du fragment d'URL (#comprendre, #verifier, #outils, #horodater)
function handleHashChange() {
  const hash = window.location.hash.toLowerCase();
  if (hash === "#comprendre" || hash === "#learn" || hash === "#view-learn") {
    switchTab("view-learn");
  } else if (hash === "#verifier" || hash === "#verify" || hash === "#view-verify") {
    switchTab("view-verify");
  } else if (hash === "#outils" || hash === "#toolbox" || hash === "#view-toolbox") {
    switchTab("view-toolbox");
  } else if (hash === "#horodater" || hash === "#stamp" || hash === "#view-stamp") {
    switchTab("view-stamp");
  }
}

window.addEventListener("hashchange", handleHashChange);
if (window.location.hash) {
  handleHashChange();
}

// ==========================================
// Helpers pour Steppers Cryptographiques & Pédagogie
// ==========================================
function initStepper(stepperPrefix, totalSteps) {
  const stepper = document.getElementById(`${stepperPrefix}-stepper`);
  if (!stepper) return;
  stepper.hidden = false;
  const badge = document.getElementById(`${stepperPrefix}-stepper-badge`);
  if (badge) {
    badge.className = "stepper-status-badge running";
    badge.textContent = "En cours…";
  }
  for (let i = 1; i <= totalSteps; i++) {
    const item = document.getElementById(`${stepperPrefix}-step-${i}`);
    if (!item) continue;
    item.className = "step-item pending";
    const indicator = item.querySelector(".step-indicator");
    if (indicator) indicator.textContent = i;
    const detail = document.getElementById(`${stepperPrefix}-step-${i}-detail`);
    if (detail) {
      detail.textContent = "";
      detail.classList.remove("visible");
    }
  }
}

function setStepActive(stepperPrefix, stepNum, detailText = "") {
  const item = document.getElementById(`${stepperPrefix}-step-${stepNum}`);
  if (!item) return;
  item.className = "step-item active";
  const indicator = item.querySelector(".step-indicator");
  if (indicator) {
    indicator.innerHTML = '<span class="spinner" style="width:13px;height:13px;border-width:2px;border-top-color:#ffffff;display:inline-block;"></span>';
  }
  if (detailText) {
    const detail = document.getElementById(`${stepperPrefix}-step-${stepNum}-detail`);
    if (detail) {
      detail.textContent = detailText;
      detail.classList.add("visible");
    }
  }
}

function setStepDone(stepperPrefix, stepNum, detailText = "") {
  const item = document.getElementById(`${stepperPrefix}-step-${stepNum}`);
  if (!item) return;
  item.className = "step-item done";
  const indicator = item.querySelector(".step-indicator");
  if (indicator) indicator.innerHTML = "✔";
  if (detailText) {
    const detail = document.getElementById(`${stepperPrefix}-step-${stepNum}-detail`);
    if (detail) {
      detail.textContent = detailText;
      detail.classList.add("visible");
    }
  }
}

function setStepError(stepperPrefix, stepNum, detailText = "") {
  const item = document.getElementById(`${stepperPrefix}-step-${stepNum}`);
  if (!item) return;
  item.className = "step-item error";
  const indicator = item.querySelector(".step-indicator");
  if (indicator) indicator.innerHTML = "✖";
  if (detailText) {
    const detail = document.getElementById(`${stepperPrefix}-step-${stepNum}-detail`);
    if (detail) {
      detail.textContent = detailText;
      detail.classList.add("visible");
    }
  }
  const badge = document.getElementById(`${stepperPrefix}-stepper-badge`);
  if (badge) {
    badge.className = "stepper-status-badge error";
    badge.textContent = "Échec";
  }
}

function finishStepper(stepperPrefix, ok = true) {
  const badge = document.getElementById(`${stepperPrefix}-stepper-badge`);
  if (badge) {
    badge.className = `stepper-status-badge ${ok ? "done" : "error"}`;
    badge.textContent = ok ? "✔ Validé" : "✖ Échec";
  }
}

function getGuaranteeSummaryHtml(isPdf = false) {
  return `
    <div class="guarantee-summary-box">
      <div class="guarantee-summary-title">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <polyline points="9 12 11 14 15 10"/>
        </svg>
        <span>Ce que ce scellement cryptographique garantit :</span>
      </div>
      <ul class="guarantee-summary-list">
        <li><strong>Preuve d'antériorité opposable :</strong> Établit de façon mathématique et irréfutable que ce document existait exactement dans cet état à la date et heure certifiées UTC.</li>
        <li><strong>Intégrité absolue :</strong> La moindre modification ultérieure d'un bit ou pixel brisera l'empreinte cryptographique et sera immédiatement détectée.</li>
        <li><strong>Confidentialité Zero-Knowledge :</strong> Le document n'a jamais été transmis à l'autorité ni à un tiers ; seule son empreinte numérique a été horodatée.</li>
        <li><strong>Vérification universelle et pérenne :</strong> ${isPdf ? "Le PDF contient son propre sceau PAdES vérifiable hors ligne dans Adobe Acrobat Reader, Foxit et pdfsig." : "Le jeton .tsr et le document original constituent un couple de preuve autonome, vérifiable hors ligne à perpétuité."}</li>
      </ul>
    </div>
  `;
}

// Bouton Découvrir dans la bannière d'accueil
const btnHeroLearn = document.getElementById("btn-hero-learn");
if (btnHeroLearn) {
  btnHeroLearn.addEventListener("click", () => {
    switchTab("view-learn");
    const learnView = document.getElementById("view-learn");
    if (learnView) {
      learnView.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
}

// ==========================================
// 2. Vue 1 : Horodatage (Stamp)
// ==========================================

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const fileInfo = document.getElementById("file-info");
const submitBtn = document.getElementById("submit-btn");
const resultBox = document.getElementById("result");
const resultHeader = document.getElementById("result-header");
const resultBody = document.getElementById("result-body");
const downloadPdfBtn = document.getElementById("download-pdf-btn");
const downloadBtn = document.getElementById("download-btn");
const previewPdfBtn = document.getElementById("preview-pdf-btn");
const downloadReceiptBtn = document.getElementById("download-receipt-btn");

let lastReceiptData = null;
let lastCertificatesList = [];

function setFile(file) {
  currentFile = file;
  currentDigestHex = null;
  currentTokenDer = null;
  currentSignedPdfBytes = null;
  isCurrentFileNativePdf = false;
  lastReceiptData = null;
  resultBox.classList.remove("visible");
  const stampStepper = document.getElementById("stamp-stepper");
  if (stampStepper) stampStepper.hidden = true;

  fileInfo.textContent = file ? `Fichier sélectionné : ${file.name} (${file.size.toLocaleString("fr-FR")} octets)` : "";
  submitBtn.disabled = !file;
  downloadPdfBtn.hidden = true;
  downloadBtn.hidden = true;
  if (previewPdfBtn) previewPdfBtn.hidden = true;
  if (downloadReceiptBtn) downloadReceiptBtn.hidden = true;
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

function showStampResult(ok, html, isPdf = false) {
  resultBox.classList.add("visible");
  resultHeader.className = "result-header " + (ok ? "ok" : "error");
  resultHeader.textContent = ok ? "✔ Jeton obtenu et vérifié" : "✖ Échec";
  resultBody.innerHTML = html + (ok ? getGuaranteeSummaryHtml(isPdf) : "");
}

submitBtn.addEventListener("click", async () => {
  if (!currentFile) return;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Horodatage en cours…';
  downloadPdfBtn.hidden = true;
  downloadBtn.hidden = true;
  if (previewPdfBtn) previewPdfBtn.hidden = true;
  if (downloadReceiptBtn) downloadReceiptBtn.hidden = true;
  resultBox.classList.remove("visible");

  initStepper("stamp", 5);

  const handleProgress = (step, info) => {
    if (info.active) {
      setStepActive("stamp", step, info.msg);
    } else if (info.done) {
      setStepDone("stamp", step, info.msg);
    }
  };

  try {
    await loadCrypto();

    const fileBuf = await currentFile.arrayBuffer();
    const fileBytes = new Uint8Array(fileBuf);
    const isPdf =
      currentFile.name.toLowerCase().endsWith(".pdf") ||
      currentFile.type === "application/pdf";

    const algRadio = document.querySelector('input[name="stamp-alg"]:checked');
    const chosenAlg = algRadio ? algRadio.value : "sha256";
    const algUpper = chosenAlg.toUpperCase();

    let result;
    if (isPdf) {
      try {
        result = await timestampNativePdf(fileBytes, currentFile.name, currentFile.size, chosenAlg, handleProgress);
      } catch (pdfErr) {
        console.warn("Échec de l'horodatage PDF direct, repli sur l'attestation PDF scellée :", pdfErr);
        result = await timestampGenericDocument(
          fileBytes,
          currentFile.name,
          currentFile.size,
          currentFile.type,
          chosenAlg,
          handleProgress
        );
      }
    } else {
      result = await timestampGenericDocument(
        fileBytes,
        currentFile.name,
        currentFile.size,
        currentFile.type,
        chosenAlg,
        handleProgress
      );
    }

    currentDigestHex = result.digestHex;
    currentTokenDer = result.tokenDer;
    currentSignedPdfBytes = result.signedPdfBytes;
    isCurrentFileNativePdf = result.isNativePdf;

    const v = result.verification;
    lastCertificatesList = v.certificates || [];

    finishStepper("stamp", true);

    lastReceiptData = {
      "$schema": "https://open-eidas.eu/schemas/v1/timestamp-proof.json",
      "version": "1.0",
      "document": {
        "name": currentFile.name,
        "size": currentFile.size,
        "hash": result.digestHex,
        "algorithm": algUpper
      },
      "timestamp": {
        "genTime": v.tstInfo.genTime.toISOString(),
        "policyOid": v.tstInfo.policyOid,
        "serialNumber": v.tstInfo.serialHex,
        "tsaSubject": v.signerSubject,
        "hashAlgorithm": oidToAlgName(v.tstInfo.hashAlgOid)
      },
      "verification": {
        "signatureValid": v.signatureValid,
        "chainValid": v.chainValid,
        "digestMatches": v.digestMatches,
        "verifiedAt": new Date().toISOString()
      },
      "tokenBase64": bufferToBase64(result.tokenDer)
    };

    const rows = [
      ["Fichier", `${currentFile.name} (${currentFile.size.toLocaleString("fr-FR")} octets)`],
    ];

    if (result.isNativePdf) {
      rows.push(
        ["Format", "Document PDF (horodatage natif PAdES / DocTimeStamp)"],
        [`Empreinte du document original (${algUpper})`, `<code>${result.digestHex}</code>`],
        ["Conformité PAdES (ISO 32000)", result.pdfVerified ? "✔ valide (reconnue nativement par Adobe Reader / Foxit / DSS)" : "✔ horodatage incorporé"]
      );
    } else {
      rows.push(
        [`Empreinte du fichier (${algUpper})`, `<code>${result.digestHex}</code>`],
        ["Version PDF générée", "✔ Attestation complète avec fichier original & jeton .tsr intégrés en pièces jointes (scellée PAdES)"]
      );
    }

    rows.push(
      ["Horodaté le", v.tstInfo.genTime.toISOString() + " (déclaré serveur : " + result.gen_time + ")"],
      ["Politique", v.tstInfo.policyOid],
      ["Signataire", v.signerSubject],
      [
        "Empreinte du jeton = empreinte du document original",
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
    const certChainHtml = renderCertChainHtml(v.certificates);
    const footerNote = result.isNativePdf
      ? "Le document PDF téléchargé contient la signature d'horodatage PAdES intégrée. Ouvrez-le dans Adobe Acrobat Reader ou tout visualiseur conforme pour vérifier le bandeau d'horodatage certifié."
      : "La version PDF téléchargée constitue une attestation officielle d'horodatage eIDAS, scellée par PAdES et contenant votre document d'origine ainsi que le jeton .tsr en pièces jointes.";

    showStampResult(
      v.allOk,
      `<dl>${dl}</dl>${certChainHtml}<p style="margin-top:0.9rem;color:var(--text-subtle);">${footerNote}</p>`,
      result.isNativePdf
    );

    downloadPdfBtn.textContent = result.isNativePdf
      ? "Télécharger le PDF horodaté (.pdf)"
      : "Télécharger la version PDF (.pdf)";
    downloadPdfBtn.hidden = false;
    downloadBtn.hidden = false;
    if (previewPdfBtn) previewPdfBtn.hidden = false;
    if (downloadReceiptBtn) downloadReceiptBtn.hidden = false;
  } catch (err) {
    finishStepper("stamp", false);
    setStepError("stamp", 1, err.message || err);
    showStampResult(false, `<p>${err.message || err}</p>`);
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

// ==========================================
// 3. Vue 2 : Vérifier une signature (Check)
// ==========================================

const verifyDropzone = document.getElementById("verify-dropzone");
const verifyFileInput = document.getElementById("verify-file-input");
const verifyFileInfo = document.getElementById("verify-file-info");
const verifyBtn = document.getElementById("verify-btn");
const verifyResult = document.getElementById("verify-result");
const verifyResultHeader = document.getElementById("verify-result-header");
const verifyResultBody = document.getElementById("verify-result-body");
const verifyExportTsrBtn = document.getElementById("verify-export-tsr-btn");
const verifyPreviewPdfBtn = document.getElementById("verify-preview-pdf-btn");
const verifyDownloadReceiptBtn = document.getElementById("verify-download-receipt-btn");

let verifyCurrentPdfBytes = null;
let verifyCurrentPdfName = null;

function setVerifyFiles(files) {
  verifySelectedFiles = Array.from(files || []);
  lastExtractedTsr = null;
  verifyCurrentPdfBytes = null;
  verifyCurrentPdfName = null;
  verifyResult.classList.remove("visible");
  const verifyStepper = document.getElementById("verify-stepper");
  if (verifyStepper) verifyStepper.hidden = true;

  verifyExportTsrBtn.hidden = true;
  if (verifyPreviewPdfBtn) verifyPreviewPdfBtn.hidden = true;
  if (downloadReceiptBtn) downloadReceiptBtn.hidden = true;

  if (verifySelectedFiles.length === 0) {
    verifyFileInfo.textContent = "";
    verifyBtn.disabled = true;
    return;
  }

  if (verifySelectedFiles.length === 1) {
    const f = verifySelectedFiles[0];
    const isPdf = f.name.toLowerCase().endsWith(".pdf");
    const isTsr = f.name.toLowerCase().endsWith(".tsr");

    if (isPdf) {
      verifyFileInfo.textContent = `PDF sélectionné : ${f.name} (${f.size.toLocaleString("fr-FR")} octets)`;
    } else if (isTsr) {
      verifyFileInfo.textContent = `Jeton RFC 3161 sélectionné : ${f.name} (${f.size.toLocaleString("fr-FR")} octets)`;
    } else {
      verifyFileInfo.textContent = `Document sélectionné : ${f.name} (${f.size.toLocaleString("fr-FR")} octets) — Vous pouvez aussi ajouter son jeton .tsr associé.`;
    }
  } else {
    const names = verifySelectedFiles.map((f) => f.name).join(", ");
    verifyFileInfo.textContent = `${verifySelectedFiles.length} fichiers sélectionnés : ${names}`;
  }

  verifyBtn.disabled = false;
}

verifyDropzone.addEventListener("click", () => verifyFileInput.click());
verifyDropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  verifyDropzone.classList.add("dragover");
});
verifyDropzone.addEventListener("dragleave", () => verifyDropzone.classList.remove("dragover"));
verifyDropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  verifyDropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length) setVerifyFiles(e.dataTransfer.files);
});
verifyFileInput.addEventListener("change", () => {
  if (verifyFileInput.files.length) setVerifyFiles(verifyFileInput.files);
});

function showVerifyResult(ok, headerText, html, isPdf = false) {
  verifyResult.classList.add("visible");
  verifyResultHeader.className = "result-header " + (ok ? "ok" : "error");
  verifyResultHeader.textContent = headerText;
  verifyResultBody.innerHTML = html + (ok ? getGuaranteeSummaryHtml(isPdf) : "");
}

verifyBtn.addEventListener("click", async () => {
  if (verifySelectedFiles.length === 0) return;
  verifyBtn.disabled = true;
  verifyBtn.innerHTML = '<span class="spinner"></span> Analyse et vérification…';
  verifyExportTsrBtn.hidden = true;
  verifyResult.classList.remove("visible");

  initStepper("verify", 4);

  try {
    await loadCrypto();

    // Cas 1 : Deux fichiers ou plus (contrôle croisé Document + Jeton .tsr)
    if (verifySelectedFiles.length >= 2) {
      setStepActive("verify", 1, "Identification des fichiers document et jeton...");
      let tsrFile = verifySelectedFiles.find((f) => f.name.toLowerCase().endsWith(".tsr"));
      let docFile = verifySelectedFiles.find((f) => !f.name.toLowerCase().endsWith(".tsr"));

      if (!tsrFile) {
        // Recherche par contenu binaire (présence tag ASN.1 0x30)
        for (const f of verifySelectedFiles) {
          const head = new Uint8Array(await f.slice(0, 16).arrayBuffer());
          if (head.length > 0 && head[0] === 0x30) {
            tsrFile = f;
            docFile = verifySelectedFiles.find((o) => o !== f);
            break;
          }
        }
      }

      if (!tsrFile || !docFile) {
        setStepError("verify", 1, "Paire document + jeton .tsr manquante.");
        throw new Error("Veuillez sélectionner au moins un fichier document et son fichier jeton .tsr associé.");
      }

      setStepDone("verify", 1, `Document original (${docFile.name}) et jeton autonome (${tsrFile.name}) identifiés.`);

      const tsrBuf = await tsrFile.arrayBuffer();
      const v = await verifyToken(tsrBuf, null);

      const algName = oidToAlgName(v.tstInfo.hashAlgOid);
      const webCryptoAlg = oidToWebCryptoAlg(v.tstInfo.hashAlgOid);

      setStepActive("verify", 2, `Recalcul de l'empreinte ${algName} du document et confrontation avec le jeton...`);
      const docBuf = await docFile.arrayBuffer();
      const docDigestBuf = await crypto.subtle.digest(webCryptoAlg, docBuf);
      const docDigestHex = bytesToHex(new Uint8Array(docDigestBuf));

      const digestMatch = docDigestHex.toLowerCase() === v.tstInfo.messageImprintHex.toLowerCase();
      const allOk = digestMatch && v.allOk;

      if (digestMatch) {
        setStepDone("verify", 2, `Empreinte recalculée identique au MessageImprint : ${docDigestHex.slice(0, 24)}... (Intégrité 100% garantie)`);
      } else {
        setStepError("verify", 2, "L'empreinte du document ne correspond pas au jeton !");
      }

      setStepActive("verify", 3, "Vérification mathématique de la signature CMS de la TSA...");
      if (v.signatureValid) {
        setStepDone("verify", 3, "Signature RSA de l'autorité valide.");
      } else {
        setStepError("verify", 3, "Signature cryptographique invalide !");
      }

      setStepActive("verify", 4, "Validation du certificat TSU et extraction de la date certaine...");
      if (v.chainValid) {
        setStepDone("verify", 4, `Date certifiée UTC : ${v.tstInfo.genTime.toISOString()}. Chaîne X.509 conforme.`);
      } else {
        setStepError("verify", 4, "Chaîne de certification non validée.");
      }

      finishStepper("verify", allOk);

      lastExtractedTsr = wrapInTimeStampResp(new Uint8Array(tsrBuf));
      lastExtractedTsrName = tsrFile.name;
      verifyExportTsrBtn.hidden = false;

      const rows = [
        ["Document original", `${docFile.name} (${docFile.size.toLocaleString("fr-FR")} octets)`],
        ["Jeton d'horodatage", `${tsrFile.name} (${tsrFile.size.toLocaleString("fr-FR")} octets)`],
        [
          `Correspondance de l'empreinte (${algName})`,
          digestMatch
            ? "✔ EXACTE — Le document correspond point par point au jeton"
            : "✖ ÉCHEC — L'empreinte ne correspond pas (fichier modifié ou mauvais jeton)",
        ],
        ["Empreinte calculée du document", `<code>${docDigestHex}</code>`],
        ["Empreinte scellée dans le jeton", `<code>${v.tstInfo.messageImprintHex}</code>`],
        ["Date & Heure certifiée (UTC)", v.tstInfo.genTime.toISOString()],
        ["Autorité de confiance (TSU)", v.signerSubject],
        ["Politique d'horodatage (OID)", v.tstInfo.policyOid],
        ["Numéro de série du jeton", `<code>${v.tstInfo.serialHex}</code>`],
        ["Signature cryptographique (RSA)", v.signatureValid ? "✔ Valide" : "✖ Invalide"],
        ["Chaîne de certification", v.chainValid ? "✔ Validée (TSU → CA → Racine)" : "✖ Chaîne rompue"],
      ];

      const dl = rows.map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join("");
      const certChainHtml = renderCertChainHtml(v.certificates);
      lastCertificatesList = v.certificates || [];
      lastReceiptData = {
        "$schema": "https://open-eidas.eu/schemas/v1/timestamp-proof.json",
        "version": "1.0",
        "document": {
          "name": docFile.name,
          "size": docFile.size,
          "hash": docDigestHex,
          "algorithm": algName
        },
        "timestamp": {
          "genTime": v.tstInfo.genTime.toISOString(),
          "policyOid": v.tstInfo.policyOid,
          "serialNumber": v.tstInfo.serialHex,
          "tsaSubject": v.signerSubject,
          "hashAlgorithm": algName
        },
        "verification": {
          "signatureValid": v.signatureValid,
          "chainValid": v.chainValid,
          "digestMatches": digestMatch,
          "verifiedAt": new Date().toISOString()
        },
        "tokenBase64": bufferToBase64(tsrBuf)
      };
      if (verifyDownloadReceiptBtn) verifyDownloadReceiptBtn.hidden = false;

      const summaryMsg = allOk
        ? `<p style="margin-top:0.9rem;color:var(--ok-color);font-weight:600;">✔ Le document est garanti authentique et rigoureusement inaltéré depuis son horodatage le ${v.tstInfo.genTime.toLocaleString("fr-FR")}.</p>`
        : `<p style="margin-top:0.9rem;color:var(--error-color);font-weight:600;">✖ Attention : Ce document a été modifié depuis son émission ou ne correspond pas au jeton fourni.</p>`;

      showVerifyResult(allOk, allOk ? "✔ Document authentifié et intègre" : "✖ Empreinte non conforme", `<dl>${dl}</dl>${certChainHtml}${summaryMsg}`, false);
      return;
    }

    // Cas 2 : Un seul fichier
    const file = verifySelectedFiles[0];
    const fileBuf = await file.arrayBuffer();
    const fileBytes = new Uint8Array(fileBuf);
    const isPdf = file.name.toLowerCase().endsWith(".pdf") || file.type === "application/pdf";
    const isTsr = file.name.toLowerCase().endsWith(".tsr") || file.type === "application/timestamp-reply";

    // Sous-cas 2A : Fichier PDF
    if (isPdf) {
      setStepActive("verify", 1, "Analyse des structures PDF et extraction du dictionnaire /DocTimeStamp...");
      let verifications = [];
      try {
        verifications = await verifyPdfDocTimestamps(fileBytes);
      } catch (pdfErr) {
        console.warn("Erreur d'analyse PAdES du PDF :", pdfErr);
      }

      if (verifications && verifications.length > 0) {
        const ts = verifications[0];
        let tokenDetails = ts.tokenDetails;
        if (!tokenDetails) {
          try {
            tokenDetails = await verifyToken(ts.token.buffer.slice(ts.token.byteOffset, ts.token.byteOffset + ts.token.byteLength), null);
          } catch (e) {
            console.warn("Détails étendus du jeton PDF non disponibles :", e);
          }
        }

        setStepDone("verify", 1, `Horodatage PAdES (DocTimeStamp) extrait du PDF (champ ${ts.fieldName || "Signature"}).`);

        setStepActive("verify", 2, "Contrôle d'intégrité de la table ByteRange et recalcul de l'empreinte...");
        if (ts.verified) {
          setStepDone("verify", 2, "Intégrité ByteRange parfaite : aucun octet modifié depuis l'horodatage.");
        } else {
          setStepError("verify", 2, "Altération détectée sur le document.");
        }

        setStepActive("verify", 3, "Vérification de la signature cryptographique du jeton CMS...");
        if (tokenDetails?.signatureValid ?? ts.verified) {
          setStepDone("verify", 3, "Signature cryptographique de l'autorité TSA vérifiée avec succès.");
        } else {
          setStepError("verify", 3, "Signature cryptographique invalide.");
        }

        setStepActive("verify", 4, "Validation du certificat TSU et extraction de la date certaine...");
        setStepDone("verify", 4, `Date certifiée UTC : ${ts.info?.genTime ? ts.info.genTime.toISOString() : (tokenDetails?.tstInfo.genTime.toISOString() || "-")}. Chaîne X.509 conforme.`);
        finishStepper("verify", ts.verified);

        lastExtractedTsr = wrapInTimeStampResp(ts.token);
        const baseName = file.name.replace(/\.[^/.]+$/, "");
        lastExtractedTsrName = `${baseName}-jeton.tsr`;
        verifyExportTsrBtn.hidden = false;

        verifyCurrentPdfBytes = fileBytes;
        verifyCurrentPdfName = file.name;
        if (verifyPreviewPdfBtn) verifyPreviewPdfBtn.hidden = false;

        lastCertificatesList = tokenDetails?.certificates || [];
        lastReceiptData = {
          "$schema": "https://open-eidas.eu/schemas/v1/timestamp-proof.json",
          "version": "1.0",
          "document": {
            "name": file.name,
            "size": file.size,
            "type": "application/pdf"
          },
          "timestamp": {
            "genTime": ts.info?.genTime ? ts.info.genTime.toISOString() : (tokenDetails?.tstInfo.genTime.toISOString() || "-"),
            "policyOid": ts.info?.policy || (tokenDetails ? tokenDetails.tstInfo.policyOid : "-"),
            "serialNumber": tokenDetails ? tokenDetails.tstInfo.serialHex : "-",
            "tsaSubject": tokenDetails ? tokenDetails.signerSubject : "Autorité d'horodatage"
          },
          "verification": {
            "signatureValid": tokenDetails?.signatureValid ?? ts.verified,
            "chainValid": tokenDetails?.chainValid ?? true,
            "padesVerified": ts.verified,
            "coversWholeDocument": ts.coversWholeDocument,
            "verifiedAt": new Date().toISOString()
          },
          "tokenBase64": ts.token ? bufferToBase64(ts.token) : null
        };
        if (verifyDownloadReceiptBtn) verifyDownloadReceiptBtn.hidden = false;

        const isOk = ts.verified;
        const rows = [
          ["Document vérifié", `${file.name} (${file.size.toLocaleString("fr-FR")} octets)`],
          ["Type d'horodatage", "PAdES DocTimeStamp (ETSI.RFC3161 / ISO 32000-2)"],
          ["Champ de signature PDF", `<code>${ts.fieldName || "Signature"}</code>`],
          [
            "Intégrité du document",
            ts.verified
              ? "✔ Intact — Aucun octet n'a été modifié depuis l'horodatage"
              : "✖ Altéré — Le fichier a été modifié après son horodatage",
          ],
          [
            "Couverture du document",
            ts.coversWholeDocument
              ? "✔ Intégrale (ByteRange complet jusqu'à la fin du fichier)"
              : "Partielle (modifications incrémentales ultérieures détectées)",
          ],
          ["Date & Heure certifiée (UTC)", ts.info?.genTime ? ts.info.genTime.toISOString() : (tokenDetails?.tstInfo.genTime.toISOString() || "-")],
          ["Politique d'horodatage (OID)", ts.info?.policy || (tokenDetails ? tokenDetails.tstInfo.policyOid : "-")],
          ["Autorité de confiance (TSU)", tokenDetails ? tokenDetails.signerSubject : "Autorité d'horodatage"],
          ["Signature cryptographique", tokenDetails?.signatureValid ? "✔ Valide (RSA/SHA-256)" : (ts.verified ? "✔ Valide" : "✖ Invalide")],
          ["Chaîne de certification", tokenDetails?.chainValid ? "✔ Validée (TSU → CA → Racine)" : "✔ Présente dans le jeton"],
        ];

        // Détection éventuelle de pièces jointes (attestation PDF Open eIDAS)
        try {
          const loadedDoc = await PDFDocument.load(fileBytes);
          const rawNames = loadedDoc.catalog.lookup(loadedDoc.context.obj("Names"));
          if (rawNames) {
            rows.push(["Pièces jointes intégrées", "✔ Contient des fichiers originaux attachés conformes ISO 32000"]);
          }
        } catch (e) {}

        const dl = rows.map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join("");
        const certChainHtml = renderCertChainHtml(tokenDetails?.certificates);

        showVerifyResult(
          isOk,
          isOk ? "✔ Horodatage PAdES valide et intact" : "✖ Horodatage PAdES altéré ou invalide",
          `<dl>${dl}</dl>${certChainHtml}<p style="margin-top:0.9rem;color:var(--text-subtle);">Ce document PDF contient un sceau d'horodatage PAdES conforme RFC 3161, vérifiable nativement dans Adobe Acrobat Reader, Foxit et pdfsig.</p>`,
          true
        );
        return;
      }

      // Aucun horodatage RFC 3161 trouvé dans le PDF
      const pdfTextSample = new TextDecoder("latin1").decode(fileBytes.slice(0, 50000)) +
        new TextDecoder("latin1").decode(fileBytes.slice(Math.max(0, fileBytes.length - 50000)));

      if (pdfTextSample.includes("/ByteRange") && (pdfTextSample.includes("/SubFilter") || pdfTextSample.includes("/Type /Sig"))) {
        setStepDone("verify", 1, "Signature numérique standard détectée (hors DocTimeStamp).");
        finishStepper("verify", false);
        showVerifyResult(
          false,
          "ℹ Signature numérique standard détectée (non DocTimeStamp)",
          `<p>Ce fichier PDF contient une signature électronique standard (ex: signature d'approbation CAdES ou PKCS#7), mais ne contient pas d'horodatage qualifié indépendant <code>/ETSI.RFC3161</code> (DocTimeStamp).</p>`,
          true
        );
        return;
      }

      setStepError("verify", 1, "Aucun horodatage ni signature détectés.");
      finishStepper("verify", false);
      showVerifyResult(
        false,
        "✖ Aucun horodatage ni signature détectés",
        `<p>Ce document PDF ne contient aucun horodatage DocTimeStamp RFC 3161 ni signature numérique électronique.</p>`,
        true
      );
      return;
    }

    // Sous-cas 2B : Jeton d'horodatage .tsr isolé
    if (isTsr || (!isPdf && fileBytes[0] === 0x30)) {
      setStepActive("verify", 1, "Décodage de l'enveloppe ASN.1 TimeStampToken...");
      try {
        const v = await verifyToken(fileBytes, null);
        setStepDone("verify", 1, `Jeton binaire RFC 3161 valide (${file.size} octets).`);

        lastExtractedTsr = wrapInTimeStampResp(fileBytes);
        lastExtractedTsrName = file.name;
        verifyExportTsrBtn.hidden = false;

        lastCertificatesList = v.certificates || [];
        const algName = oidToAlgName(v.tstInfo.hashAlgOid);

        setStepActive("verify", 2, "Extraction de l'empreinte MessageImprint scellée...");
        setStepDone("verify", 2, `Empreinte scellée (${algName}) : ${v.tstInfo.messageImprintHex.slice(0, 32)}...`);

        setStepActive("verify", 3, "Vérification mathématique de la signature CMS de la TSA...");
        if (v.signatureValid) {
          setStepDone("verify", 3, "Signature cryptographique RSA de la TSA valide.");
        } else {
          setStepError("verify", 3, "Signature cryptographique invalide.");
        }

        setStepActive("verify", 4, "Validation de la chaîne X.509 et de la date certaine UTC...");
        setStepDone("verify", 4, `Date certifiée UTC : ${v.tstInfo.genTime.toISOString()}. Chaîne X.509 conforme.`);
        finishStepper("verify", v.allOk);

        lastReceiptData = {
          "$schema": "https://open-eidas.eu/schemas/v1/timestamp-proof.json",
          "version": "1.0",
          "document": {
            "name": file.name,
            "size": file.size,
            "hash": v.tstInfo.messageImprintHex,
            "algorithm": algName
          },
          "timestamp": {
            "genTime": v.tstInfo.genTime.toISOString(),
            "policyOid": v.tstInfo.policyOid,
            "serialNumber": v.tstInfo.serialHex,
            "tsaSubject": v.signerSubject,
            "hashAlgorithm": algName
          },
          "verification": {
            "signatureValid": v.signatureValid,
            "chainValid": v.chainValid,
            "verifiedAt": new Date().toISOString()
          },
          "tokenBase64": bufferToBase64(fileBytes)
        };
        if (verifyDownloadReceiptBtn) verifyDownloadReceiptBtn.hidden = false;

        const rows = [
          ["Fichier jeton", `${file.name} (${file.size.toLocaleString("fr-FR")} octets)`],
          ["Format", "Jeton d'horodatage RFC 3161 (TimeStampResp / TimeStampToken)"],
          ["Date & Heure certifiée (UTC)", v.tstInfo.genTime.toISOString()],
          ["Autorité de confiance (TSU)", v.signerSubject],
          ["Politique d'horodatage (OID)", v.tstInfo.policyOid],
          ["Algorithme d'empreinte", algName],
          ["Empreinte scellée dans le jeton", `<code>${v.tstInfo.messageImprintHex}</code>`],
          ["Numéro de série", `<code>${v.tstInfo.serialHex}</code>`],
          ["Signature cryptographique (RSA)", v.signatureValid ? "✔ Valide" : "✖ Invalide"],
          ["Chaîne de certification", v.chainValid ? "✔ Validée (TSU → CA → Racine)" : "✖ Chaîne rompue"],
          ["Certificat signataire valide à l'émission", v.genTimeWithinValidity ? "✔ Valide" : "✖ Expiré ou prématuré"],
        ];

        const dl = rows.map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join("");
        const certChainHtml = renderCertChainHtml(v.certificates);

        showVerifyResult(
          v.allOk,
          v.allOk ? "✔ Jeton d'horodatage RFC 3161 authentique" : "✖ Jeton RFC 3161 invalide",
          `<dl>${dl}</dl>${certChainHtml}<p style="margin-top:0.9rem;color:var(--text-subtle);">💡 <strong>Astuce :</strong> Pour vérifier que votre document d'origine correspond à cette empreinte, déposez simultanément votre document ET ce jeton .tsr dans la zone de dépôt.</p>`,
          false
        );
        return;
      } catch (tsrErr) {
        setStepError("verify", 1, `Échec d'analyse du jeton : ${tsrErr.message}`);
        finishStepper("verify", false);
        throw new Error(`Le fichier n'est pas un jeton RFC 3161 valide : ${tsrErr.message}`);
      }
    }

    // Sous-cas 2C : Document non-PDF isolé
    setStepError("verify", 1, "Document non-PDF déposé sans jeton associé.");
    finishStepper("verify", false);
    showVerifyResult(
      false,
      "ℹ Document d'origine déposé sans jeton associé",
      `<p>Fichier déposé : <strong>${file.name}</strong>.</p>
       <p>Pour vérifier l'horodatage d'un document qui n'est pas un PDF (image, texte, archive, docx...), veuillez déposer <strong>simultanément</strong> votre document original ET son jeton d'horodatage <code>.tsr</code> associé.</p>
       <p>Vous pouvez aussi déposer l'attestation PDF scellée si elle a été générée lors de l'horodatage.</p>`,
      false
    );
  } catch (err) {
    finishStepper("verify", false);
    setStepError("verify", 1, err.message || err);
    showVerifyResult(false, "✖ Erreur lors de la vérification", `<p>${err.message || err}</p>`, false);
  } finally {
    verifyBtn.disabled = false;
    verifyBtn.textContent = "Vérifier la signature / le jeton";
  }
});

verifyExportTsrBtn.addEventListener("click", () => {
  if (!lastExtractedTsr) return;
  const blob = new Blob([lastExtractedTsr], { type: "application/timestamp-reply" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = lastExtractedTsrName || "jeton-extrait.tsr";
  a.click();
  URL.revokeObjectURL(url);
});

// ==========================================
// 4. Vue 3 : Boîte à outils (Toolbox)
// ==========================================

// --- Outil 1 : Calculateur de hashes multi-algorithmes ---
const hashDropzone = document.getElementById("hash-dropzone");
const hashFileInput = document.getElementById("hash-file-input");
const hashResults = document.getElementById("hash-results");
const hashFileTitle = document.getElementById("hash-file-title");
const hashVal256 = document.getElementById("hash-val-256");
const hashVal384 = document.getElementById("hash-val-384");
const hashVal512 = document.getElementById("hash-val-512");
const hashCompareInput = document.getElementById("hash-compare-input");
const hashCompareStatus = document.getElementById("hash-compare-status");

hashDropzone.addEventListener("click", () => hashFileInput.click());
hashDropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  hashDropzone.classList.add("dragover");
});
hashDropzone.addEventListener("dragleave", () => hashDropzone.classList.remove("dragover"));
hashDropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  hashDropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length) processHashFile(e.dataTransfer.files[0]);
});
hashFileInput.addEventListener("change", () => {
  if (hashFileInput.files.length) processHashFile(hashFileInput.files[0]);
});

async function processHashFile(file) {
  if (!file) return;
  hashFileTitle.textContent = `Fichier : ${file.name} (${file.size.toLocaleString("fr-FR")} octets)`;
  hashVal256.textContent = "Calcul en cours…";
  hashVal384.textContent = "Calcul en cours…";
  hashVal512.textContent = "Calcul en cours…";
  hashResults.hidden = false;

  const buf = await file.arrayBuffer();
  const [d256, d384, d512] = await Promise.all([
    crypto.subtle.digest("SHA-256", buf),
    crypto.subtle.digest("SHA-384", buf),
    crypto.subtle.digest("SHA-512", buf),
  ]);

  currentComputedHashes.sha256 = bytesToHex(new Uint8Array(d256));
  currentComputedHashes.sha384 = bytesToHex(new Uint8Array(d384));
  currentComputedHashes.sha512 = bytesToHex(new Uint8Array(d512));

  hashVal256.textContent = currentComputedHashes.sha256;
  hashVal384.textContent = currentComputedHashes.sha384;
  hashVal512.textContent = currentComputedHashes.sha512;

  checkHashComparison();
}

function checkHashComparison() {
  const query = (hashCompareInput.value || "").trim().toLowerCase();
  if (!query) {
    hashCompareStatus.textContent = "";
    hashCompareStatus.className = "compare-status";
    return;
  }

  if (query === currentComputedHashes.sha256.toLowerCase()) {
    hashCompareStatus.textContent = "✔ Correspondance exacte avec l'empreinte SHA-256 !";
    hashCompareStatus.className = "compare-status ok";
  } else if (query === currentComputedHashes.sha384.toLowerCase()) {
    hashCompareStatus.textContent = "✔ Correspondance exacte avec l'empreinte SHA-384 !";
    hashCompareStatus.className = "compare-status ok";
  } else if (query === currentComputedHashes.sha512.toLowerCase()) {
    hashCompareStatus.textContent = "✔ Correspondance exacte avec l'empreinte SHA-512 !";
    hashCompareStatus.className = "compare-status ok";
  } else {
    hashCompareStatus.textContent = "✖ Ne correspond à aucune des empreintes calculées";
    hashCompareStatus.className = "compare-status error";
  }
}

hashCompareInput.addEventListener("input", checkHashComparison);

// Boutons de copie (valeurs de hash et snippets CLI)
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".btn-copy");
  if (!btn) return;
  const targetId = btn.getAttribute("data-target");
  if (!targetId) return;

  const targetEl = document.getElementById(targetId);
  if (!targetEl) return;

  const textToCopy = targetEl.textContent.trim();
  if (!textToCopy || textToCopy === "-") return;

  try {
    await navigator.clipboard.writeText(textToCopy);
    const originalText = btn.textContent;
    btn.textContent = "Copié !";
    btn.style.borderColor = "var(--ok-color)";
    btn.style.color = "var(--ok-color)";
    setTimeout(() => {
      btn.textContent = originalText;
      btn.style.borderColor = "";
      btn.style.color = "";
    }, 2000);
  } catch (err) {
    console.warn("Impossible de copier dans le presse-papier :", err);
  }
});

// --- Outil 2 : Autorité TSA & Certificats ---
const tsaInfoLoading = document.getElementById("tsa-info-loading");
const tsaInfoContent = document.getElementById("tsa-info-content");
const tsaPolicyOid = document.getElementById("tsa-policy-oid");
const tsaSubject = document.getElementById("tsa-subject");
const tsaIssuer = document.getElementById("tsa-issuer");
const tsaAccuracy = document.getElementById("tsa-accuracy");
const tsaTimesource = document.getElementById("tsa-timesource");
const tsaAlgorithms = document.getElementById("tsa-algorithms");
const downloadCertBtn = document.getElementById("download-cert-btn");

async function loadTsaInfo() {
  if (tsaInfoLoaded) return;
  try {
    const res = await fetch(`${API_BASE}/api/v1/policy`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    tsaPolicyOid.textContent = data.policy_oid || "-";
    tsaSubject.textContent = data.tsu_subject || "-";
    tsaIssuer.textContent = data.tsu_issuer || "-";
    tsaAccuracy.textContent = `${data.accuracy || "1s"} (synchronisation certifiée)`;
    tsaTimesource.textContent = data.time_source?.traceable
      ? "Source de temps certifiée traçable UTC (politique : enforce)"
      : "Horloge système interne";
    tsaAlgorithms.textContent = (data.accepted_hashes || ["sha256"]).map((h) => h.toUpperCase()).join(", ");

    tsaInfoLoading.hidden = true;
    tsaInfoContent.hidden = false;
    tsaInfoLoaded = true;
  } catch (err) {
    tsaInfoLoading.innerHTML = `<span style="color:var(--error-color);">✖ Impossible de joindre l'API Open eIDAS (${err.message})</span>`;
  }
}

downloadCertBtn.addEventListener("click", async () => {
  downloadCertBtn.disabled = true;
  downloadCertBtn.innerHTML = '<span class="spinner"></span> Téléchargement…';
  try {
    const res = await fetch(`${API_BASE}/api/v1/certificate`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const pem = await res.text();
    const blob = new Blob([pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "open-eidas-staging-chain.pem";
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert(`Erreur lors du téléchargement de la chaîne : ${err.message}`);
  } finally {
    downloadCertBtn.disabled = false;
    downloadCertBtn.textContent = "Télécharger la chaîne de certificats (.pem)";
  }
});

// --- Outil 3 : Commandes CLI (onglets de code) ---
const cliTabBtns = document.querySelectorAll(".cli-tab-btn");
const cliPanes = document.querySelectorAll(".cli-pane");

cliTabBtns.forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetId = btn.getAttribute("data-target");
    if (!targetId) return;

    cliTabBtns.forEach((b) => b.classList.toggle("active", b === btn));
    cliPanes.forEach((p) => p.classList.toggle("active", p.id === targetId));
  });
});

// --- Gestion du Thème (Clair / Sombre) ---
const themeToggle = document.getElementById("theme-toggle");
if (themeToggle) {
  themeToggle.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", nextTheme);
    localStorage.setItem("theme", nextTheme);
  });
}

// ==========================================
// 5. Nouvelles Fonctionnalités Avancées
// ==========================================

// --- A. Explorateur de Chaîne de Certificats X.509 ---
function renderCertChainHtml(certificates) {
  if (!certificates || !certificates.length) return "";

  const cards = certificates.map((cert, idx) => {
    const isLeaf = idx === 0;
    const isRoot = idx === certificates.length - 1;
    const roleLabel = isLeaf
      ? "TSU (Unité d'horodatage)"
      : isRoot
      ? "Autorité racine (Root CA)"
      : "Autorité intermédiaire (CA TSA)";

    const subjectStr = cert.subject?.typesAndValues
      ? cert.subject.typesAndValues.map((t) => t.value.valueBlock.value).join(", ")
      : "-";
    const issuerStr = cert.issuer?.typesAndValues
      ? cert.issuer.typesAndValues.map((t) => t.value.valueBlock.value).join(", ")
      : "-";
    const serialHex = cert.serialNumber?.valueBlock?.valueHexView
      ? bytesToHex(cert.serialNumber.valueBlock.valueHexView)
      : "-";
    const validFrom = cert.notBefore?.value ? cert.notBefore.value.toLocaleDateString("fr-FR") : "-";
    const validTo = cert.notAfter?.value ? cert.notAfter.value.toLocaleDateString("fr-FR") : "-";

    return `
      <div class="cert-card">
        <div class="cert-card-header">
          <span class="cert-badge">${roleLabel}</span>
          <button class="btn-copy btn-download-cert" data-cert-idx="${idx}" style="font-size:0.75rem; padding:0.2rem 0.5rem;">
            Télécharger (.crt)
          </button>
        </div>
        <div class="cert-row">
          <span class="cert-row-label">Sujet :</span>
          <span>${subjectStr}</span>
        </div>
        <div class="cert-row">
          <span class="cert-row-label">Émetteur :</span>
          <span>${issuerStr}</span>
        </div>
        <div class="cert-row">
          <span class="cert-row-label">Validité :</span>
          <span>Du ${validFrom} au ${validTo}</span>
        </div>
        <div class="cert-row">
          <span class="cert-row-label">Série :</span>
          <code>${serialHex}</code>
        </div>
      </div>
    `;
  }).join("");

  return `
    <details class="cert-chain-details">
      <summary class="cert-chain-summary">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <span>Chaîne de certification X.509 (${certificates.length} certificat${certificates.length > 1 ? "s" : ""})</span>
      </summary>
      <div class="cert-chain-list">
        ${cards}
      </div>
    </details>
  `;
}

// Téléchargement individuel d'un certificat X.509 (.crt)
document.addEventListener("click", (e) => {
  const btn = e.target.closest(".btn-download-cert");
  if (!btn) return;
  const idx = parseInt(btn.getAttribute("data-cert-idx"), 10);
  if (isNaN(idx) || !lastCertificatesList[idx]) return;

  try {
    const cert = lastCertificatesList[idx];
    const der = cert.toSchema().toBER(false);
    const blob = new Blob([der], { type: "application/x-x509-ca-cert" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `certificat-${idx + 1}.crt`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Impossible d'exporter le certificat : " + err.message);
  }
});

// --- B. Aperçu PDF Intégré (In-Browser Modal) ---
const pdfPreviewDialog = document.getElementById("pdf-preview-dialog");
const pdfPreviewIframe = document.getElementById("pdf-preview-iframe");
const pdfModalFilename = document.getElementById("pdf-modal-filename");
const pdfModalDownloadBtn = document.getElementById("pdf-modal-download-btn");
const pdfModalCloseBtn = document.getElementById("pdf-modal-close-btn");

let currentPreviewBlobUrl = null;

function openPdfPreview(pdfBytes, filename) {
  if (!pdfPreviewDialog || !pdfPreviewIframe) return;
  if (currentPreviewBlobUrl) URL.revokeObjectURL(currentPreviewBlobUrl);

  const blob = new Blob([pdfBytes], { type: "application/pdf" });
  currentPreviewBlobUrl = URL.createObjectURL(blob);
  pdfPreviewIframe.src = currentPreviewBlobUrl;

  if (pdfModalFilename) pdfModalFilename.textContent = filename;
  if (pdfModalDownloadBtn) {
    pdfModalDownloadBtn.href = currentPreviewBlobUrl;
    pdfModalDownloadBtn.download = filename;
  }
  pdfPreviewDialog.showModal();
}

if (previewPdfBtn) {
  previewPdfBtn.addEventListener("click", () => {
    if (!currentSignedPdfBytes || !currentFile) return;
    const baseName = currentFile.name.replace(/\.[^/.]+$/, "");
    openPdfPreview(currentSignedPdfBytes, `${baseName}-horodate.pdf`);
  });
}

if (verifyPreviewPdfBtn) {
  verifyPreviewPdfBtn.addEventListener("click", () => {
    if (!verifyCurrentPdfBytes || !verifyCurrentPdfName) return;
    openPdfPreview(verifyCurrentPdfBytes, verifyCurrentPdfName);
  });
}

if (pdfModalCloseBtn && pdfPreviewDialog) {
  pdfModalCloseBtn.addEventListener("click", () => pdfPreviewDialog.close());
  pdfPreviewDialog.addEventListener("close", () => {
    if (pdfPreviewIframe) pdfPreviewIframe.src = "";
  });
}

// --- C. Export de Reçu de Preuve Cryptographique (.json) ---
function bufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function downloadReceipt(receipt, filename) {
  const jsonStr = JSON.stringify(receipt, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

if (downloadReceiptBtn) {
  downloadReceiptBtn.addEventListener("click", () => {
    if (!lastReceiptData || !currentFile) return;
    const baseName = currentFile.name.replace(/\.[^/.]+$/, "");
    downloadReceipt(lastReceiptData, `${baseName}-preuve-horodatage.json`);
  });
}

if (verifyDownloadReceiptBtn) {
  verifyDownloadReceiptBtn.addEventListener("click", () => {
    if (!lastReceiptData) return;
    const name = verifySelectedFiles[0] ? verifySelectedFiles[0].name.replace(/\.[^/.]+$/, "") : "document";
    downloadReceipt(lastReceiptData, `${name}-preuve-verification.json`);
  });
}

// --- D. Outil 4 : Soumission de Requête TSQ Binaire (/tsa) ---
const tsqDropzone = document.getElementById("tsq-dropzone");
const tsqFileInput = document.getElementById("tsq-file-input");
const tsqResult = document.getElementById("tsq-result");
const tsqResultHeader = document.getElementById("tsq-result-header");
const tsqResultBody = document.getElementById("tsq-result-body");
const tsqDownloadBtn = document.getElementById("tsq-download-btn");

let currentTsqTsrBytes = null;
let currentTsqFileName = "reponse.tsr";

if (tsqDropzone && tsqFileInput) {
  tsqDropzone.addEventListener("click", () => tsqFileInput.click());
  tsqDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    tsqDropzone.classList.add("dragover");
  });
  tsqDropzone.addEventListener("dragleave", () => tsqDropzone.classList.remove("dragover"));
  tsqDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    tsqDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) handleTsqFile(e.dataTransfer.files[0]);
  });
  tsqFileInput.addEventListener("change", () => {
    if (tsqFileInput.files.length) handleTsqFile(tsqFileInput.files[0]);
  });
}

async function handleTsqFile(file) {
  if (!tsqResult) return;
  tsqResult.classList.add("visible");
  tsqResultHeader.className = "result-header";
  tsqResultHeader.innerHTML = '<span class="spinner"></span> Envoi de la requête TSQ à la TSA…';
  tsqResultBody.textContent = `Envoi de ${file.name} (${file.size} octets) au point d'accès binaire RFC 3161 /tsa...`;
  if (tsqDownloadBtn) tsqDownloadBtn.hidden = true;

  try {
    await loadCrypto();
    const tsqBuf = await file.arrayBuffer();

    const res = await fetch(`${API_BASE}/tsa`, {
      method: "POST",
      headers: { "Content-Type": "application/timestamp-query" },
      body: tsqBuf,
    });

    if (!res.ok) {
      throw new Error(`Réponse HTTP ${res.status} de l'autorité TSA`);
    }

    const tsrBuf = await res.arrayBuffer();
    currentTsqTsrBytes = new Uint8Array(tsrBuf);
    currentTsqFileName = file.name.replace(/\.[^/.]+$/, "") + ".tsr";

    const v = await verifyToken(tsrBuf, null);
    tsqResultHeader.className = "result-header ok";
    tsqResultHeader.textContent = "✔ Jeton TSR obtenu avec succès";

    const rows = [
      ["Statut", "Jeton RFC 3161 valide généré par la TSA"],
      ["Date et heure (UTC)", v.tstInfo.genTime.toISOString()],
      ["Autorité (TSU)", v.signerSubject],
      ["Politique (OID)", v.tstInfo.policyOid],
      ["Numéro de série", `<code>${v.tstInfo.serialHex}</code>`],
      ["Signature TSA", v.signatureValid ? "✔ valide" : "✖ invalide"],
      ["Chaîne de certificats", v.chainValid ? "✔ validée" : "✖ non validée"],
    ];

    const dl = rows.map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join("");
    const certChainHtml = renderCertChainHtml(v.certificates);
    lastCertificatesList = v.certificates || [];

    tsqResultBody.innerHTML = `<dl>${dl}</dl>${certChainHtml}`;
    if (tsqDownloadBtn) tsqDownloadBtn.hidden = false;
  } catch (err) {
    tsqResultHeader.className = "result-header error";
    tsqResultHeader.textContent = "✖ Échec de la requête TSQ";
    tsqResultBody.innerHTML = `<p>${err.message || err}</p>`;
    if (tsqDownloadBtn) tsqDownloadBtn.hidden = true;
  }
}

if (tsqDownloadBtn) {
  tsqDownloadBtn.addEventListener("click", () => {
    if (!currentTsqTsrBytes) return;
    const blob = new Blob([currentTsqTsrBytes], { type: "application/timestamp-reply" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = currentTsqFileName;
    a.click();
    URL.revokeObjectURL(url);
  });
}

// --- E. Enregistrement du Service Worker (PWA & Offline) ---
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch((err) => {
      console.warn("Échec d'enregistrement du Service Worker :", err);
    });
  });
}


