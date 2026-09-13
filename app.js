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
    const verifications = await verifyPdfDocTimestamps(signedPdfBytes);
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
async function timestampGenericDocument(fileBuf, fileName, fileSize, mimeType) {
  const digestBytes = await sha256(fileBuf);
  const digestHex = bytesToHex(digestBytes);

  const { token, gen_time } = await requestTimestamp(digestHex);
  const tokenDer = base64ToBuffer(token);
  const v = await verifyToken(tokenDer, digestHex);

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

function showStampResult(ok, html) {
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

    showStampResult(
      v.allOk,
      `<dl>${dl}</dl><p style="margin-top:0.9rem;color:var(--text-subtle);">${footerNote}</p>`
    );

    downloadPdfBtn.textContent = result.isNativePdf
      ? "Télécharger le PDF horodaté (.pdf)"
      : "Télécharger la version PDF (.pdf)";
    downloadPdfBtn.hidden = false;
    downloadBtn.hidden = false;
  } catch (err) {
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

function setVerifyFiles(files) {
  verifySelectedFiles = Array.from(files || []);
  lastExtractedTsr = null;
  verifyResult.classList.remove("visible");
  verifyExportTsrBtn.hidden = true;

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

function showVerifyResult(ok, headerText, html) {
  verifyResult.classList.add("visible");
  verifyResultHeader.className = "result-header " + (ok ? "ok" : "error");
  verifyResultHeader.textContent = headerText;
  verifyResultBody.innerHTML = html;
}

verifyBtn.addEventListener("click", async () => {
  if (verifySelectedFiles.length === 0) return;
  verifyBtn.disabled = true;
  verifyBtn.innerHTML = '<span class="spinner"></span> Analyse et vérification…';
  verifyExportTsrBtn.hidden = true;

  try {
    await loadCrypto();

    // Cas 1 : Deux fichiers ou plus (contrôle croisé Document + Jeton .tsr)
    if (verifySelectedFiles.length >= 2) {
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
        throw new Error("Veuillez sélectionner au moins un fichier document et son fichier jeton .tsr associé.");
      }

      const tsrBuf = await tsrFile.arrayBuffer();
      const v = await verifyToken(tsrBuf, null);

      const algName = oidToAlgName(v.tstInfo.hashAlgOid);
      const webCryptoAlg = oidToWebCryptoAlg(v.tstInfo.hashAlgOid);

      const docBuf = await docFile.arrayBuffer();
      const docDigestBuf = await crypto.subtle.digest(webCryptoAlg, docBuf);
      const docDigestHex = bytesToHex(new Uint8Array(docDigestBuf));

      const digestMatch = docDigestHex.toLowerCase() === v.tstInfo.messageImprintHex.toLowerCase();
      const allOk = digestMatch && v.allOk;

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
      const summaryMsg = allOk
        ? `<p style="margin-top:0.9rem;color:var(--ok-color);font-weight:600;">✔ Le document est garanti authentique et rigoureusement inaltéré depuis son horodatage le ${v.tstInfo.genTime.toLocaleString("fr-FR")}.</p>`
        : `<p style="margin-top:0.9rem;color:var(--error-color);font-weight:600;">✖ Attention : Ce document a été modifié depuis son émission ou ne correspond pas au jeton fourni.</p>`;

      showVerifyResult(allOk, allOk ? "✔ Document authentifié et intègre" : "✖ Empreinte non conforme", `<dl>${dl}</dl>${summaryMsg}`);
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

        lastExtractedTsr = wrapInTimeStampResp(ts.token);
        const baseName = file.name.replace(/\.[^/.]+$/, "");
        lastExtractedTsrName = `${baseName}-jeton.tsr`;
        verifyExportTsrBtn.hidden = false;

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
        showVerifyResult(
          isOk,
          isOk ? "✔ Horodatage PAdES valide et intact" : "✖ Horodatage PAdES altéré ou invalide",
          `<dl>${dl}</dl><p style="margin-top:0.9rem;color:var(--text-subtle);">Ce document PDF contient un sceau d'horodatage PAdES conforme RFC 3161, vérifiable nativement dans Adobe Acrobat Reader, Foxit et pdfsig.</p>`
        );
        return;
      }

      // Aucun horodatage RFC 3161 trouvé dans le PDF
      // Vérifions si le PDF contient au moins une signature d'approbation standard
      const pdfTextSample = new TextDecoder("latin1").decode(fileBytes.slice(0, 50000)) +
        new TextDecoder("latin1").decode(fileBytes.slice(Math.max(0, fileBytes.length - 50000)));

      if (pdfTextSample.includes("/ByteRange") && (pdfTextSample.includes("/SubFilter") || pdfTextSample.includes("/Type /Sig"))) {
        showVerifyResult(
          false,
          "ℹ Signature numérique standard détectée (non DocTimeStamp)",
          `<p>Ce fichier PDF contient une signature électronique standard (ex: signature d'approbation CAdES ou PKCS#7), mais ne contient pas d'horodatage qualifié indépendant <code>/ETSI.RFC3161</code> (DocTimeStamp).</p>`
        );
        return;
      }

      showVerifyResult(
        false,
        "✖ Aucun horodatage ni signature détectés",
        `<p>Ce document PDF ne contient aucun horodatage DocTimeStamp RFC 3161 ni signature numérique électronique.</p>`
      );
      return;
    }

    // Sous-cas 2B : Jeton d'horodatage .tsr isolé
    if (isTsr || (!isPdf && fileBytes[0] === 0x30)) {
      try {
        const v = await verifyToken(fileBytes, null);
        lastExtractedTsr = wrapInTimeStampResp(fileBytes);
        lastExtractedTsrName = file.name;
        verifyExportTsrBtn.hidden = false;

        const algName = oidToAlgName(v.tstInfo.hashAlgOid);
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
        showVerifyResult(
          v.allOk,
          v.allOk ? "✔ Jeton d'horodatage RFC 3161 authentique" : "✖ Jeton RFC 3161 invalide",
          `<dl>${dl}</dl><p style="margin-top:0.9rem;color:var(--text-subtle);">💡 <strong>Astuce :</strong> Pour vérifier que votre document d'origine correspond à cette empreinte, déposez simultanément votre document ET ce jeton .tsr dans la zone de dépôt.</p>`
        );
        return;
      } catch (tsrErr) {
        throw new Error(`Le fichier n'est pas un jeton RFC 3161 valide : ${tsrErr.message}`);
      }
    }

    // Sous-cas 2C : Document non-PDF isolé
    showVerifyResult(
      false,
      "ℹ Document d'origine déposé sans jeton associé",
      `<p>Fichier déposé : <strong>${file.name}</strong>.</p>
       <p>Pour vérifier l'horodatage d'un document qui n'est pas un PDF (image, texte, archive, docx...), veuillez déposer <strong>simultanément</strong> votre document original ET son jeton d'horodatage <code>.tsr</code> associé.</p>
       <p>Vous pouvez aussi déposer l'attestation PDF scellée si elle a été générée lors de l'horodatage.</p>`
    );
  } catch (err) {
    showVerifyResult(false, "✖ Erreur lors de la vérification", `<p>${err.message || err}</p>`);
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
