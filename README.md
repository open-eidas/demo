# demo

Démo web statique du staging public Open eIDAS, hébergée sur
[demo.open-eidas.eu](https://demo.open-eidas.eu) via GitHub Pages.

Aucun serveur applicatif : tout se passe dans le navigateur.

- Le hash SHA-256 du fichier choisi est calculé localement (Web Crypto),
  jamais le fichier lui-même.
- La requête d'horodatage part directement du navigateur vers
  `https://api.staging.open-eidas.eu/api/v1/timestamp` — voir le CORS
  dédié à cette origine dans
  [open-eidas/open-eidas](https://github.com/open-eidas/open-eidas)
  (`tsa.corsAllowedOrigin` du chart Helm).
- Le jeton RFC 3161 renvoyé est intégralement parsé et vérifié côté
  client avec [pkijs](https://pkijs.org/)/[asn1js](https://github.com/PeculiarVentures/ASN1.js)
  (chargés depuis jsDelivr) : empreinte, signature CMS, chaîne de
  certification jusqu'à la racine — sans appel serveur supplémentaire.
- Téléchargement du jeton brut (`.tsr`) et d'une version PDF incluant
  la signature d'horodatage TSA :
  - **Documents PDF** : horodatage PAdES direct (`/SubFilter /ETSI.RFC3161`)
    incorporé dans le PDF, reconnu nativement par Adobe Acrobat Reader, Foxit et DSS.
  - **Tous les autres types de documents** (images, texte, tableurs, archives, etc.) :
    génération d'une attestation PDF officielle, scellée par horodatage PAdES,
    incorporant le document original et son jeton `.tsr` en pièces jointes (conforme ISO 32000).
- **Vérificateur de signature & jeton (100% côté client)** :
  - Analyse de PDF horodatés PAdES (DocTimeStamp RFC 3161 / ETSI.RFC3161) : vérification de l'intégrité du document (`ByteRange`), de la signature cryptographique et extraction/export du jeton `.tsr`.
  - Vérification de jetons d'horodatage autonomes (`.tsr`) : décodage ASN.1 (TimeStampResp / TimeStampToken), validation de la signature CMS et de la chaîne de certificats.
  - Contrôle croisé document + jeton `.tsr` : calcul local de l'empreinte et confirmation que le fichier n'a pas été altéré depuis son horodatage.
- **Boîte à outils (Toolbox)** :
  - Calculateur multi-empreintes instantané (SHA-256, SHA-384, SHA-512) via Web Crypto avec comparateur d'empreinte intégré.
  - Statut en direct de l'autorité TSA Open eIDAS (politique, précision, source de temps) et téléchargement de la chaîne de certificats (`.pem`).
  - Générateur de commandes CLI prêtes à copier (cURL JSON, OpenSSL RFC 3161 TSQ/TSR, pyHanko, pdfsig).


## Développement local

```bash
python3 -m http.server 8000
```

Puis ouvrir `http://localhost:8000`. La requête d'horodatage échouera
(CORS restreint à `https://demo.open-eidas.eu`) tant que testée depuis
une autre origine — c'est le comportement attendu, pas un bug.

## Structure

- `index.html`, `style.css` — page unique, pas de build.
- `app.js` — logique : hash, appel API, parsing/vérification RFC 3161.
- `CNAME` — domaine personnalisé GitHub Pages.

## Pourquoi pas la classe `pkijs.TSTInfo` ?

Un bug connu de pkijs/ASN1.js rejette certaines valeurs `TSTInfo`
pourtant valides (voir
[PeculiarVentures/ASN1.js#37](https://github.com/PeculiarVentures/ASN1.js/issues/37)).
`app.js` parse donc `TSTInfo` à la main avec l'API générique d'`asn1js`
plutôt qu'avec la classe stricte de pkijs — voir les commentaires de
`parseTstInfoFields`.
