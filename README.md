# Independent IMS Token PoC

**Verified: a non-Adobe-hosted DA app can mint its own IMS token using a separately registered OAuth Single-Page App client and S256 PKCE. The resulting token successfully read this site's DA source, without using DA's supplied SDK token.**

Reusing the shared `darkalley` client did not work from this app's origin, including when tested with authorization code + PKCE.

## Run the deployed experiment

- [Registered site apps](https://da.live/apps#/ben-there-done-that/token-poc)
- [Embedded DA app](https://da.live/app/ben-there-done-that/token-poc/tools/token/index?ref=tokenpoc)
- [Standalone app](https://tokenpoc--token-poc--ben-there-done-that.aem.live/tools/token/index.html)
- [Preview-host app](https://tokenpoc--token-poc--ben-there-done-that.aem.page/tools/token/index.html)

Code is deployed on `tokenpoc`; `main` retains the AEM boilerplate. AEM Code Sync is installed for this repository, the DA content source is configured, and the app is registered in the site's `apps` sheet.

### Own-client PKCE

Open the app and click **Mint via code + PKCE**. Its defaults are:

- Public client ID: `70d42326a3344517a75310c36b9b4f2b`
- Requested scopes: `openid,AdobeID,profile,email,org.read`
- Authorization: `https://ims-na1.adobelogin.com/ims/authorize/v2`
- Code exchange: `https://ims-na1.adobelogin.com/ims/token/v3`
- Default callback: `https://tokenpoc--token-poc--ben-there-done-that.aem.live/tools/token/callback.html`

The app generates a fresh random verifier, sends an S256 challenge, validates OAuth state and the popup's origin/source, exchanges the code directly from the browser without a client secret, and makes one authenticated read of this site's DA `index.html` source. Code responses use a fragment; the callback immediately removes the fragment/query from the URL. The verifier remains in app memory.

The client was created in a new **DA Independent IMS Token PoC** project under **Sites Internal**, using **Adobe Commerce with Adobe ID**, which offered the genuine SPA credential type. Edge Delivery Services offered only server-to-server credentials in this Console setup; Analytics offered legacy Web/iOS/Android types. No existing client was changed and no Commerce API was called.

- [Developer Console project](https://developer.adobe.com/console/projects/245265/4566206088345771412/overview)
- [SPA credential](https://developer.adobe.com/console/projects/245265/4566206088345771412/credentials/1046764/details)

**The client is in development mode with one beta user.** Other users are not enabled. Public use would require the applicable Developer Console approval process. The redirect patterns are restricted to the exact callback on the `tokenpoc` branch's `.aem.live`, `.aem.page`, and `.preview.da.live` hosts, not arbitrary origins.

### Shared-client comparisons

To repeat code/PKCE with the shared client, replace the client ID field with `darkalley`. The legacy **Mint with own IMS library** and **Mint via browser OAuth** buttons also use `darkalley` and DA's original scope list. Reload between experiments. PKCE allows five minutes for interactive sign-in/consent; legacy flows have a 30-second callback wait.

## Observed results — 2026-10-06

Testing used external Chrome Ben after passkey authentication crashed Studio's embedded Chromium.

| Experiment | Verified result |
| --- | --- |
| `darkalley`, direct implicit OAuth from the standalone AEM origin | IMS replaced the requested app callback with `https://da.live`; no token reached the app. |
| `darkalley`, own IMS library sign-in from the embedded DA preview origin | The sign-in popup landed on `da.live`, not the app callback; no token reached the app. |
| `darkalley`, own IMS library silent refresh | Browser CORS rejected `/ims/check/v6/token` with `MissingAllowOriginHeader`; library reported `networkError`. |
| `darkalley`, authorization code + S256 PKCE | IMS preserved `response_type=code` and S256 but replaced the app callback with `https://da.live`. The app received no authorization code and could not perform a code exchange. |
| Own SPA client, standalone `.aem.live` app | App callback honored; code received; token endpoint HTTP 200; DA source GET HTTP 200. `sdkTokenReceived=false`, `sdkTokenUsed=false`. |
| Own SPA client, embedded `.preview.da.live` DA app | App callback honored; a second token minted under the new client ID; token endpoint HTTP 200; DA source GET HTTP 200. `sdkTokenReceived=true`, `sdkTokenUsed=false`. |

The two own-client tokens had different fingerprints and issuance times. Their inspected client IDs matched the registered SPA client, not `darkalley`, and their scopes matched the requested identity/profile/organization scopes.

### Boundaries and limitations

- **DA user trust and IMS client registration are separate.** Trusting a DA app does not make its callback acceptable to `darkalley`. [IMS documentation](https://developer.adobe.com/developer-console/docs/guides/authentication/UserAuthentication/ims#authorize-request) explicitly describes falling back to the default URI when the requested callback does not match the client's pattern.
- **Minting and API authorization are separate.** This experiment verified a read of `https://admin.da.live/source/ben-there-done-that/token-poc/index.html`. It did not test writes, publication, EDS Admin APIs, or Helix 6 source-bus APIs, and does not establish access to those services.
- The own client was registered through the available API in Sites Internal and enabled for one beta account. This is not evidence that every organization/API exposes SPA credential creation or that all users can use this client.
- The shared `darkalley` IMS configuration was neither inspected nor changed.

## Token isolation and evidence

The DA SDK is not imported. DA's initialization message is used only to record token presence and set the title; its token is not used for auth or API requests. Evidence contains selected token metadata, a SHA-256 fingerprint, request status codes, and SDK-isolation flags. No raw tokens, authorization codes, PKCE verifiers, client secrets, or user profile claims are displayed or exported.

## Source checks

- [DA shell trust gate](https://github.com/adobe/da-nx/blob/8210dcf2177b3cdde50e2747ba1ca27ce606a2ad/nx/blocks/shell/shell.js#L107-L120).
- [DA shell SDK-token dispatch](https://github.com/adobe/da-nx/blob/8210dcf2177b3cdde50e2747ba1ca27ce606a2ad/nx/blocks/shell/shell.js#L82-L91).
- [DA IMS client/scopes](https://github.com/adobe/da-live/blob/d66eec6860809f65f4ef442378e3cba37d24fb9a/scripts/scripts.js#L51-L57).
- [Adobe's public-client PKCE and token-exchange reference](https://developer.adobe.com/developer-console/docs/guides/authentication/UserAuthentication/ims).
- [Adobe's SPA credential and redirect-pattern guidance](https://developer.adobe.com/developer-console/docs/guides/authentication/UserAuthentication/implementation).

## Local checks

```sh
npm ci
node --test test/token-auth.test.mjs
npm run lint
npx stylelint tools/token/style.css
```

Tests cover independent auth, the RFC 7636 S256 vector, verifier generation, OAuth state/origin/popup validation, public-client code exchange, safe failure reporting, fresh-token DA reads, SDK-token isolation, callback deadlines, and verified SPA defaults. Failing tests were committed before implementation changes. Runtime is vanilla HTML/JavaScript/CSS, with no build step or production package dependencies.
