# Independent IMS Token PoC

Tests whether a non-Adobe, user-trusted DA app can obtain its own IMS token using the `darkalley` client, without using the token supplied by DA.

## Run the deployed experiment

- [Registered site apps](https://da.live/apps#/ben-there-done-that/token-poc)
- [Embedded DA app](https://da.live/app/ben-there-done-that/token-poc/tools/token/index?ref=tokenpoc)
- [Standalone app](https://tokenpoc--token-poc--ben-there-done-that.aem.live/tools/token/index.html)
- [Preview-host app](https://tokenpoc--token-poc--ben-there-done-that.aem.page/tools/token/index.html)

The implementation is deployed on the `tokenpoc` branch. The `main` branch retains the AEM boilerplate. AEM Code Sync is installed for this repository, the DA content source is configured, and the app is registered in the site's `apps` sheet.

Reload between experiments. The buttons test:

1. A new IMS library instance configured with `client_id=darkalley`, followed by its own browser sign-in if anonymous.
2. A direct browser OAuth request to `/ims/authorize/v2`, with a same-origin callback and unpredictable, validated `state`.

Any token delivered by DA's initialization message is ignored. The DA SDK is not imported. The app does not print or export token values or user profile claims. If IMS supplies a token independently, the app summarizes selected metadata, computes a fingerprint, and attempts one read-only request to this site's DA `index.html` source with that token. No content write, publish, or admin operation is part of the token probe.

## Observed result — 2026-10-06

**No independently obtained token reached the app in the tested configuration.** Testing used external Chrome Ben after passkey authentication crashed Studio's embedded Chromium.

| Experiment | Observed outcome |
| --- | --- |
| DA app initialization | The non-Adobe, user-trusted app loads inside DA on `tokenpoc--token-poc--ben-there-done-that.preview.da.live`. DA supplies an SDK token; the app records its presence only and does not use it. |
| Direct OAuth from the standalone AEM origin | IMS receives the app's `darkalley` authorization request, but navigation ultimately lands on `da.live`, not the app callback. No token reaches the app. |
| Own IMS library sign-in from the embedded DA preview origin | The library requests `/ims/authorize/v1` with the app's preview-host redirect URI. The login popup instead lands on `da.live`; no token reaches the app. |
| Own IMS library silent refresh from the embedded origin | `POST https://adobeid-na1.services.adobe.com/ims/check/v6/token` fails browser CORS with `MissingAllowOriginHeader`; the library reports `networkError`. |

The observed result is **not** proof that all third-party IMS clients or every possible origin must fail. DA's user-trust list is distinct from IMS redirect/CORS policy. The `darkalley` IMS client configuration was not inspected or changed. Testing a separately registered IMS client, or explicitly supported redirect/origin configuration, is a different experiment.

The app reports `no-callback` after 30 seconds rather than waiting indefinitely. A DA source-read success was not reached because the app did not receive its own token.

## Source checks

- [DA shell trust gate](https://github.com/adobe/da-nx/blob/8210dcf2177b3cdde50e2747ba1ca27ce606a2ad/nx/blocks/shell/shell.js#L107-L120): non-Adobe apps can be trusted per `org/repo/ref`.
- [DA shell token dispatch](https://github.com/adobe/da-nx/blob/8210dcf2177b3cdde50e2747ba1ca27ce606a2ad/nx/blocks/shell/shell.js#L82-L91): receiving the supplied token is not Adobe-only after trust acceptance.
- [DA IMS client and scopes](https://github.com/adobe/da-live/blob/d66eec6860809f65f4ef442378e3cba37d24fb9a/scripts/scripts.js#L51-L57).
- [Independent CLI auth helper](https://github.com/adobe-rnd/da-auth-helper/blob/a221ba57dd27f2085634a2830a17afa5d875c9d3/src/auth.js#L32-L47): its localhost callback is not evidence that this deployed app's callback is supported.

## Local checks

```sh
npm ci
node --test test/token-auth.test.mjs
npm run lint
npx stylelint tools/token/style.css
```

The tests cover the independent authorization request, OAuth state/origin/popup validation, safe metadata, fresh-token DA reads, SDK-token isolation, explicit own-instance sign-in, bounded callback waits, and error-code sanitization. Failing tests were committed before implementation changes. Runtime code is vanilla HTML/JavaScript/CSS with no build step or production package dependencies.
