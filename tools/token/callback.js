import { acceptOAuthResult } from './auth.js';

const { hash } = window.location;
window.history.replaceState(null, '', window.location.pathname);
const state = sessionStorage.getItem('token-poc-state');
sessionStorage.removeItem('token-poc-state');
const message = { type: 'token-poc-oauth', state };
try {
  Object.assign(message, acceptOAuthResult(hash, state));
} catch (error) {
  message.error = error.message;
}
if (window.opener) {
  window.opener.postMessage(message, window.location.origin);
  window.close();
}
document.querySelector('#status').textContent = message.error || 'Authorization complete. Return to the app.';
