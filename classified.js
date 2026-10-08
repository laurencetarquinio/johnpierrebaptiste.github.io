// Classified: decrypts an essay in the browser once the reader enters the
// clearance code. The page ships only ciphertext (see tools/classify.mjs);
// a correct code is remembered so the rest of the archive opens on its own.

(() => {
  const payloadEl = document.getElementById('classified-payload');
  const dossier = document.getElementById('dossier');
  if (!payloadEl || !dossier) return;

  const STORE_KEY = 'jpb-clearance';
  const form = document.getElementById('dossier-form');
  const input = document.getElementById('clearance');
  const status = document.getElementById('dossier-status');
  const button = form.querySelector('button');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let payload;
  try {
    payload = JSON.parse(payloadEl.textContent);
  } catch {
    status.textContent = 'This file is damaged and cannot be decrypted.';
    button.disabled = true;
    return;
  }

  if (!window.crypto || !window.crypto.subtle) {
    status.textContent = 'This browser cannot decrypt files. Open the page over https.';
    button.disabled = true;
    return;
  }

  const store = {
    get() { try { return localStorage.getItem(STORE_KEY); } catch { return null; } },
    set(v) { try { localStorage.setItem(STORE_KEY, v); } catch {} },
    clear() { try { localStorage.removeItem(STORE_KEY); } catch {} },
  };

  const normalize = s => s.trim().toUpperCase();
  const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const wait = ms => new Promise(r => setTimeout(r, reduceMotion ? 0 : ms));

  async function decrypt(code) {
    const subtle = window.crypto.subtle;
    const material = await subtle.importKey('raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveKey']);
    const key = await subtle.deriveKey(
      { name: 'PBKDF2', salt: fromB64(payload.salt), iterations: payload.iter, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(payload.iv) }, key, fromB64(payload.ct));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  function reveal(doc) {
    const body = dossier.closest('.post-body');
    const sub = document.querySelector('.post-subtitle.redacted');
    if (sub) {
      if (doc.sub) {
        sub.innerHTML = doc.sub;
        sub.classList.remove('redacted');
        sub.removeAttribute('aria-hidden');
      } else {
        sub.remove();
      }
    }
    body.innerHTML = doc.body;
    body.classList.add('declassified');
    document.documentElement.classList.add('cleared');
    // Content height changed; let the reading-progress bar recompute.
    window.dispatchEvent(new Event('scroll'));
  }

  function deny(message) {
    status.textContent = message;
    dossier.classList.remove('denied');
    void dossier.offsetWidth; // restart the shake animation
    dossier.classList.add('denied');
    input.focus();
    input.select();
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const code = normalize(input.value);
    if (!code) return deny('Enter a clearance code.');

    button.disabled = true;
    dossier.classList.remove('denied');
    status.textContent = 'Verifying clearance...';

    let doc;
    try {
      doc = await decrypt(code);
    } catch {
      button.disabled = false;
      return deny('Access denied. Invalid clearance code.');
    }

    store.set(code);
    dossier.classList.add('granted');
    status.textContent = 'Access granted. Declassifying.';
    dossier.classList.add('unsealing');
    await wait(650);
    reveal(doc);
  });

  // A reader who already has clearance goes straight through.
  const saved = store.get();
  if (saved) {
    dossier.classList.add('checking');
    status.textContent = 'Verifying clearance...';
    decrypt(saved).then(reveal, () => {
      store.clear();
      dossier.classList.remove('checking');
      status.textContent = '';
    });
  }
})();
