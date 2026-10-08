// Laurence Tarquinio — Site Interactions
// One job: a thin ink line tracking reading progress on essay pages.

(() => {
  if (!document.querySelector('.post-body')) return;

  const bar = document.createElement('div');
  bar.id = 'reading-progress';
  document.body.appendChild(bar);

  let ticking = false;

  const update = () => {
    const doc = document.documentElement;
    const max = doc.scrollHeight - window.innerHeight;
    const progress = max > 0 ? Math.min(Math.max(window.scrollY / max, 0), 1) : 0;
    bar.style.transform = `scaleX(${progress})`;
    ticking = false;
  };

  window.addEventListener('scroll', () => {
    if (!ticking) {
      ticking = true;
      requestAnimationFrame(update);
    }
  }, { passive: true });

  update();
})();
