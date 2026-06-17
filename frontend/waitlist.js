/* ============================================================================
 * Occasions — Waitlist page JS (supplier-only)
 *
 * Vanilla JS, no dependencies. Mirrors the main app's hero sparkle recipe
 * (frontend/js/app.js mountHeroSparkles) so the waitlist reads as the same
 * brand as the marketplace.
 *
 * Security posture:
 *   - Honeypot field (website) — bots fill, real users don't see it.
 *   - Timing check (form_loaded_at) — submissions under 1.5s are dropped
 *     server-side as bots.
 *   - All payload values come from form inputs, never from URL/HTML.
 *   - No innerHTML with user data; only textContent for status messages.
 * ============================================================================ */

(function () {
  'use strict';

  /* ---------------- helpers ---------------- */
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  /* ============================================================================
   * Hero sparkle layer
   *
   * Same particle recipe as the main app: 120 dots in pink + gold + warm-white,
   * drifting upward with sine-wave twinkle. ~50 lines, ~0KB of deps. Pauses
   * when the tab is hidden to save battery. Hidden under prefers-reduced-motion
   * by CSS, but the JS still mounts so a preference flip re-shows it.
   * ============================================================================ */
  function mountHeroSparkles() {
    const hero = $('.hero');
    const canvas = hero && $('.hero-sparkles', hero);
    if (!hero || !canvas) {
      // eslint-disable-next-line no-console
      console.warn('[waitlist] sparkles: hero or canvas missing', { hero, canvas });
      return;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    // Brand palette as rgba prefixes — alpha appended per-frame so each
    // particle twinkles independently without string churn.
    const colours = [
      'rgba(255,200,225,', // bright pink
      'rgba(255,225,160,', // bright gold
      'rgba(255,255,255,', // warm white
    ];
    const COUNT = 120;
    const particles = [];
    let w = 0, h = 0, raf = 0;

    function resize() {
      const r = hero.getBoundingClientRect();
      // Fall back hard if layout hasn't settled yet — better an over-sized
      // canvas than an invisible 0×0 one.
      w = r.width  || hero.clientWidth  || window.innerWidth;
      h = r.height || hero.clientHeight || window.innerHeight;
      if (w < 1) w = window.innerWidth;
      if (h < 1) h = window.innerHeight;
      canvas.width  = Math.round(w * DPR);
      canvas.height = Math.round(h * DPR);
      canvas.style.width  = w + 'px';
      canvas.style.height = h + 'px';
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    }
    function makeParticle(seedY) {
      return {
        x: Math.random() * w,
        y: seedY != null ? seedY : Math.random() * h,
        r: 0.8 + Math.random() * 1.7,            // 0.8–2.5px — matches main app
        vy: -0.08 - Math.random() * 0.25,
        vx: (Math.random() - 0.5) * 0.18,
        tw: Math.random() * Math.PI * 2,
        twSpeed: 0.012 + Math.random() * 0.03,
        colour: colours[(Math.random() * colours.length) | 0],
      };
    }
    function seedParticles() {
      particles.length = 0;
      for (let i = 0; i < COUNT; i++) particles.push(makeParticle());
    }

    function draw() {
      ctx.clearRect(0, 0, w, h);
      for (const p of particles) {
        p.x += p.vx;
        p.y += p.vy;
        p.tw += p.twSpeed;
        if (p.y < -6) { p.y = h + 6; p.x = Math.random() * w; }
        if (p.x < -6) p.x = w + 6;
        if (p.x > w + 6) p.x = -6;
        const alpha = (Math.sin(p.tw) * 0.5 + 0.5) * 0.7 + 0.3;
        const core  = p.colour + alpha.toFixed(2) + ')';
        const glow  = p.colour + (alpha * 0.35).toFixed(2) + ')';
        ctx.beginPath();
        ctx.fillStyle = glow;
        ctx.arc(p.x, p.y, p.r * 1.75, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.fillStyle = core;
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    function loop() {
      draw();
      raf = requestAnimationFrame(loop);
    }

    resize();
    seedParticles();
    draw();              // paint one frame immediately so something is
                         // visible even if rAF starts slow
    loop();

    // Layout sometimes finalises a tick after DOMContentLoaded (web fonts,
    // image reflow). Re-fit and re-seed once on next frame + once on
    // window.load so we never get stuck with a 0-pixel canvas.
    requestAnimationFrame(() => { resize(); seedParticles(); });
    window.addEventListener('load', () => { resize(); seedParticles(); }, { once: true });

    // Pause when tab hidden — saves battery on background tabs.
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        raf = 0;
      } else if (!raf) {
        loop();
      }
    });
    // Re-fit on resize / orientation change (rAF-debounced).
    let resizeRaf = 0;
    window.addEventListener('resize', () => {
      if (resizeRaf) return;
      resizeRaf = requestAnimationFrame(() => {
        resize();
        resizeRaf = 0;
      });
    });
  }

  /* ============================================================================
   * Modal handling — open / close + focus trap + Esc to close
   * ============================================================================ */
  const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  let lastFocused = null;
  const FORM_LOADED_AT = {};   // map of modal-name -> ms timestamp

  function openModal(name) {
    const overlay = document.getElementById('modal-' + name);
    if (!overlay) return;
    // If another modal is already open (e.g. user clicked the Privacy link
    // inside the supplier modal), swap rather than stack.
    const alreadyOpen = $('.modal-overlay.open');
    if (alreadyOpen && alreadyOpen !== overlay) {
      alreadyOpen.classList.remove('open');
    } else {
      // Only remember the original trigger when no modal was already open,
      // otherwise we'd dump focus back into a closed modal on Esc.
      lastFocused = document.activeElement;
    }
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
    // Record the moment the user actually saw the form so the server can
    // reject sub-1.5s submissions as bots. Stored as seconds-since-epoch
    // to match the server's time.time() comparison.
    FORM_LOADED_AT[name] = Date.now() / 1000;

    // Move focus to the first real input (or the close button, for prose modals).
    requestAnimationFrame(() => {
      const first = overlay.querySelector('input:not(.honeypot input):not([type="hidden"]), select, textarea')
                 || overlay.querySelector('.modal-close');
      if (first) first.focus();
    });
  }

  function closeModal(overlay) {
    if (!overlay) return;
    overlay.classList.remove('open');
    document.body.style.overflow = '';
    if (lastFocused && lastFocused.focus) lastFocused.focus();
  }

  function wireModals() {
    // Open triggers
    $$('[data-open]').forEach(btn => {
      btn.addEventListener('click', e => {
        e.preventDefault();
        openModal(btn.dataset.open);
      });
    });
    // Close: backdrop click + close button + Esc
    $$('.modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', e => {
        if (e.target === overlay) closeModal(overlay);
      });
      $$('[data-close]', overlay).forEach(btn => {
        btn.addEventListener('click', () => closeModal(overlay));
      });
    });
    document.addEventListener('keydown', e => {
      if (e.key !== 'Escape') return;
      const open = $('.modal-overlay.open');
      if (open) closeModal(open);
    });
    // Focus trap inside an open modal
    document.addEventListener('keydown', e => {
      if (e.key !== 'Tab') return;
      const overlay = $('.modal-overlay.open');
      if (!overlay) return;
      const focusables = $$(FOCUSABLE, overlay).filter(el => el.offsetParent !== null);
      if (!focusables.length) return;
      const first = focusables[0];
      const last  = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault(); last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus();
      }
    });
  }

  /* ============================================================================
   * Chip-group toggling — single-select for service area
   * ============================================================================ */
  function wireChips(groupId) {
    const group = document.getElementById(groupId);
    if (!group) return;
    group.addEventListener('click', e => {
      const chip = e.target.closest('.chip');
      if (!chip) return;
      // Single-select: clicking the active chip clears it; otherwise switch.
      const wasActive = chip.classList.contains('active');
      $$('.chip', group).forEach(c => c.classList.remove('active'));
      if (!wasActive) chip.classList.add('active');
    });
  }

  function activeChipValue(groupId) {
    const group = document.getElementById(groupId);
    if (!group) return '';
    const active = $('.chip.active', group);
    return active ? active.dataset.area || '' : '';
  }

  /* ============================================================================
   * Multi-select chip group — category picker.
   *
   * UX rules (kept intentionally simple so suppliers never wonder what they
   * just did):
   *   - First tap            = PRIMARY (solid gold, bold)
   *   - 2nd / 3rd tap        = SECONDARY (gold outline)
   *   - Tap an active chip   = remove it. If you removed the primary, the
   *                            oldest secondary auto-promotes to primary.
   *   - Cap of `data-max` (3) selections. When at cap, untapped chips dim
   *     to communicate "you're full".
   *
   * Selection order is stored on the group as a data attribute (CSV of
   * slugs) so the submit handler can read primary + secondaries without
   * re-walking the DOM.
   * ============================================================================ */
  function wireMultiChips(groupId) {
    const group = document.getElementById(groupId);
    if (!group) return;
    const max = Math.max(1, parseInt(group.dataset.max || '3', 10));
    /** @type {string[]} Ordered selection — first entry is primary. */
    const selected = [];

    function render() {
      const isFull = selected.length >= max;
      $$('.chip', group).forEach(chip => {
        const slug = chip.dataset.cat || '';
        const idx = selected.indexOf(slug);
        chip.classList.remove('primary', 'secondary', 'active');
        chip.disabled = false;
        if (idx === 0) {
          chip.classList.add('primary');
          chip.setAttribute('aria-pressed', 'true');
        } else if (idx > 0) {
          chip.classList.add('secondary');
          chip.setAttribute('aria-pressed', 'true');
        } else {
          chip.setAttribute('aria-pressed', 'false');
          if (isFull) chip.disabled = true;
        }
      });
      group.dataset.selected = selected.join(',');
      // Toggle the "Other — tell us" free-text row whenever the primary
      // changes. Driven from here (not a separate change listener) so the
      // single source of truth is the selection array.
      syncCategoryOtherVisibility(selected[0] || '');
    }

    group.addEventListener('click', e => {
      const chip = e.target.closest('.chip');
      if (!chip || chip.disabled) return;
      const slug = chip.dataset.cat || '';
      if (!slug) return;
      const idx = selected.indexOf(slug);
      if (idx >= 0) {
        // Deselect. If we removed the primary, the next entry auto-
        // promotes — splice() already gives us that behaviour for free.
        selected.splice(idx, 1);
      } else if (selected.length < max) {
        selected.push(slug);
      }
      render();
    });

    // Expose a read-only snapshot for the submit handler.
    group._selected = () => selected.slice();
    render();
  }

  /* Drives visibility of the category-other free-text row from outside
     the chip handler so it stays in sync however the primary was set. */
  function syncCategoryOtherVisibility(primarySlug) {
    const row = document.getElementById('sup-category-other-row');
    const input = document.getElementById('sup-category-other');
    if (!row || !input) return;
    if (primarySlug === 'other') {
      row.classList.remove('hidden');
      input.required = true;
    } else {
      row.classList.add('hidden');
      input.required = false;
      input.value = '';
    }
  }

  function selectedCategories(groupId) {
    const group = document.getElementById(groupId);
    if (!group || typeof group._selected !== 'function') return [];
    return group._selected();
  }

  /* ============================================================================
   * Category “Other” — visibility is now driven by the category chip group
   * (see syncCategoryOtherVisibility above). No standalone wire-up needed
   * since the legacy <select> was retired in favour of multi-select chips.
   * ============================================================================ */

  /* ============================================================================
   * Celebration takeover — confetti + animated tick after successful signup.
   *
   * Vanilla canvas, ~140 pieces in brand colours, gentle gravity, auto-stops
   * after 6s. No third-party deps so CSP `script-src 'self'` stays intact.
   * ============================================================================ */
  let _confettiRaf = 0;
  function launchConfetti() {
    const canvas = document.querySelector('#celebration .celebration-confetti');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const DPR = Math.min(window.devicePixelRatio || 1, 2);

    function size() {
      const r = canvas.getBoundingClientRect();
      const w = Math.max(1, r.width  || window.innerWidth);
      const h = Math.max(1, r.height || window.innerHeight);
      canvas.width  = Math.round(w * DPR);
      canvas.height = Math.round(h * DPR);
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      return { w, h };
    }
    let { w, h } = size();

    // Brand palette — gold, pink, white plus a hint of deep blue for depth.
    const colours = ['#D4A843', '#F5E6B8', '#E8A0BF', '#FBF0F5', '#ffffff', '#3A4FAD'];
    const N = 140;
    const pieces = [];
    function spawnPiece(seedTop) {
      // seedTop=true → start above the canvas (used for the initial burst);
      // seedTop=false → respawn at top so the loop is endless.
      return {
        x: Math.random() * w,
        y: seedTop ? -20 - Math.random() * h * 0.6 : -20 - Math.random() * 40,
        vx: (Math.random() - 0.5) * 1.6,
        vy: 1.8 + Math.random() * 2.8,
        s: 5 + Math.random() * 5,
        rot: Math.random() * Math.PI * 2,
        vrot: (Math.random() - 0.5) * 0.28,
        colour: colours[(Math.random() * colours.length) | 0],
        shape: Math.random() < 0.55 ? 'rect' : 'circle',
      };
    }
    for (let i = 0; i < N; i++) pieces.push(spawnPiece(true));

    function frame() {
      ctx.clearRect(0, 0, w, h);
      for (let i = 0; i < pieces.length; i++) {
        const p = pieces[i];
        p.x += p.vx;
        p.y += p.vy;
        p.vy += 0.018;             // gentle gravity
        p.rot += p.vrot;
        // Recycle pieces that have fallen off-screen — keeps the loop
        // endless without ever growing the array.
        if (p.y - p.s > h || p.x < -50 || p.x > w + 50) {
          pieces[i] = spawnPiece(false);
          continue;
        }
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rot);
        ctx.fillStyle = p.colour;
        if (p.shape === 'rect') {
          ctx.fillRect(-p.s / 2, -p.s / 4, p.s, p.s * 0.5);
        } else {
          ctx.beginPath();
          ctx.arc(0, 0, p.s * 0.4, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.restore();
      }
      _confettiRaf = requestAnimationFrame(frame);
    }
    _confettiRaf = requestAnimationFrame(frame);

    // Re-fit on resize / orientation change (rAF-debounced).
    let resizeRaf = 0;
    window.addEventListener('resize', () => {
      if (resizeRaf) return;
      resizeRaf = requestAnimationFrame(() => {
        ({ w, h } = size());
        resizeRaf = 0;
      });
    });
  }

  function showCelebration() {
    const overlay = document.getElementById('celebration');
    if (!overlay) return;
    // Hide any open modal first so the takeover feels like a real moment,
    // not a stack of dialogs.
    const open = $('.modal-overlay.open');
    if (open) closeModal(open);
    overlay.classList.add('open');
    overlay.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    launchConfetti();
    // Focus the close button for keyboard / screen-reader users.
    const close = overlay.querySelector('.celebration-close');
    if (close) requestAnimationFrame(() => close.focus());
  }

  function hideCelebration() {
    const overlay = document.getElementById('celebration');
    if (!overlay) return;
    overlay.classList.remove('open');
    overlay.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    if (_confettiRaf) { cancelAnimationFrame(_confettiRaf); _confettiRaf = 0; }
  }

  function wireCelebration() {
    const closeBtn = document.getElementById('celebration-close');
    if (closeBtn) closeBtn.addEventListener('click', hideCelebration);
    document.addEventListener('keydown', e => {
      if (e.key !== 'Escape') return;
      const overlay = document.getElementById('celebration');
      if (overlay && overlay.classList.contains('open')) hideCelebration();
    });
  }

  /* ============================================================================
   * Status helpers (success / error banners inside the modal)
   * ============================================================================ */
  function setStatus(boxId, kind, message) {
    const box = document.getElementById(boxId);
    if (!box) return;
    box.innerHTML = '';
    if (!message) return;
    const div = document.createElement('div');
    div.className = kind === 'error' ? 'form-error' : 'form-success';
    div.textContent = message;   // textContent, never innerHTML, with user data
    box.appendChild(div);
  }

  /* ============================================================================
   * Supplier form submission
   * ============================================================================ */
  function wireSupplierForm() {
    const form = document.getElementById('form-supplier');
    if (!form) return;
    const submitBtn = document.getElementById('sup-submit');
    const statusBox = 'sup-feedback-box';

    form.addEventListener('submit', async e => {
      e.preventDefault();
      setStatus(statusBox, null, null);

      const business = ($('#sup-business').value || '').trim();
      const cats     = selectedCategories('sup-categories');
      const category = cats[0] || '';
      const secondaries = cats.slice(1);     // already capped at 2 by max=3
      const categoryOtherRaw = ($('#sup-category-other').value || '').trim();
      const area     = activeChipValue('sup-areas');
      const insta    = ($('#sup-instagram').value || '').trim().replace(/^@/, '');
      const email    = ($('#sup-email').value || '').trim();
      const feedback = ($('#sup-feedback').value || '').trim();
      const ready    = !!$('#sup-ready').checked;
      const honeypot = ($('#sup-website').value || '');

      // Client-side validation matches what the server enforces, so users
      // see fast feedback instead of a generic 422. Server is still the
      // source of truth — never trust this branch alone.
      if (!business) return setStatus(statusBox, 'error', 'Tell us your business name.');
      if (!category) return setStatus(statusBox, 'error', 'Pick at least one category.');
      if (category === 'other' && !categoryOtherRaw) {
        return setStatus(statusBox, 'error', 'Tell us what kind of supplier you are.');
      }
      if (categoryOtherRaw.length > 60) {
        return setStatus(statusBox, 'error', 'Keep the category description under 60 characters.');
      }
      if (!area)     return setStatus(statusBox, 'error', 'Pick a service area.');
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        return setStatus(statusBox, 'error', 'That email looks off — double-check?');
      }
      if (insta && !/^[A-Za-z0-9._]{1,30}$/.test(insta)) {
        return setStatus(statusBox, 'error', 'Instagram handles are letters, numbers, dots or underscores.');
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Joining…';
      try {
        const res = await fetch('/api/waitlist/supplier', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({
            business_name: business,
            category,
            category_other: category === 'other' ? (categoryOtherRaw || null) : null,
            secondary_categories: secondaries,
            service_area: area,
            instagram_handle: insta || null,
            email,
            feedback: feedback || null,
            ready_to_onboard: ready,
            website: honeypot,                          // honeypot
            form_loaded_at: FORM_LOADED_AT.supplier || 0,
          }),
        });
        if (!res.ok) {
          // Try to surface server's detail without trusting its HTML.
          let detail = 'Something went wrong. Try again in a moment?';
          try {
            const body = await res.json();
            if (body && typeof body.detail === 'string') detail = body.detail;
          } catch (_) { /* ignore */ }
          if (res.status === 429) detail = 'Easy there — try again in a minute.';
          throw new Error(detail);
        }
        setStatus(statusBox, 'success', "You're on the list. We'll be in touch when it's your turn.");
        submitBtn.textContent = 'Joined';
        // Disable further submits — server is idempotent but we'd rather
        // not encourage clicks. Show the celebration takeover so the user
        // gets a moment to enjoy the win.
        showCelebration();
      } catch (err) {
        setStatus(statusBox, 'error', err.message || 'Network hiccup. Try again?');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Join the waitlist';
      }
    });
  }

  /* ============================================================================
   * Border beam — JS-driven rotation
   *
   * We previously tried a CSS-only @property + keyframe approach to animate
   * the conic-gradient's `from` angle, but `@property` is gated behind
   * Chromium 85+ / Safari 16.4+ AND many corporate browsers force-enable
   * `prefers-reduced-motion` which would disable the animation outright.
   *
   * Driving the angle in JS via requestAnimationFrame is bulletproof: the
   * conic gradient re-evaluates each frame because we're literally
   * re-setting its `--beam-angle` custom property. We honour
   * prefers-reduced-motion explicitly so users who genuinely opted out
   * still get a static ring. Pauses when the tab is hidden.
   * ============================================================================ */
  function startBorderBeams() {
    const beams = $$('.border-beam');
    if (!beams.length) return;
    const reducedMotion = window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reducedMotion) {
      // Set a static angle so the ring is still visible (just doesn't rotate).
      beams.forEach(b => b.style.setProperty('--beam-angle', '0deg'));
      return;
    }
    const DURATION_MS = 4000;
    let raf = 0;
    let startTime = null;
    function frame(t) {
      if (startTime === null) startTime = t;
      const angle = ((t - startTime) / DURATION_MS) * 360 % 360;
      // Setting the variable triggers a repaint of the conic gradient on
      // every browser back to Chrome 69 / Safari 12.1 / Firefox 65.
      const value = angle.toFixed(2) + 'deg';
      for (const b of beams) b.style.setProperty('--beam-angle', value);
      raf = requestAnimationFrame(frame);
    }
    raf = requestAnimationFrame(frame);
    // Pause when the tab is hidden — saves CPU on background tabs.
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        if (raf) { cancelAnimationFrame(raf); raf = 0; }
      } else if (!raf) {
        startTime = null;
        raf = requestAnimationFrame(frame);
      }
    });
  }

  /* ============================================================================
   * Boot
   * ============================================================================ */
  function boot() {
    const yearEl = document.getElementById('year');
    if (yearEl) yearEl.textContent = String(new Date().getFullYear());
    mountHeroSparkles();
    wireModals();
    wireChips('sup-areas');
    wireMultiChips('sup-categories');
    wireCelebration();
    wireSupplierForm();
    startBorderBeams();
  }
  // Handle both cases: script loaded before DOMContentLoaded fires, and
  // script injected after the document is already complete (some browsers
  // restore tabs in 'complete' state).
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
