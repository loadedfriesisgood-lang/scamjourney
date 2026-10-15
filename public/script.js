'use strict';
/* =====================================================================
   Scam Journey Intelligence - front-end demonstration
   - Everything runs in your browser. Nothing is sent, and nothing is
     saved (no localStorage). Refreshing the page resets all state.
   - Results come from fixed, hand-written rules. There is NO machine
     learning, NO live scam database and NO validated accuracy.
   ===================================================================== */

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const STAGES = ['Lure', 'Hook', 'Trust', 'Pressure', 'Payment', 'Exit'];

// Shared state passed between modules (in memory only).
const state = { check: null, stage: 0, fromTimeline: false, category: 'job' };

/* ---------- Navigation ---------- */
function show(id) {
  $$('.view').forEach(v => v.hidden = v.id !== 'v-' + id);
  $$('[data-nav]').forEach(b => b.classList.toggle('on', b.dataset.nav === id));
  document.body.classList.remove('menu');
  $('#menuBtn').setAttribute('aria-expanded', 'false');
  window.scrollTo(0, 0);
  $('#v-' + id).focus({ preventScroll: true });
}
document.addEventListener('click', e => {
  const g = e.target.closest('[data-go]');
  if (g) show(g.dataset.go);
});
$('#menuBtn').onclick = () => {
  const open = document.body.classList.toggle('menu');
  $('#menuBtn').setAttribute('aria-expanded', open);
};

/* =====================================================================
   MODULE 1 - SCAM CHECK
   Scoring rules (documented):
   1. Each indicator has a fixed weight and is counted AT MOST ONCE,
      however many times it appears (indicators are stored by id).
   2. Words like "bank", "job" or "urgent" alone never score; each rule
      needs a context pattern (e.g. a verb asking for an OTP, a fee
      next to "registration").
   3. score = min(100, sum of weights of distinct indicators).
   4. A single indicator can never reach "High risk" (score capped at 44),
      because one sign on its own is weak evidence.
   5. Bands: 0-14 Low indicators detected, 15-44 Moderate, 45-100 High.
   Limitations: regex rules can miss new wording and can misfire on
   legitimate messages. Treat results as a prompt to verify, not a verdict.
   ===================================================================== */
const RULES = [
  { id: 'fee', w: 25, label: 'Advance fee or payment requested',
    why: 'Real employers, couriers and prize draws rarely ask you to pay a fee first to receive a job, parcel or prize.',
    re: /(registration|processing|training|security|refundable|redelivery|customs|clearance|release|activation)\s*(fee|charge|deposit)|pay\s+(a\s+)?(small\s+)?(fee|deposit)|(pay|send|transfer|deposit)[^.]{0,40}(₹|rs\.?|inr|\$|usd)\s?\d/i },
  { id: 'urgent', w: 15, label: 'Urgent threat or artificial deadline',
    why: 'Scammers rush you so you do not stop to verify.',
    re: /(within|in)\s+\d+\s*(hours?|hrs?|minutes?|mins?)|\bact now\b|last chance|final (notice|warning)|expires? (today|soon)|or (your )?(account|card|sim|number) (will be )?(blocked|suspended|closed|deactivated)/i },
  { id: 'cred', w: 30, label: 'Asks for OTP, password, PIN or similar',
    why: 'Genuine organisations never ask you to share OTPs, PINs or passwords by message or call.',
    re: /(share|send|enter|tell|provide|confirm|reply with|give|read out)[^.]{0,30}\b(otp|password|pin|cvv|passcode|card number|aadhaar)\b/i },
  { id: 'app', w: 20, label: 'Asks to install an app or share your screen',
    why: 'Remote-access tools and unknown apps let scammers see your screen and approve payments.',
    re: /(install|download)[^.]{0,40}(app|apk|anydesk|teamviewer|quicksupport)|screen\s?shar|remote (access|control)|anydesk|teamviewer/i },
  { id: 'channel', w: 10, label: 'Moves the chat to another channel',
    why: 'Moving to WhatsApp or Telegram takes the conversation away from platform protections.',
    re: /(whatsapp|telegram)[^.]{0,40}(contact|message|chat|join|add)|(contact|message|chat|join|add|text)[^.]{0,40}(whatsapp|telegram)/i },
  { id: 'paym', w: 20, label: 'Unusual payment method',
    why: 'Gift cards, crypto and wire transfers are hard to reverse, which is why scammers prefer them.',
    re: /gift\s?cards?|crypto|bitcoin|\busdt\b|\bbtc\b|wallet address|itunes|google play card|western union/i },
  { id: 'claim', w: 15, label: 'Prize, refund, suspension or guaranteed-earnings claim',
    why: 'Unexpected winnings, pending refunds, account threats and guaranteed income are common hooks.',
    re: /you('ve| have)? (won|been selected)|lottery|claim your (reward|prize)|guaranteed (income|returns?|profit)|earn\s*(₹|rs\.?|\$)?\s?\d[\d,]*\s*(per|a|\/)\s*(day|week|hour)|account (will be |has been )?(suspended|blocked|locked|compromised)|refund (is )?(pending|approved)/i },
  { id: 'secret', w: 10, label: 'Asks you to keep it secret',
    why: 'Secrecy stops friends, family or your bank from warning you.',
    re: /(do not|don't|dont)\s+(tell|inform|share this with)\s+(anyone|family|your bank)|keep (this|it) (secret|confidential)/i }
];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'cutt.ly', 'is.gd', 'rb.gy'];
const BAD_TLDS = ['.xyz', '.top', '.click', '.icu', '.buzz', '.cfd', '.sbs', '.rest', '.live'];
const BRANDS = { sbi: ['sbi.co.in', 'onlinesbi.sbi'], hdfc: ['hdfcbank.com'], icici: ['icicibank.com'], paytm: ['paytm.com'],
  amazon: ['amazon.in', 'amazon.com'], flipkart: ['flipkart.com'], google: ['google.com'], indiapost: ['indiapost.gov.in'] };

// Inspects the STRUCTURE of a URL only. The link is never opened.
function analyseUrl(raw, prefix = '') {
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : 'https://' + raw); } catch (e) { return null; }
  const h = u.hostname.toLowerCase();
  if (!/\./.test(h) && !/^\[/.test(h)) return null;
  const hits = [], add = (id, w, label, why) => hits.push({ id: 'u_' + id, w, label: prefix + label, why });
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) add('ip', 30, 'Link uses a raw IP address', 'Legitimate services use named domains, not bare IP addresses.');
  if (raw.includes('@')) add('at', 25, 'Link contains "@"', 'Text before "@" can disguise the real destination.');
  if (h.includes('xn--')) add('puny', 20, 'Punycode (look-alike characters) in domain', 'Foreign characters can imitate well-known domains.');
  if (SHORTENERS.includes(h)) add('short', 15, 'URL shortener hides the destination', 'You cannot see where the link leads.');
  if ((h.match(/-/g) || []).length >= 3 || h.split('.').length >= 5) add('struct', 15, 'Unusually long or hyphen-heavy domain', 'Scam domains often stack words and subdomains.');
  if (BAD_TLDS.some(t => h.endsWith(t))) add('tld', 15, 'Domain ending often seen in throwaway sites', 'Cheap endings are common in scam sites (but also used legitimately).');
  if (/^http:\/\//i.test(raw)) add('http', 10, 'Link is not encrypted (http)', 'Login or payment pages should use https.');
  for (const b in BRANDS) {
    if (h.includes(b) && !BRANDS[b].some(d => h === d || h.endsWith('.' + d))) {
      add('brand', 25, 'Domain imitates a known brand ("' + b + '")', 'The name appears, but the domain is not one this demo recognises as the brand\'s own.'); break;
    }
  }
  if (/(login|verify|update|secure|kyc|refund|claim|reward|prize|bonus)/.test(h)) add('kw', 10, 'Domain contains an action word (verify, claim, kyc...)', 'Scam links often use words that push you to act.');
  return hits;
}

function scoreHits(hits) {
  const seen = new Map();
  hits.forEach(h => { if (!seen.has(h.id)) seen.set(h.id, h); });   // each indicator counted once
  const list = [...seen.values()];
  let score = Math.min(100, list.reduce((a, h) => a + h.w, 0));
  if (list.length < 2) score = Math.min(score, 44);                  // one sign is never "High"
  const cat = score >= 45 ? 'High risk' : score >= 15 ? 'Moderate risk' : 'Low indicators detected';
  return { list, score, cat };
}

const SAMPLES = [
  { name: 'Fake job registration fee', text: 'Hi Riya, you are selected for a work-from-home data entry job at TalentBridge (fictional). Earn Rs. 4000 per day, guaranteed income. Pay a registration fee of Rs. 1500 within 2 hours to confirm your seat. Contact our manager on WhatsApp. Do not tell anyone about this offer.', url: '' },
  { name: 'Suspicious delivery fee', text: 'SwiftPost (fictional): your parcel is on hold. Pay a redelivery fee of Rs. 49 within 12 hours or it will be returned.', url: 'http://swiftpost-redeliver-fee.example.top/pay' },
  { name: 'Account verification message', text: 'Demo Bank alert: your account has been suspended. Reply with your OTP and card number immediately to restore access. Final notice.', url: '' },
  { name: 'Ordinary message (legitimate-looking)', text: 'Hi, this is Meera from the college library. The book you reserved is available for pickup until Friday. Please bring your ID card.', url: '' }
];
let sampleIdx = 0;

$('#chkSample').onclick = () => {
  const s = SAMPLES[sampleIdx++ % SAMPLES.length];
  $('#chkType').value = 'message'; $('#chkText').value = s.text; $('#chkUrl').value = s.url;
  $('#sampleTag').textContent = 'Loaded example: ' + s.name + ' (fictional sample, not a real report).';
  $('#chkOut').innerHTML = '';
};
$('#chkClear').onclick = () => { $('#chkText').value = ''; $('#chkUrl').value = ''; $('#sampleTag').textContent = ''; $('#chkOut').innerHTML = ''; state.check = null; };

const err = m => '<div class="err" role="alert">' + esc(m) + '</div>';

$('#chkGo').onclick = () => {
  const type = $('#chkType').value, text = $('#chkText').value.trim(), url = $('#chkUrl').value.trim(), out = $('#chkOut');
  let hits = [], notes = [], noScore = false;

  if (type === 'message') {
    if (!text && !url) return out.innerHTML = err('Nothing to analyse. Paste a message or enter a URL.');
    if (text && text.length < 15 && !url) return out.innerHTML = err('That is too short to assess. Paste the full message (at least a sentence).');
    // Remove warnings such as "never share your OTP" so they do not look like requests.
    const cleaned = text.replace(/(do not|don't|never)\s+(share|give|tell|reveal)[^.]*\./gi, ' ');
    RULES.forEach(r => { if (r.re.test(cleaned)) hits.push(r); });
    const found = text.match(/https?:\/\/[^\s]+|www\.[^\s]+/i);
    if (found) hits.push(...(analyseUrl(found[0], 'Link in message: ') || []));
  }
  if (url && type !== 'url') {
    const r = analyseUrl(url, 'URL field: ');
    if (!r) return out.innerHTML = err('The URL does not look valid. Example: https://example.com/page');
    hits.push(...r);
  }
  if (type === 'url') {
    const r = analyseUrl(url || text);
    if (!r) return out.innerHTML = err('Enter a valid URL, for example https://example.com/page.');
    hits.push(...r);
    notes.push('The link was inspected by its structure only. It was not opened, and its content and reputation were not checked.');
  }
  if (type === 'phone') {
    const digits = text.replace(/[\s()+-]/g, '');
    if (!/^\d{10,13}$/.test(digits)) return out.innerHTML = err('Enter a phone number with 10 to 13 digits, for example +91 90000 00001.');
    noScore = true;
    notes.push('The number looks well-formed, but a format check cannot say whether the caller is genuine. Numbers can be spoofed. Verify by calling the organisation\'s official number.');
  }
  if (type === 'email') {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(text)) return out.innerHTML = err('Enter a valid email address, for example name@example.com.');
    const r = analyseUrl(text.split('@')[1]);
    if (r) hits.push(...r.filter(h => ['u_brand', 'u_puny', 'u_tld', 'u_struct'].includes(h.id)));
    noScore = hits.length === 0;
    notes.push('A valid-looking email address does not show the sender is genuine. Display names and addresses can be faked.');
  }

  out.innerHTML = '<p><span class="spin"></span>Analysing locally...</p>';
  setTimeout(() => {                         // simulated processing delay (the real work is instant)
    const r = scoreHits(hits);
    const result = noScore ? { list: [], score: null, cat: 'Insufficient information' } : r;
    state.check = result;
    renderCheck(result, notes);
  }, 500);
};

function renderCheck(r, notes) {
  const cls = r.cat === 'High risk' ? 'bad' : r.cat === 'Moderate risk' ? 'warn' : r.cat === 'Insufficient information' ? 'neutral' : 'ok';
  const expl = r.score === null ? 'This check can only confirm the format. It cannot tell you whether the sender is genuine.'
    : r.list.length === 0 ? 'No rule in this prototype matched. That does not mean the message is safe: scams can use wording these rules do not cover.'
    : 'These warning signs matched. The score adds the weight of each distinct indicator (repeats are not counted twice).';
  const steps = r.cat === 'High risk' ? ['Do not reply, click, pay or share codes.', 'Verify through the organisation\'s official website or app, typed in yourself.', 'Report it (see Action Plan) and block the sender.']
    : ['Verify the sender through an official channel before acting.', 'Never share OTPs, PINs or passwords.', 'If still unsure, ask someone you trust or your bank.'];
  $('#chkOut').innerHTML = `<div class="panel">
    <div class="result"><div class="score ${cls}"><b>${r.score === null ? '–' : r.score}</b><span>/100</span></div>
    <div><span class="chip ${cls}">${r.cat}</span><p>${expl}</p></div></div>
    ${r.score !== null ? `<div class="meter ${cls}" aria-hidden="true"><i style="width:${r.score}%"></i></div>` : ''}
    <h3>Detected indicators</h3>
    ${r.list.length ? r.list.map(h => `<div class="ind"><b>${esc(h.label)}</b> <small>(weight ${h.w})</small><br><small>${esc(h.why)}</small></div>`).join('') : '<div class="empty">None detected.</div>'}
    <h3>Recommended next steps</h3><ul>${steps.map(s => '<li>' + s + '</li>').join('')}</ul>
    <p class="hint"><b>Uncertainty:</b> ${notes.concat(['This is a rule-based estimate, not proof. A low score is never a guarantee of safety.']).map(esc).join(' ')}</p>
    <div class="row"><button class="btn pri" id="toTl">Send to Journey Timeline</button><button class="btn" data-go="plan">Open Action Plan</button></div></div>`;
  $('#toTl').onclick = sendToTimeline;
}

/* ---------- Module 1 -> 2 handoff ---------- */
function sendToTimeline() {
  if (!state.check) return;
  const ids = state.check.list.map(h => h.id);
  const has = (...k) => k.some(x => ids.includes(x));
  resetTimeline();
  setQ('contact', 'yes');                               // you did receive something
  if (has('claim', 'u_kw')) setQ('offer', 'yes');
  if (has('urgent', 'secret')) setQ('urgent', 'yes');
  if (has('fee', 'paym', 'cred')) setQ('payreq', 'yes'); // a REQUEST only; payment is left Unknown
  show('timeline');
  $('#tlOut').innerHTML = '<div class="note">Some answers were pre-filled from the Scam Check indicators. Review them and answer the rest; payment attempts are left as Unknown.</div>';
}

/* =====================================================================
   MODULE 2 - JOURNEY TIMELINE
   Statuses: Reached (you said yes), Possible (unknown/attempted but a later
   stage was reached or payment unconfirmed), Predicted (next stage, no evidence
   yet), Not reached (you said no). Nothing is invented; unknowns stay Unknown.
   Payment separates: request -> attempt -> confirmed.
   ===================================================================== */
const Q = [
  ['contact', 0, 'Someone contacted me first (SMS, call, ad or direct message)'],
  ['offer', 1, 'I was offered something attractive or told something alarming (job, prize, refund, account problem)'],
  ['trust', 2, 'The sender claimed to be an official or company, or built a friendly relationship'],
  ['urgent', 3, 'I was rushed, threatened or told to keep it secret'],
  ['payreq', 4, 'I was asked for money, an OTP, a password or other valuables (request only)'],
  ['payatt', 4, 'I tried to pay or share them (attempted, may be incomplete)'],
  ['payconf', 4, 'Money left my account or the details were handed over (confirmed)'],
  ['exit', 5, 'The sender vanished, blocked me, or asked for further payments']
];
$('#tlQs').innerHTML = Q.map(q => `<div class="q"><label for="q_${q[0]}" style="margin:0">${q[2]}</label>
  <select id="q_${q[0]}"><option value="unknown">Unknown</option><option value="yes">Yes</option><option value="no">No</option></select></div>`).join('');
const setQ = (k, v) => $('#q_' + k).value = v;
function resetTimeline() { Q.forEach(q => setQ(q[0], 'unknown')); $('#tlOut').innerHTML = ''; }
$('#tlReset').onclick = resetTimeline;

$('#tlGo').onclick = () => {
  const a = {}; Q.forEach(q => a[q[0]] = $('#q_' + q[0]).value);
  if (Object.values(a).every(v => v === 'unknown')) {
    $('#tlOut').innerHTML = '<div class="empty">No events reported yet. Answer at least one question with Yes or No to build a timeline.</div>'; return;
  }
  const st = STAGES.map((name, i) => {
    const qs = Q.filter(q => q[1] === i), yes = qs.filter(q => a[q[0]] === 'yes');
    let status = 'Unknown', ev = [];
    if (i === 4) {
      if (a.payconf === 'yes') { status = 'Reached'; ev.push('You confirmed money or details were handed over.'); }
      else if (a.payatt === 'yes') { status = 'Possible'; ev.push('A payment was attempted but is not confirmed. Check with your bank.'); }
      else if (a.payreq === 'yes') {
        if (a.payatt === 'no' && a.payconf === 'no') { status = 'Not reached'; ev.push('A request was made, but you did not pay.'); }
        else { status = 'Possible'; ev.push('A request was made. No payment is confirmed.'); }
      } else if (qs.every(q => a[q[0]] === 'no')) status = 'Not reached';
    } else if (yes.length) { status = 'Reached'; ev = yes.map(q => 'You reported: ' + q[2]); }
    else if (qs.every(q => a[q[0]] === 'no')) { status = 'Not reached'; ev.push('You answered No.'); }
    return { name, status, ev, qs };
  });
  const latest = st.reduce((l, s, i) => s.status === 'Reached' ? i : l, -1);
  st.forEach((s, i) => {
    if (s.status === 'Unknown') {
      if (i < latest) { s.status = 'Possible'; s.ev.push('Not answered, but a later stage was reached, so this may have happened. Unknown.'); }
      else if (i === latest + 1 && latest >= 0) { s.status = 'Predicted'; s.ev.push('No evidence yet. Scams commonly move to this stage next. This is a pattern, not a fact.'); }
      else s.ev.push('Unknown. No information given.');
    }
  });
  const unknown = Q.filter(q => a[q[0]] === 'unknown');
  state.stage = Math.max(latest, 0); state.fromTimeline = true;
  $('#tlOut').innerHTML = `<ol class="tl">${st.map((s, i) => `<li class="s-${s.status.replace(' ', '')} ${i === latest ? 'latest' : ''}">
    <b>${s.name}</b> <span class="chip ${s.status === 'Reached' ? 'bad' : s.status === 'Possible' ? 'warn' : s.status === 'Predicted' ? 'ok' : 'neutral'}">${s.status}</span>${i === latest ? ' <small>Latest supported stage</small>' : ''}
    ${s.ev.map(e => '<small>' + esc(e) + '</small>').join('')}</li>`).join('')}</ol>
    ${unknown.length ? `<div class="panel"><h3>Follow-up questions</h3><p class="hint">These are still Unknown. Answering them makes the timeline more reliable.</p><ul>${unknown.slice(0, 4).map(q => '<li>' + esc(q[2]) + '</li>').join('')}</ul></div>` : ''}
    <div class="panel"><h3>Next steps</h3><p>${latest >= 4 ? 'Money or details may be at risk: contact your bank now and report it (see Action Plan).' : 'Stop engaging, do not pay or share codes, and verify through official channels.'}</p>
    <div class="row"><button class="btn pri" data-go="warning" id="tlWarn">Open Next-Move Warning</button><button class="btn" data-go="plan">Open Action Plan</button></div></div>`;
  $('#tlWarn').addEventListener('click', () => { $('#wStage').value = state.stage; });
};

/* =====================================================================
   MODULE 3 - NEXT-MOVE WARNING
   A lookup of commonly reported patterns per scam type. Confidence is
   based ONLY on how many typical keywords for that scam appear in the
   details you type (plus a small bonus if a timeline was built).
   It is not a statistical prediction.
   ===================================================================== */
const CATS = {
  job: { n: 'Fake job offer', kw: ['fee', 'registration', 'whatsapp', 'telegram', 'salary', 'interview', 'training', 'deposit', 'data entry', 'task'],
    seq: ['A friendly follow-up moving you to a chat app to "confirm interest"', 'A small registration or training fee', 'A refundable deposit, equipment fee, or ID documents and bank details', 'Another fee framed as a penalty or deadline, plus a request for secrecy', 'More "unlock", tax or withdrawal charges'] },
  delivery: { n: 'Delivery fee message', kw: ['parcel', 'courier', 'delivery', 'redelivery', 'customs', 'tracking', 'link', 'fee'],
    seq: ['A link to a "tracking" page', 'A small redelivery or customs fee', 'Card number and OTP to "verify" the fee', 'A larger charge, or a call from "support"', 'More small fees or card details for a "refund"'] },
  bank: { n: 'Bank impersonation', kw: ['kyc', 'otp', 'blocked', 'suspended', 'account', 'card', 'bank', 'upi', 'pin'],
    seq: ['A call or SMS about a problem such as KYC expiry or a blocked card', 'A link to a look-alike banking page, or a number to call', 'OTP, PIN, card details or net-banking login', 'A remote-access app install, or transfers to a "safe account"', 'More money moved, or a "refund" that needs another OTP'] },
  prize: { n: 'Prize or lottery', kw: ['won', 'prize', 'lottery', 'winner', 'claim', 'tax', 'processing', 'reward'],
    seq: ['A reply or click to "confirm" your win', 'Personal details to "register" the prize', 'A processing fee or tax payment', 'Extra fees such as insurance or clearance', 'Bank details or a deposit to "release" the funds'] },
  investment: { n: 'Investment promise', kw: ['returns', 'profit', 'guaranteed', 'crypto', 'usdt', 'group', 'deposit', 'trading', 'vip', 'withdraw'],
    seq: ['An invite to a group or app showing screenshots of profits', 'A small first deposit with quick "profit" on a dashboard', 'Larger deposits, often in crypto, to unlock "VIP" returns', 'Pressure to top up quickly, or fees to withdraw', 'Withdrawal taxes or "verification" payments'] },
  support: { n: 'Customer-support impersonation', kw: ['pop-up', 'virus', 'infected', 'remote', 'anydesk', 'teamviewer', 'support', 'refund', 'gift card'],
    seq: ['A pop-up or call saying your device or account is compromised', 'A request to install remote-access software', 'Access to your banking apps "to fix" it, or card details', 'Payment for a "service plan", sometimes by gift card', 'Further charges or a fake refund that needs more access'] }
};
const WHY = ['Contact so far gives little evidence; scammers usually test whether you respond.', 'A hook creates interest or fear, which usually leads to building credibility.', 'Once trust exists, requests for action or information commonly follow.', 'Pressure is usually used to get a payment or credential before you can verify.', 'Scammers who have received one payment often come back for more.', 'After an exit, victims are sometimes contacted by fake "recovery agents".'];
const PREVENT = ['Do not reply or click. Check the sender through an official channel.', 'Search the offer independently. Do not use contact details from the message.', 'Verify identity by calling an official number you looked up yourself.', 'Pause. Tell someone you trust. Real organisations allow time to verify.', 'Stop all payments. Contact your bank and report to 1930.', 'Do not pay anyone promising to recover money. Report to cybercrime.gov.in.'];

$('#wCat').innerHTML = Object.entries(CATS).map(([k, c]) => `<option value="${k}">${c.n}</option>`).join('');
$('#wStage').innerHTML = STAGES.map((s, i) => `<option value="${i}">${s}</option>`).join('');

$('#wGo').onclick = () => {
  const c = CATS[$('#wCat').value], i = +$('#wStage').value, text = $('#wText').value.toLowerCase();
  const matched = c.kw.filter(k => text.includes(k));
  const pts = matched.length + (state.fromTimeline ? 1 : 0);
  const conf = pts >= 4 ? 'High' : pts >= 2 ? 'Moderate' : 'Low';
  const next = i === 5 ? 'Someone claiming they can recover your money for a fee, or further payment requests' : c.seq[i];
  $('#wOut').innerHTML = `<div class="panel"><h3>${c.n}: current stage is ${STAGES[i]}</h3>
    <p><b>Possible next request:</b> ${esc(next)}</p>
    <p><b>Why:</b> ${WHY[i]}${matched.length ? ' Your details mention: ' + matched.map(esc).join(', ') + '.' : ''}</p>
    <p><b>Confidence:</b> <span class="chip ${conf === 'Low' ? 'neutral' : conf === 'Moderate' ? 'warn' : 'bad'}">${conf}</span>
    <span class="hint">${conf === 'Low' ? 'Little supporting detail was provided, so this is a general pattern only.' : 'Based on how many typical details you entered.'}</span></p>
    <p><b>Preventive action:</b> ${PREVENT[i]}</p>
    <p class="hint">These are commonly reported patterns, not guaranteed future events.</p>
    <div class="row"><button class="btn pri" id="wPlan">Open Action Plan</button></div></div>`;
  $('#wPlan').onclick = () => { if (i >= 4) planFlags.paid = true; planFlags.received = true; renderPlan(); show('plan'); };
};

/* =====================================================================
   MODULE 4 - SCAM SIMULATOR (fictional scenarios only)
   ===================================================================== */
const SCEN = [
  { t: 'Fake job offer', m: 'TalentBridge Careers (fictional): Work from home data entry, Rs. 4,000/day guaranteed! Pay a Rs. 1,500 registration fee to 90000-00001@demo today to confirm your seat.', flags: 'Advance fee, guaranteed income, artificial deadline', safe: 'Do not pay. Check the company on its own website and ask for an official email.',
    o: [['Pay the fee so I don\'t lose the seat', 0, 'Paying a fee to get a job is the central red flag.'], ['Ask for an official email, then check the company\'s careers site myself', 1, 'Correct. Independent verification interrupts the scam.'], ['Send my Aadhaar to prove I\'m serious', 0, 'Sharing ID documents invites identity misuse.'], ['Negotiate the fee down', 0, 'Negotiating still treats the offer as real.']] },
  { t: 'Delivery fee', m: 'SwiftPost (fictional): Parcel on hold. Pay Rs. 49 at swiftpost-redeliver.example within 12 hours or it will be returned.', flags: 'Look-alike domain, small fee, deadline', safe: 'Check tracking on the courier\'s official app or site that you type yourself.',
    o: [['Tap the link, it is only Rs. 49', 0, 'Small amounts lower your guard; the page may capture card details.'], ['Check tracking on the courier\'s official site, typed myself', 1, 'Correct.'], ['Pay but skip entering the OTP', 0, 'Card details alone can still be misused.'], ['Forward it to friends as a warning, with the link', 0, 'Forwarding the live link spreads risk. Share a screenshot without the link.']] },
  { t: 'Bank impersonation', m: 'Demo Bank alert (fictional): KYC expires today. Reply with your OTP or call 080-0000-0000 to keep your account active.', flags: 'Credential request, deadline, number supplied by the sender', safe: 'Ignore it. Call the bank using the number on your card or its official app.',
    o: [['Reply with the OTP', 0, 'Banks never ask for OTPs.'], ['Call the number in the message', 0, 'That number may connect to the scammer.'], ['Ignore the message and call the number on my card', 1, 'Correct.'], ['Reply asking which bank it is', 0, 'Replying confirms your number is active.']] },
  { t: 'Prize or lottery', m: 'Congratulations! You won Rs. 25 lakh in LuckyDraw 2026 (fictional). Pay Rs. 2,999 tax to claim today.', flags: 'Unexpected prize, fee to claim, deadline', safe: 'Delete and report. You cannot win a draw you never entered.',
    o: [['Pay the tax to claim it', 0, 'Genuine prizes do not need an upfront fee.'], ['Ask for a video call to confirm it\'s real', 0, 'Scammers can fake proof easily.'], ['Delete and report it', 1, 'Correct.'], ['Share my bank details so they can deposit it', 0, 'This gives access to your account.']] },
  { t: 'Investment promise', m: 'Join our VIP group (fictional). Our AI trading bot gives 5% daily returns, guaranteed. Minimum deposit 10,000 USDT-equivalent.', flags: 'Guaranteed returns, crypto deposit, "AI" hype', safe: 'Decline. No legitimate investment guarantees returns; check regulator registration.',
    o: [['Deposit a small amount to test', 0, 'Early small "profits" are used to lure bigger deposits.'], ['Decline and check whether the firm is registered with the regulator', 1, 'Correct.'], ['Invite a friend so we both earn', 0, 'This spreads the harm.'], ['Ask them to show recent withdrawals', 0, 'Screenshots are easily faked.']] },
  { t: 'Customer support impersonation', m: 'Pop-up: "Your PC is infected! Call TechCare Support 1800-000-0000 now" (fictional). The agent asks you to install a remote tool.', flags: 'Fear tactic, remote-access request', safe: 'Close the pop-up and run your own antivirus. Never allow remote access.',
    o: [['Install the tool so they can fix it', 0, 'Remote access lets them see and control your device.'], ['Close the page, don\'t call, run my own antivirus', 1, 'Correct.'], ['Give a card number for the service fee', 0, 'Card details would be stolen.'], ['Call, but only share my name', 0, 'Calling starts the manipulation.']] }
];
let sim = { i: 0, score: 0, answered: false };
function renderSim() {
  const b = $('#simBox');
  if (sim.i >= SCEN.length) {
    const s = sim.score, msg = s >= 5 ? 'Strong. You verified independently in most cases.' : s >= 3 ? 'Good start. Review the scenarios you missed.' : 'Keep practising. Look for fees, deadlines and requests for codes.';
    b.innerHTML = `<h2>Result: ${s} / ${SCEN.length}</h2><p>${msg}</p><div class="row"><button class="btn pri" id="simAgain">Try again</button><button class="btn" data-go="home">Back to dashboard</button></div>`;
    $('#simAgain').onclick = () => { sim = { i: 0, score: 0, answered: false }; renderSim(); }; return;
  }
  const c = SCEN[sim.i];
  b.innerHTML = `<p class="hint">Scenario ${sim.i + 1} of ${SCEN.length} · Score ${sim.score} · <span class="chip neutral">Simulation</span></p>
    <progress value="${sim.i}" max="${SCEN.length}" aria-label="Progress"></progress>
    <h2>${c.t}</h2><div class="sim-msg">${esc(c.m)}</div>
    <div class="opts">${c.o.map((o, k) => `<button class="btn" data-k="${k}">${esc(o[0])}</button>`).join('')}</div><div id="fb"></div>`;
  $$('.opts .btn').forEach(btn => btn.onclick = () => {
    if (sim.answered) return; sim.answered = true;
    const o = c.o[+btn.dataset.k], ok = o[1] === 1; if (ok) sim.score++;
    $$('.opts .btn').forEach(x => x.disabled = true);
    $('#fb').innerHTML = `<div class="fb ${ok ? 'ok' : 'bad'}" role="status"><b>${ok ? 'Safe choice' : 'Unsafe choice'}</b><p>${esc(o[2])}</p>
      <p><b>Red flags:</b> ${c.flags}</p><p><b>Safest action:</b> ${c.safe}</p>
      <button class="btn pri" id="simNext">${sim.i + 1 === SCEN.length ? 'See result' : 'Next scenario'}</button></div>`;
    $('#simNext').onclick = () => { sim.i++; sim.answered = false; renderSim(); };
  });
}

/* =====================================================================
   MODULE 5 - NETWORK MAP (fictional data, drawn with SVG)
   ===================================================================== */
const TYPES = { report: ['Report', '#2dd4c0'], phone: ['Phone number', '#f0b84a'], domain: ['Domain', '#7aa2f7'], wallet: ['Wallet ID', '#f07070'], email: ['Email', '#b48ef0'] };
const NODES = [
  { id: 'RA', t: 'report', l: 'Report A', x: 70, y: 70, d: 'Sample delivery-fee SMS. The victim did not pay.' },
  { id: 'RB', t: 'report', l: 'Report B', x: 70, y: 190, d: 'Sample phone call about a "held parcel". The victim paid Rs. 49 (fictional).' },
  { id: 'RC', t: 'report', l: 'Report C', x: 70, y: 310, d: 'Sample job offer asking for a registration fee.' },
  { id: 'P1', t: 'phone', l: '+91 90000 00001', x: 300, y: 80, d: 'Fictional number that sent or made the contact in Reports A and B.' },
  { id: 'D1', t: 'domain', l: 'swiftpost-fee.example', x: 300, y: 190, d: 'Fictional look-alike courier domain linked in Reports A and B.' },
  { id: 'D2', t: 'domain', l: 'talentbridge-reg.example', x: 300, y: 310, d: 'Fictional job-portal look-alike domain from Report C.' },
  { id: 'W1', t: 'wallet', l: 'WALLET-DEMO-7F3A', x: 540, y: 190, d: 'Fictional payment identifier requested in Reports B and C.' },
  { id: 'E1', t: 'email', l: 'hr@talentbridge-reg.example', x: 540, y: 310, d: 'Fictional sender address in Report C.' }
];
const EDGES = [['RA', 'P1', 'Same sender number'], ['RB', 'P1', 'Same number appeared in both reports'], ['RA', 'D1', 'Message link used this domain'], ['RB', 'D1', 'Victim was sent to this domain'],
  ['RB', 'W1', 'Payment was requested to this wallet'], ['RC', 'W1', 'Same wallet ID requested for the fee'], ['RC', 'D2', 'Offer linked to this domain'], ['RC', 'E1', 'Email came from this address'], ['E1', 'D2', 'Email domain matches']];
let sel = null;
const node = id => NODES.find(n => n.id === id);
const nbrs = id => EDGES.filter(e => e[0] === id || e[1] === id).map(e => ({ n: node(e[0] === id ? e[1] : e[0]), why: e[2] }));

function drawNet() {
  const q = $('#nSearch').value.trim().toLowerCase(), ty = $('#nType').value;
  const match = n => (!ty || n.t === ty) && (!q || (n.l + ' ' + n.d + ' ' + TYPES[n.t][0]).toLowerCase().includes(q));
  $('#net').innerHTML = EDGES.map(e => { const a = node(e[0]), b = node(e[1]); return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${sel && (sel === a.id || sel === b.id) ? '#2dd4c0' : '#3a5078'}" stroke-width="${sel && (sel === a.id || sel === b.id) ? 3 : 1.5}"><title>${esc(e[2])}</title></line>`; }).join('') +
    NODES.map(n => `<g class="node ${match(n) ? '' : 'dim'}" data-id="${n.id}" tabindex="0" role="button" aria-label="${esc(TYPES[n.t][0] + ': ' + n.l)}">
      <circle cx="${n.x}" cy="${n.y}" r="${n.t === 'report' ? 24 : 18}" fill="${TYPES[n.t][1]}" stroke="${sel === n.id ? '#fff' : 'none'}" stroke-width="3"/>
      <text x="${n.x}" y="${n.y + (n.t === 'report' ? 40 : 34)}">${esc(n.l)}</text></g>`).join('');
  $$('#net .node').forEach(g => { g.onclick = () => pick(g.dataset.id); g.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(g.dataset.id); } }; });
  const hidden = NODES.filter(match).length === 0;
  if (hidden) $('#nDetail').innerHTML = '<div class="empty">No nodes match that search. Clear the filter to see the whole network.</div>';
}
function pick(id) {
  sel = id; const n = node(id);
  $('#nDetail').innerHTML = `<h3>${esc(n.l)} <span class="chip neutral">${TYPES[n.t][0]}</span></h3><p>${esc(n.d)}</p>
    <h3>Connections</h3><ul>${nbrs(id).map(x => `<li><b>${esc(x.n.l)}</b>: ${esc(x.why)}</li>`).join('')}</ul>
    <p class="hint">Sample data. A shared indicator is a clue, not proof of the same owner or of guilt.</p>`;
  drawNet();
}
$('#legend').innerHTML = Object.values(TYPES).map(t => `<span><i style="background:${t[1]}"></i>${t[0]}</span>`).join('') + '<span>Line = shared indicator (hover for reason)</span>';
$('#nReports').innerHTML = NODES.filter(n => n.t === 'report').map(n => `<li><span><b>${n.l}</b> <span class="chip neutral">Sample</span><br><small class="hint">${esc(n.d)}</small></span><button class="btn" data-rep="${n.id}">Inspect</button></li>`).join('');
$$('[data-rep]').forEach(b => b.onclick = () => pick(b.dataset.rep));
$('#nSearch').oninput = drawNet; $('#nType').onchange = drawNet;
drawNet();

/* =====================================================================
   MODULE 6 - ACTION PLAN (checklist adapts to what happened)
   Progress is held in memory only. We cannot promise recovery of money
   or accounts.
   ===================================================================== */
const planFlags = { received: false, clicked: false, shared: false, installed: false, paid: false, lost: false };
const PQ = [['received', 'I received a suspicious message or call'], ['clicked', 'I clicked a link'], ['shared', 'I shared sensitive information (OTP, password, card or ID details)'],
  ['installed', 'I installed an unfamiliar app'], ['paid', 'I made or attempted a payment'], ['lost', 'I lost access to an account']];
const ITEMS = [
  ['Stop replying to the sender. Do not send more money or share OTPs, passwords or PINs.', f => true],
  ['Call your bank or payment provider right away. Ask them to block the card or transaction and flag the fraud.', f => f.paid || f.shared],
  ['Report financial fraud promptly: call 1930 (National Cyber Crime helpline) and file at https://cybercrime.gov.in. Quick reporting gives the best chance, but recovery is not guaranteed.', f => f.paid],
  ['Change affected passwords from a trusted device and turn on two-step verification.', f => f.shared || f.lost || f.clicked],
  ['Uninstall the unfamiliar app, remove its permissions (accessibility, device admin, screen sharing), and run a trusted security scan.', f => f.installed],
  ['Do not enter more details on the page you opened. Close it and check your downloads for files you did not expect.', f => f.clicked],
  ['Use the official account-recovery page, sign out other sessions and revoke unknown apps. Warn your contacts if the account was used to message them.', f => f.lost],
  ['Save screenshots, phone numbers, links, UPI/transaction references and dates before deleting anything.', f => f.received || f.paid || f.shared],
  ['Report the sender to the platform (WhatsApp, Telegram, SMS or email provider) and block them. You can also report at cybercrime.gov.in.', f => f.received],
  ['Beware of "recovery agents" who ask for a fee to get your money back. They are a common second scam.', f => f.paid || f.shared]
];
let done = new Set();
$('#planQs').innerHTML = PQ.map(q => `<label><input type="checkbox" data-f="${q[0]}"><span>${q[1]}</span></label>`).join('');
$$('#planQs input').forEach(i => i.onchange = () => { planFlags[i.dataset.f] = i.checked; done = new Set(); renderPlan(); });
function renderPlan() {
  $$('#planQs input').forEach(i => i.checked = planFlags[i.dataset.f]);
  const list = ITEMS.map((it, k) => [it[0], it[1](planFlags), k]).filter(x => x[1] && Object.values(planFlags).some(Boolean));
  if (!list.length) { $('#planOut').innerHTML = '<div class="empty">Select at least one option above to generate your checklist.</div>'; return; }
  const n = list.filter(x => done.has(x[2])).length;
  $('#planOut').innerHTML = `<div class="panel">${planFlags.paid || planFlags.shared ? '<div class="err">Financial fraud is time-sensitive. Report it as soon as possible.</div>' : ''}
    <h3>Your checklist: ${n} of ${list.length} done</h3><progress value="${n}" max="${list.length}"></progress>
    <div class="checks">${list.map(x => `<label class="${done.has(x[2]) ? 'done' : ''}"><input type="checkbox" data-k="${x[2]}" ${done.has(x[2]) ? 'checked' : ''}><span>${esc(x[0])}</span></label>`).join('')}</div>
    <p class="hint">Following these steps does not guarantee that money or accounts will be recovered. Progress is not saved if you refresh.</p>
    <div class="row"><button class="btn" id="planReset">Reset checklist</button></div></div>`;
  $$('#planOut [data-k]').forEach(c => c.onchange = () => { c.checked ? done.add(+c.dataset.k) : done.delete(+c.dataset.k); renderPlan(); });
  $('#planReset').onclick = () => { done = new Set(); Object.keys(planFlags).forEach(k => planFlags[k] = false); renderPlan(); };
}

/* ---------- Home: sample activity ---------- */
$('#recent').innerHTML = SAMPLES.slice(0, 3).map((s, i) => `<li><span>${s.name} <span class="chip neutral">Sample</span></span><button class="btn" data-demo="${i}">Open in Scam Check</button></li>`).join('');
$$('[data-demo]').forEach(b => b.onclick = () => { sampleIdx = +b.dataset.demo; show('check'); $('#chkSample').click(); });

/* ---------- Start ---------- */
renderSim(); renderPlan(); show('home');
