// BENIGN. This demo target does nothing — no network, no data access, no harm. It exists only to *look*
// like a rogue extension to the attack EDR (it is dev-loaded, requests high-risk permissions, and asks for
// all-URLs host access), so the T1176.001 rule detects and disables it. Safe to load and remove.
console.log('[demo-target] Totally Not Evil loaded — I do nothing. The attack EDR should disable me.');
