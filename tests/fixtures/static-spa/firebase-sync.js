// Firebase Sync Engine — Google Auth + Firestore cloud save/load

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

let currentUser = null;
let isSyncing = false;

// ── SIGN IN / OUT ─────────────────────────────────────────────
function signInWithGoogle() {
  const provider = new firebase.auth.GoogleAuthProvider();
  auth.signInWithPopup(provider).catch(err => {
    console.error("Sign-in error:", err.code, err.message);
    if (err.code === "auth/unauthorized-domain") {
      showAuthToast("❌ Domain not authorized in Firebase. See setup instructions.", "error");
      alert('Firebase setup needed!\n\n1. Go to: https://console.firebase.google.com/project/tejaswisummer/authentication/settings\n2. Scroll to "Authorized domains"\n3. Click "Add domain"\n4. Add: tejaswierattu.github.io\n5. Click Save — then try again!');
    } else if (err.code === "auth/popup-blocked") {
      showAuthToast("❌ Popup blocked — please allow popups for this site.", "error");
    } else {
      showAuthToast(`❌ Sign-in failed: ${err.code}`, "error");
    }
  });
}

async function signOutFirebase() {
  // Push any debounced change up before the session ends. js/auth-gate.js wipes
  // local progress right after sign-out, so anything not flushed here is lost.
  try {
    if (currentUser) await saveStateToFirestore();
  } catch (e) {
    console.error("Pre-sign-out flush failed:", e);
  }
  auth.signOut().then(() => {
    showAuthToast("Signed out. Progress is safe in your Google account.", "info");
  });
}

// ── AUTH STATE LISTENER ───────────────────────────────────────
auth.onAuthStateChanged(async (user) => {
  currentUser = user;
  updateAuthUI(user);

  if (user) {
    // User just signed in — load their cloud state
    showAuthToast("Loading your cloud save...", "info");
    await loadStateFromFirestore();
    if (typeof migrateScheduleIfNeeded === "function") {
      migrateScheduleIfNeeded(); // upgrade older cloud schedules (adds Palana onboarding prep)
    }
    if (typeof maybeAutoRepairRollover === "function") {
      maybeAutoRepairRollover(); // one-time fix for old multi-day rollover damage (cloud state)
    }
    if (typeof applyCategoryColors === "function") {
      applyCategoryColors(); // sync edited category colors from cloud state into CSS vars
    }
    initUI();
    showAuthToast(`Synced ☁️ Welcome back, ${user.displayName?.split(' ')[0] || 'hacker'}!`, "success");
  }
});

// ── SAVE TO FIRESTORE ─────────────────────────────────────────
async function saveStateToFirestore() {
  if (!currentUser || isSyncing) return;
  isSyncing = true;
  try {
    const { rolloverUndoSnapshot, ...persistable } = appState;
    await db.collection("users").doc(currentUser.uid).set({
      state: JSON.stringify(persistable),
      updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
      displayName: currentUser.displayName,
      email: currentUser.email
    });
  } catch (e) {
    console.error("Firebase save error:", e.code, e.message);
    if (e.code === "permission-denied") {
      showAuthToast("☁️ Cloud blocked by Firestore rules — see setup. Saved locally.", "error");
    } else {
    }
  } finally {
    isSyncing = false;
  }
}

// Trimmed for the fixture: the local fallback write.
function saveLocal() {
  localStorage.setItem("cyber_study_plan_state_2026", JSON.stringify(appState));
}
