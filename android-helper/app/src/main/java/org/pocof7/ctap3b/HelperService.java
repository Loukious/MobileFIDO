package org.pocof7.ctap3b;

import android.app.Service;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.hardware.biometrics.BiometricManager;
import android.net.Credentials;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Binder;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Process;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Single-client, app-owned broker. AF_UNIX ABSTRACT socket grants access
 * only to root in the Android user namespace. No TCP listener and no INTERNET
 * permission. The bound Binder is exported=false and used by our own Activity.
 *
 * JSON v1: 4-byte BE length + UTF-8 JSON (1..65536 bytes); one request/socket.
 * Requests: {v:1,id:hex,op:getInfo|makeCredential|getAssertion,params:{...}}
 * Interim:  {v:1,id:hex,event:user_presence_required}
 * Replies:  {v:1,id:hex,ok:true,result:{...}} or {v:1,id:hex,ok:false,error:...}
 *
 * The socket survives the Activity being backgrounded using an opt-in
 * foreground service. An incoming CTAP operation posts a user-tappable
 * notification. No background Activity launches and no signature without
 * successful foreground BiometricPrompt.CryptoObject.
 */
public final class HelperService extends Service {
    static final String SOCKET_NAME = "ctaphid-m3b-v1";
    private static final String LOG_TAG = "Ctap3bHelper";
    private static final String LISTENER_CHANNEL = "ctap3b_listener";
    private static final String APPROVAL_CHANNEL = "ctap3b_authorization";
    private static final int LISTENER_ID = 1201;
    static final String ACTION_OPEN_APPROVAL = "org.pocof7.ctap3b.OPEN_APPROVAL";
    static final String EXTRA_APPROVAL_TOKEN = "org.pocof7.ctap3b.APPROVAL_TOKEN";
    private static final int MAX_FRAME = 65536;
    // Allow time to notice the request, unlock the phone, tap notification,
    // and authenticate. Native IPC deadline + CTAPHID CBOR deadline MUST
    // exceed this (native worker is coordinating 65s / 70s respectively).
    private static final long TIMEOUT_MS = 60000L;
    private static final int KEYSTORE_STARTUP_ATTEMPTS = 12;
    private static final long KEYSTORE_RETRY_MS = 2000L;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final LocalBinder binder = new LocalBinder();
    private final SecureRandom random = new SecureRandom();
    private final Object operationLock = new Object();
    private final AtomicInteger activeSockets = new AtomicInteger();
    private NotificationManager notifications;
    private volatile UiBridge ui;
    private volatile LocalServerSocket listener;
    private volatile boolean running;
    private Operation active;
    private boolean maintenanceActive;
    private long maintenanceToken;
    CryptoKeyManager keys;

    public interface UiBridge {
        void onOperation(Operation operation);
        /** Bound alone does not imply the Activity is visible or RESUMED. */
        boolean isReadyForPrompt();
    }

    /** Internal app-only Binder; the service is never exported. */
    public final class LocalBinder extends Binder {
        public HelperService service() {
            if (getCallingUid() != Process.myUid()) {
                throw new SecurityException("Binder caller is not the helper app");
            }
            return HelperService.this;
        }
        public void attach(UiBridge bridge) {
            if (getCallingUid() != Process.myUid()) {
                throw new SecurityException("Binder caller is not the helper app");
            }
            ui = bridge;
            // A CTAP operation may have arrived while the Activity was
            // backgrounded. Restore only the single CURRENT live operation;
            // never queue/store challenges in a notification or Intent.
            Operation waiting;
            synchronized (operationLock) {
                waiting = active;
            }
            if (waiting != null && !waiting.isDone()) {
                main.post(() -> {
                    if (ui == bridge && !waiting.isDone()) {
                        deliverOrNotify(waiting);
                    }
                });
            }
        }

        /** Activity lifecycle transitions repair the attach/onResume race. */
        public void uiStateChanged(UiBridge bridge) {
            if (getCallingUid() != Process.myUid()) {
                throw new SecurityException("Binder caller is not the helper app");
            }
            if (ui != bridge) return;
            Operation waiting;
            synchronized (operationLock) { waiting = active; }
            if (waiting != null && !waiting.isDone()) {
                main.post(() -> {
                    if (ui == bridge && !waiting.isDone()) deliverOrNotify(waiting);
                });
            }
        }

        public void detach(UiBridge bridge) {
            // An older Activity may stop after a newer one attached; never
            // cancel the new screen's live approval from the old instance.
            if (ui != bridge) return;
            ui = null;
            Operation pending;
            synchronized (operationLock) { pending = active; }
            // If Activity goes away during a biometric attempt, its CryptoObject
            // is no longer a safe consent surface. A notification-only request
            // is NOT cancelled unless already claimed by that Activity.
            if (pending != null && pending.promptClaimed.get()) {
                pending.cancel("CANCELLED");
            } else if (pending != null && !pending.isDone()) {
                notifyApproval(pending);
            }
        }

        public void demo(String requestType, String credentialId, UiBridge bridge) {
            if (getCallingUid() != Process.myUid()) {
                throw new SecurityException("Binder caller is not the helper app");
            }
            try {
                JSONObject params = new JSONObject();
                params.put("rpId", CryptoKeyManager.RP_ID);
                byte[] hash = new byte[32];
                random.nextBytes(hash);
                params.put("clientDataHash", CryptoKeyManager.encode(hash));
                if ("makeCredential".equals(requestType)) {
                    params.put("userId", CryptoKeyManager.encode(
                        "LOCAL_UI_DEMO".getBytes(StandardCharsets.US_ASCII)));
                    params.put("excludeIds", new JSONArray());
                    params.put("up", true);
                    params.put("residentKey", false);
                } else {
                    params.put("allowIds", new JSONArray().put(credentialId));
                    params.put("up", true);
                }
                JSONObject request = new JSONObject();
                request.put("v", 1);
                request.put("id", Long.toHexString(random.nextLong()).replace("-", "0"));
                request.put("op", requestType);
                request.put("params", params);
                Operation operation = prepare(request);
                if (operation == null) throw new IllegalStateException("operation busy");
                if (ui != bridge) {
                    operation.cancel("NOT_ALLOWED");
                    return;
                }
                main.post(() -> bridge.onOperation(operation));
            } catch (Exception error) {
                if (bridge instanceof MainActivity) {
                    ((MainActivity) bridge).showStatus("Local demo request rejected");
                }
            }
        }

        public String status() {
            if (!running || listener == null) return "root-only socket unavailable";
            return "root-only socket ready: " + SOCKET_NAME +
                (canNotifyApproval()
                    ? "\nTap a security-key approval notification when your PC requests it."
                    : "\nNotifications unavailable: keep app visible for CTAP or enable " +
                      "app notifications in Android Settings.");
        }

        /** Called only after the Activity actually claims the CURRENT prompt. */
        public void approvalClaimed(Operation operation, UiBridge bridge) {
            if (getCallingUid() != Process.myUid()) {
                throw new SecurityException("Binder caller is not the helper app");
            }
            synchronized (operationLock) {
                if (ui == bridge && active == operation && operation.promptClaimed.get()) {
                    dismissApprovalNotification(operation);
                }
            }
        }

        /** Never race a credential deletion with an active browser request. */
        public void deleteCredential(String credentialId, String rpId) throws Exception {
            if (getCallingUid() != Process.myUid()) {
                throw new SecurityException("Binder caller is not the helper app");
            }
            synchronized (operationLock) {
                if (active != null || maintenanceActive || keys == null) {
                    throw new IllegalStateException("Security-key operation pending");
                }
                keys.deleteCredential(credentialId, rpId);
            }
        }

        /**
         * Serialize recovery export/import against CTAP makeCredential and
         * getAssertion. Recovery temporarily handles portable private-key
         * material, so it must never race a browser signing/registration
         * request. This flag does not stop the root socket; new CTAP requests
         * simply fail closed until the user finishes/cancels maintenance.
         */
        public long beginRecoveryMaintenance() {
            if (getCallingUid() != Process.myUid()) {
                throw new SecurityException("Binder caller is not the helper app");
            }
            synchronized (operationLock) {
                if (active != null || maintenanceActive || keys == null) return 0L;
                long token;
                do { token = random.nextLong(); } while (token == 0L);
                maintenanceActive = true;
                maintenanceToken = token;
                return token;
            }
        }

        public void endRecoveryMaintenance(long token) {
            if (getCallingUid() != Process.myUid()) {
                throw new SecurityException("Binder caller is not the helper app");
            }
            synchronized (operationLock) {
                // A stale Activity must never release a newer screen's
                // recovery lock after recreation/rotation.
                if (maintenanceActive && token != 0L && token == maintenanceToken) {
                    maintenanceActive = false;
                    maintenanceToken = 0L;
                }
            }
        }
    }

    public static final class Operation {
        public final String id;
        public final String op;
        public final String rpId;
        public final byte[] clientDataHash;
        public final byte[] userId;
        public final String userName;
        public final String displayName;
        public volatile String credentialId;
        public final boolean up;
        public final boolean excluded;
        public final boolean discoverable;
        public final List<CryptoKeyManager.CredentialInfo> accountChoices;
        public final CancellationSignal cancelSignal = new CancellationSignal();
        // One user-visible BiometricPrompt attempt per CTAP operation, even
        // if the Activity is recreated/reattaches or receives duplicate intents.
        final AtomicBoolean promptClaimed = new AtomicBoolean(false);
        final AtomicBoolean completed = new AtomicBoolean(false);
        final CountDownLatch done = new CountDownLatch(1);
        volatile JSONObject response;
        volatile CryptoKeyManager.CreatedKey newKey;
        final String notificationToken;
        final int notificationId;
        final HelperService parent;

        Operation(HelperService parent, String id, String op, String rpId, byte[] hash,
                  byte[] userId, String userName, String displayName,
                  String credentialId, boolean up, boolean excluded,
                  boolean discoverable,
                  List<CryptoKeyManager.CredentialInfo> accountChoices) {
            this.parent = parent;
            this.id = id;
            this.op = op;
            this.rpId = rpId;
            this.clientDataHash = hash;
            this.userId = userId;
            this.userName = userName;
            this.displayName = displayName;
            this.credentialId = credentialId;
            this.up = up;
            this.excluded = excluded;
            this.discoverable = discoverable;
            this.accountChoices = Collections.unmodifiableList(accountChoices);
            byte[] token = new byte[16];
            parent.random.nextBytes(token);
            this.notificationToken = CryptoKeyManager.encode(token);
            this.notificationId = 3000 + parent.random.nextInt(Integer.MAX_VALUE - 3000);
        }

        public synchronized void success(JSONObject result) {
            if (completed.compareAndSet(false, true)) {
                response = ok(id, result);
                done.countDown();
                parent.finished(this);
            }
        }

        public synchronized void cancel(String error) {
            if (completed.compareAndSet(false, true)) {
                cancelSignal.cancel();
                response = err(id, error);
                parent.keys.discardUncommitted(newKey);
                done.countDown();
                parent.finished(this);
            }
        }

        public boolean isDone() {
            return completed.get();
        }

        /** Account selection is a foreground UI action, never a host-supplied
         * credential hint. The key is rechecked against the RP before use.
         */
        public boolean selectAccount(String credentialId) {
            synchronized (parent.operationLock) {
                if (!discoverable || parent.active != this || isDone()
                    || promptClaimed.get() || this.credentialId != null) return false;
                for (CryptoKeyManager.CredentialInfo account : accountChoices) {
                    if (account.available && account.discoverable
                        && rpId.equals(account.rpId)
                        && account.credentialId.equals(credentialId)
                        && parent.keys.hasCredential(credentialId, rpId)) {
                        this.credentialId = credentialId;
                        return true;
                    }
                }
                return false;
            }
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        // MUST promote quickly after startForegroundService from a cold boot.
        // Keystore.load / OEM StrongBox initialization can be slow; doing it
        // before startForeground risks Android's foreground-service timeout,
        // killing the listener until the user manually reopens the Activity.
        if (!startPersistentListener()) {
            Log.w(LOG_TAG, "Foreground service could not start: authorization alerts unavailable");
            stopSelf();
            return;
        }
        running = true;
        // Keystore can initialize slowly/transiently fail immediately after
        // first user unlock. Keep cold boot initialization off Android's main
        // thread and retry for a bounded period instead of requiring a user
        // to foreground-authenticate once merely to warm up the listener.
        Thread socketThread = new Thread(this::initializeAndServe,
            "ctap3b-private-root-socket");
        socketThread.setDaemon(true);
        socketThread.start();
    }

    private void initializeAndServe() {
        for (int attempt = 1; running && attempt <= KEYSTORE_STARTUP_ATTEMPTS; attempt++) {
            try {
                CryptoKeyManager manager = new CryptoKeyManager(this);
                if (!running) return;
                keys = manager;
                serve();
                return;
            } catch (Exception failed) {
                Log.w(LOG_TAG, "Keystore startup attempt " + attempt + " failed: " +
                    CryptoKeyManager.safeExceptionClasses(failed));
                if (attempt < KEYSTORE_STARTUP_ATTEMPTS && running) {
                    SystemClock.sleep(KEYSTORE_RETRY_MS);
                }
            }
        }
        if (running) {
            Log.w(LOG_TAG, "Keystore unavailable after bounded boot retries; stopping listener");
            main.post(this::stopSelf);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        // Started explicitly when the user launches the Activity. Android
        // may restart a previously authorized foreground service but never
        // start the Activity or a biometric prompt by itself.
        return running ? START_STICKY : START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        running = false;
        Operation pending;
        synchronized (operationLock) { pending = active; }
        if (pending != null) pending.cancel("CANCELLED");
        if (pending != null) dismissApprovalNotification(pending);
        try {
            if (listener != null) listener.close();
        } catch (Exception ignored) {}
        super.onDestroy();
    }

    private void finished(Operation operation) {
        synchronized (operationLock) {
            if (active == operation) active = null;
        }
        dismissApprovalNotification(operation);
    }

    private PendingIntent launcherIntent(String token) {
        Intent launch = new Intent(this, MainActivity.class)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK |
                      Intent.FLAG_ACTIVITY_SINGLE_TOP |
                      Intent.FLAG_ACTIVITY_CLEAR_TOP);
        if (token != null) {
            launch.setAction(ACTION_OPEN_APPROVAL);
            launch.putExtra(EXTRA_APPROVAL_TOKEN, token);
            // Unique PendingIntent identity per operation: a stale tap must
            // never be retargeted silently to the following CTAP request.
            launch.setData(android.net.Uri.parse("ctap3b://authorization/" + token));
        }
        return PendingIntent.getActivity(this, token == null ? 0 : 1,
            launch, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    private boolean startPersistentListener() {
        notifications = getSystemService(NotificationManager.class);
        if (notifications == null) return false;
        notifications.createNotificationChannel(new NotificationChannel(
            LISTENER_CHANNEL, "Hardware security key service",
            NotificationManager.IMPORTANCE_LOW));
        notifications.createNotificationChannel(new NotificationChannel(
            APPROVAL_CHANNEL, "Security key approval requests",
            NotificationManager.IMPORTANCE_HIGH));
        Notification serviceNotification = listenerNotification(false);
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(LISTENER_ID, serviceNotification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                // specialUse was added in API 34; this app still supports
                // API 31-33, where an unknown service type must not be used.
                startForeground(LISTENER_ID, serviceNotification);
            }
            return true;
        } catch (RuntimeException rejected) {
            // No fallback background service: it would be stopped and would
            // misleadingly claim to be listening with no notification.
            Log.w(LOG_TAG, "Foreground service rejected: " +
                rejected.getClass().getSimpleName());
            return false;
        }
    }

    private Notification listenerNotification(boolean ready) {
        return new Notification.Builder(this, LISTENER_CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(ready
                ? "Hardware security key ready"
                : "Starting hardware security-key listener")
            .setContentText(ready
                ? "Tap to open biometric security-key helper"
                : "Waiting for AndroidKeyStore and the local root-only socket")
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(launcherIntent(null))
            .build();
    }

    boolean canNotifyApproval() {
        if (notifications == null || !notifications.areNotificationsEnabled()) return false;
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(
                Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        NotificationChannel channel = notifications.getNotificationChannel(APPROVAL_CHANNEL);
        return channel != null && channel.getImportance() != NotificationManager.IMPORTANCE_NONE;
    }

    private void notifyApproval(Operation operation) {
        if (operation.isDone() || operation.promptClaimed.get()) return;
        if (!canNotifyApproval()) {
            // While a foreground Activity is requesting notification
            // permission, defer. If it leaves without permission, detach()
            // will reach here with ui=null and fail the request closed.
            if (ui == null) operation.cancel("NOT_ALLOWED");
            return;
        }
        String label = "makeCredential".equals(operation.op)
            ? "Register hardware security key" : "Approve security-key sign-in";
        Notification alert = new Notification.Builder(this, APPROVAL_CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(label)
            .setContentText("Tap to open the app and confirm with your fingerprint")
            .setCategory(Notification.CATEGORY_EVENT)
            .setAutoCancel(true)
            .setTimeoutAfter(TIMEOUT_MS)
            .setContentIntent(launcherIntent(operation.notificationToken))
            .build();
        try {
            notifications.notify(operation.notificationId, alert);
        } catch (RuntimeException unavailable) {
            Log.w(LOG_TAG, "Authorization alert rejected: " +
                unavailable.getClass().getSimpleName());
            operation.cancel("NOT_ALLOWED");
        }
    }

    private void dismissApprovalNotification(Operation operation) {
        // Scoped to THIS operation's random notification ID, so a late
        // finished/cancelled request cannot clear a NEW request's alert.
        if (notifications != null) notifications.cancel(operation.notificationId);
    }

    private void deliverOrNotify(Operation operation) {
        if (operation.isDone()) return;
        UiBridge visible = ui;
        if (visible != null && visible.isReadyForPrompt()) {
            visible.onOperation(operation);
        } else {
            // A Binder established in Activity.onStart may still be attached
            // after onPause or before onResume. Do not lose the first CTAP
            // request simply because ui != null.
            notifyApproval(operation);
        }
    }

    private static JSONObject ok(String id, JSONObject result) {
        JSONObject reply = new JSONObject();
        try {
            reply.put("v", 1).put("id", id).put("ok", true).put("result", result);
        } catch (Exception ignored) {}
        return reply;
    }

    private static JSONObject err(String id, String code) {
        JSONObject reply = new JSONObject();
        try {
            reply.put("v", 1).put("id", id).put("ok", false).put("error", code);
        } catch (Exception ignored) {}
        return reply;
    }

    private void serve() {
        try (LocalServerSocket socket = new LocalServerSocket(SOCKET_NAME)) {
            listener = socket;
            if (notifications != null && running) {
                try {
                    notifications.notify(LISTENER_ID, listenerNotification(true));
                } catch (RuntimeException disabled) {
                    Log.w(LOG_TAG, "Listener status notification update denied: " +
                        disabled.getClass().getSimpleName());
                }
            }
            while (running) {
                try {
                    LocalSocket peer = socket.accept();
                    // A malicious app must not cause user prompts, infer
                    // credential membership or request signing. Root is the
                    // explicit trust boundary for the NetHunter CTAP daemon.
                    Credentials credentials = peer.getPeerCredentials();
                    if (credentials == null || credentials.getUid() != 0) {
                        peer.close();
                        continue;
                    }
                    // A pending biometric must not block GetInfo for a
                    // second CTAPHID channel. Bound concurrent root peers.
                    if (activeSockets.incrementAndGet() > 4) {
                        activeSockets.decrementAndGet();
                        peer.close();
                        continue;
                    }
                    Thread handler = new Thread(() -> {
                        try (LocalSocket connection = peer) {
                            connection.setSoTimeout((int) TIMEOUT_MS + 5000);
                            handlePeer(connection);
                        } catch (Exception failed) {
                            // Do not log request content, aliases or keys.
                        } finally {
                            activeSockets.decrementAndGet();
                        }
                    }, "ctap3b-root-peer");
                    handler.setDaemon(true);
                    handler.start();
                } catch (Exception requestFailure) {
                    // Do not log request data, key aliases, or secrets.
                    if (!running) break;
                }
            }
        } catch (Exception unavailable) {
            // If the socket name is occupied, fail closed instead of silently
            // choosing another name or exposing the app to other callers.
            Log.w(LOG_TAG, "Root-only socket unavailable: " +
                unavailable.getClass().getSimpleName());
        } finally {
            listener = null;
            running = false;
            // Never leave a stale 'security key ready' foreground notification
            // behind when the listener has exited or an abstract socket bind
            // failed after device unlock.
            main.post(this::stopSelf);
        }
    }

    private void handlePeer(LocalSocket peer) throws Exception {
        DataInputStream input = new DataInputStream(peer.getInputStream());
        DataOutputStream output = new DataOutputStream(peer.getOutputStream());
        int length = input.readInt();
        if (length < 1 || length > MAX_FRAME) return;
        byte[] raw = new byte[length];
        input.readFully(raw);
        JSONObject request = new JSONObject(new String(raw, StandardCharsets.UTF_8));
        String id = request.optString("id", "");
        if (request.optInt("v", -1) != 1 || !id.matches("[0-9a-fA-F]{8,64}")) {
            writeFrame(output, err(id, "NOT_ALLOWED"));
            return;
        }
        String command = request.optString("op", "");
        if ("getInfo".equals(command)) {
            BiometricManager manager = getSystemService(BiometricManager.class);
            if (manager == null || manager.canAuthenticate(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    != BiometricManager.BIOMETRIC_SUCCESS) {
                writeFrame(output, err(id, "NOT_ALLOWED"));
                return;
            }
            JSONObject info = new JSONObject();
            info.put("up", true)
                .put("uvEnforced", true)
                .put("perUseCryptoObject", true)
                .put("silentSigning", false)
                .put("aaguid", CryptoKeyManager.encode(CryptoKeyManager.AAGUID))
                .put("rpIdPolicy", RelyingPartyPolicy.VERSION)
                .put("discoverablePolicy", "rp-bound-account-picker-v1")
                .put("hardwarePolicy", "TEE_OR_STRONGBOX_VERIFIED_PER_CREDENTIAL");
            writeFrame(output, ok(id, info));
            return;
        }
        UiBridge attached = ui;
        if (attached == null && !canNotifyApproval()) {
            writeFrame(output, err(id, "NOT_ALLOWED"));
            return;
        }
        Operation operation;
        try {
            operation = prepare(request);
        } catch (IllegalArgumentException badRequest) {
            writeFrame(output, err(id, "NO_CREDENTIALS".equals(badRequest.getMessage())
                ? "NO_CREDENTIALS" : "NOT_ALLOWED"));
            return;
        }
        if (operation == null) {
            writeFrame(output, err(id, "NOT_ALLOWED"));
            return;
        }
        writeFrame(output, new JSONObject()
            .put("v", 1).put("id", id).put("event", "user_presence_required"));
        // The CTAPHID caller closes its socket on CANCEL/USB disconnect. A
        // separate reader detects EOF while the service awaits the biometric.
        // LocalSocket's read timeout bounds this daemon thread's lifetime.
        Thread disconnectMonitor = new Thread(() -> {
            try {
                int extra = input.read();
                if (extra == -1 || extra >= 0) operation.cancel("CANCELLED");
            } catch (java.net.SocketTimeoutException timeout) {
                // Main request deadline handles this independently.
            } catch (Exception disconnected) {
                operation.cancel("CANCELLED");
            }
        }, "ctap3b-peer-disconnect");
        disconnectMonitor.setDaemon(true);
        disconnectMonitor.start();
        main.post(() -> {
            if (operation.isDone()) return;
            deliverOrNotify(operation);
        });
        if (!operation.done.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            operation.cancel("TIMEOUT");
        }
        writeFrame(output, operation.response == null
            ? err(id, "OTHER") : operation.response);
    }

    private Operation prepare(JSONObject request) {
        synchronized (operationLock) {
            if (active != null || maintenanceActive) return null;
            String op = request.optString("op", "");
            if (!"makeCredential".equals(op) && !"getAssertion".equals(op)) {
                throw new IllegalArgumentException("unknown command");
            }
            JSONObject params = request.optJSONObject("params");
            String rpId = params == null ? null : params.optString("rpId", "");
            RelyingPartyPolicy.require(rpId);
            byte[] hash = CryptoKeyManager.decode(
                params.optString("clientDataHash", ""), 32, 32);
            boolean requireUp = params.optBoolean("up", true);
            if ("makeCredential".equals(op) && !requireUp) {
                throw new IllegalArgumentException("registration requires UP");
            }
            String selectedId = null;
            byte[] userId = null;
            String userName = null;
            String displayName = null;
            boolean excluded = false;
            boolean discoverable = false;
            List<CryptoKeyManager.CredentialInfo> accountChoices =
                Collections.emptyList();
            if ("makeCredential".equals(op)) {
                if (params.has("residentKey")
                    && !(params.opt("residentKey") instanceof Boolean)) {
                    throw new IllegalArgumentException("residentKey must be boolean");
                }
                discoverable = params.optBoolean("residentKey", false);
                userId = CryptoKeyManager.decode(params.optString("userId", ""), 1, 64);
                if (params.has("userName") && !params.isNull("userName")) {
                    if (!(params.opt("userName") instanceof String)) {
                        throw new IllegalArgumentException("Invalid user name");
                    }
                    userName = CryptoKeyManager.safeAccountLabel(params.optString("userName", ""));
                }
                if (params.has("displayName") && !params.isNull("displayName")) {
                    if (!(params.opt("displayName") instanceof String)) {
                        throw new IllegalArgumentException("Invalid display name");
                    }
                    displayName = CryptoKeyManager.safeAccountLabel(params.optString("displayName", ""));
                }
                JSONArray exclude = params.optJSONArray("excludeIds");
                if (exclude == null) throw new IllegalArgumentException("excludeIds missing");
                if (exclude.length() > 64) throw new IllegalArgumentException("excludeIds too long");
                for (int i = 0; i < exclude.length(); i++) {
                    String id = exclude.optString(i, "");
                    CryptoKeyManager.decode(id, 1, 1023);
                    if (keys.hasCredential(id, rpId)) excluded = true;
                }
            } else {
                JSONArray allowed = params.optJSONArray("allowIds");
                if (allowed == null || allowed.length() > 64) {
                    throw new IllegalArgumentException("allowIds missing or invalid");
                }
                if (allowed.length() == 0) {
                    // An empty native-to-helper allowIds array represents an
                    // OMITTED CTAP allowList. Never offer pre-existing
                    // non-discoverable or other-RP credentials.
                    discoverable = true;
                    accountChoices = keys.discoverableForRp(rpId);
                    if (accountChoices.isEmpty()) {
                        throw new IllegalArgumentException("NO_CREDENTIALS");
                    }
                    if (accountChoices.size() == 1) {
                        selectedId = accountChoices.get(0).credentialId;
                    }
                } else {
                    for (int i = 0; i < allowed.length(); i++) {
                        String id = allowed.optString(i, "");
                        CryptoKeyManager.decode(id, 1, 1023);
                        if (selectedId == null && keys.hasCredential(id, rpId)) selectedId = id;
                    }
                    if (selectedId == null) {
                        throw new IllegalArgumentException("NO_CREDENTIALS");
                    }
                }
            }
            Operation operation = new Operation(
                this, request.optString("id", ""), op, rpId,
                hash, userId, userName, displayName, selectedId, requireUp, excluded,
                discoverable, accountChoices);
            active = operation;
            return operation;
        }
    }

    private static void writeFrame(DataOutputStream output, JSONObject json) throws Exception {
        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_FRAME) throw new IllegalArgumentException("response too large");
        output.writeInt(bytes.length);
        output.write(bytes);
        output.flush();
    }
}
