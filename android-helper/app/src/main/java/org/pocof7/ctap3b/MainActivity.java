package org.pocof7.ctap3b;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.Manifest;
import android.content.res.ColorStateList;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.Gravity;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Signature;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** The only user-consent surface. The root broker cannot bypass this Activity. */
public final class MainActivity extends Activity implements HelperService.UiBridge {
    private static final String LOG_TAG = "Ctap3bHelper";
    private static final int CREATE_BACKUP = 781;
    private static final int OPEN_BACKUP = 782;
    private static final int VERIFY_BACKUP = 783;
    // The encrypted archive contains actual recoverable passkey private keys;
    // bound provider reads so hostile or broken providers cannot exhaust RAM.
    private static final int MAX_BACKUP_BYTES = RecoverableBackupManager.MAX_BLOB;
    private final ExecutorService cryptoExecutor = Executors.newSingleThreadExecutor();
    // Hardware-capability inspection must not delay time-limited CTAP
    // signing/biometric work on the main cryptographic executor.
    private final ExecutorService diagnosticsExecutor = Executors.newSingleThreadExecutor();
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private HelperService.LocalBinder binder;
    private boolean attached;
    private boolean resumed;
    private boolean notificationPermissionPending;
    private TextView status;
    private TextView deviceSupport;
    private TextView listenerStatus;
    private TextView notificationStatus;
    private Button notificationSettingsButton;
    private TextView credentialCount;
    private TextView backupFreshness;
    private TextView pendingDescription;
    private LinearLayout pendingPanel;
    private LinearLayout credentialRows;
    private EditText catalogSearch;
    private List<CryptoKeyManager.CredentialInfo> cachedCatalog = Collections.emptyList();
    private boolean deletionBusy;
    private CancellationSignal deletionSignal;
    private CancellationSignal recoverySignal;
    private Button refreshButton;
    private Button exportButton;
    private Button importButton;
    private Button verifyButton;
    private boolean backupBusy;
    private boolean backupFlowActive;
    private boolean recoveryMaintenanceActive;
    private HelperService.LocalBinder recoveryMaintenanceBinder;
    private long recoveryMaintenanceToken;
    private boolean dark;
    private int background;
    private int surface;
    private int foreground;
    private int muted;
    private int accent;
    private int border;
    private int developmentSurface;
    private int developmentBorder;
    private int warningSurface;
    private int warningBorder;
    private int secondaryButtonSurface;
    private int secondaryButtonText;
    private int secondaryButtonBorder;
    private int destructive;
    private int destructiveSurface;
    private int destructiveBorder;
    private long credentialRefreshId;
    private boolean catalogReady;
    private CryptoKeyManager.BackupStatus cachedBackupStatus;
    private final Runnable listenerRefresh = new Runnable() {
        @Override public void run() {
            if (!resumed || isFinishing() || isDestroyed()) return;
            if (accountDialogOperation != null && accountDialogOperation.isDone()) {
                AlertDialog expired = accountDialog;
                accountDialog = null;
                accountDialogOperation = null;
                if (expired != null) expired.dismiss();
                showStatus("Account request expired or was canceled. No signature was sent.");
            }
            renderListenerStatus();
            renderApprovalPanel();
            if (!catalogReady && helper != null && helper.keys != null
                && !backupBusy && !backupFlowActive) {
                catalogReady = true;
                scheduleCatalogRefresh();
            }
            uiHandler.postDelayed(this, 2500L);
        }
    };
    private HelperService.Operation displayed;
    private AlertDialog accountDialog;
    private HelperService.Operation accountDialogOperation;
    private final ServiceConnection connection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder service) {
            binder = (HelperService.LocalBinder) service;
            helper = binder.service();
            binder.attach(MainActivity.this);
            if (!binder.status().startsWith("root-only socket ready:")) {
                showStatus("Local security-key service unavailable.");
            }
            renderListenerStatus();
            renderNotificationState();
            refreshDeviceSupport();
            scheduleCatalogRefresh();
            catalogReady = helper != null && helper.keys != null;
            updateButtons();
        }
        @Override public void onServiceDisconnected(ComponentName name) {
            binder = null;
            helper = null;
            catalogReady = false;
            renderListenerStatus();
            showStatus("Helper service disconnected");
            updateButtons();
        }
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        dark = (getResources().getConfiguration().uiMode
            & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        // Android 12+ system palette follows wallpaper, including a separate
        // light/dark tonal set. Min SDK is 31, so these resources always exist.
        // The Activity's day/night platform theme also colors native dialogs.
        background = getColor(dark ? android.R.color.system_neutral1_900
            : android.R.color.system_neutral1_10);
        surface = getColor(dark ? android.R.color.system_neutral1_800
            : android.R.color.system_neutral1_0);
        foreground = getColor(dark ? android.R.color.system_neutral1_100
            : android.R.color.system_neutral1_900);
        muted = getColor(dark ? android.R.color.system_neutral2_200
            : android.R.color.system_neutral2_600);
        accent = getColor(dark ? android.R.color.system_accent1_200
            : android.R.color.system_accent1_600);
        border = getColor(dark ? android.R.color.system_neutral2_700
            : android.R.color.system_neutral2_200);
        developmentSurface = getColor(dark ? android.R.color.system_accent2_800
            : android.R.color.system_accent2_50);
        developmentBorder = getColor(dark ? android.R.color.system_accent2_600
            : android.R.color.system_accent2_200);
        warningSurface = getColor(dark ? android.R.color.system_accent3_800
            : android.R.color.system_accent3_50);
        warningBorder = getColor(dark ? android.R.color.system_accent3_600
            : android.R.color.system_accent3_200);
        secondaryButtonSurface = getColor(dark ? android.R.color.system_accent2_800
            : android.R.color.system_accent2_50);
        secondaryButtonText = getColor(dark ? android.R.color.system_accent2_100
            : android.R.color.system_accent2_800);
        secondaryButtonBorder = getColor(dark ? android.R.color.system_accent2_600
            : android.R.color.system_accent2_300);
        // Semantic destructive colors are intentionally stable rather than
        // wallpaper-derived: deleting a credential should remain recognizably
        // destructive under every Dynamic Color palette.
        destructive = dark ? 0xffffb4ab : 0xffba1a1a;
        destructiveSurface = dark ? 0xff3f1513 : 0xffffdad6;
        destructiveBorder = dark ? 0xff93000a : 0xffffb4ab;

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(background);
        scroll.setClipToPadding(false);
        // Target SDK 35 enforces edge-to-edge on Android 15+. Keep the top
        // heading and bottom SAF controls clear of system/gesture bars.
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsets.Type.systemBars());
            view.setPadding(0, systemBars.top, 0, systemBars.bottom);
            return insets;
        });
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(20), dp(28), dp(20), dp(32));
        scroll.addView(content, new ScrollView.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView eyebrow = text("ANDROID SECURITY KEY", 12, accent, true);
        eyebrow.setLetterSpacing(0.10f);
        content.addView(eyebrow);
        TextView title = text("MobileFIDO", 31, foreground, true);
        space(content, 6);
        content.addView(title);
        space(content, 8);
        content.addView(text("Your phone, your security key. Fingerprint approval for every use.",
            15, muted, false));
        space(content, 16);
        TextView development = text(
            "DEVELOPMENT BUILD  ·  Not FIDO-certified",
            12, foreground, true);
        development.setPadding(dp(13), dp(10), dp(13), dp(10));
        development.setBackground(shape(developmentSurface, 12, developmentBorder));
        development.setContentDescription(
            "Development prototype. Not FIDO certified.");
        content.addView(development);
        space(content, 18);

        LinearLayout serviceCard = card(content, "KEY STATUS", null);
        listenerStatus = statusLine("○  Connecting to the local service…");
        serviceCard.addView(listenerStatus);
        space(serviceCard, 9);
        notificationStatus = statusLine("○  Checking approval notifications…");
        serviceCard.addView(notificationStatus);
        space(serviceCard, 9);
        status = statusLine("○  Waiting for a request from your computer");
        status.setTextIsSelectable(true);
        serviceCard.addView(status);
        space(serviceCard, 10);
        notificationSettingsButton = button("Enable approval notifications", false);
        notificationSettingsButton.setOnClickListener(view -> openNotificationSettings());
        serviceCard.addView(notificationSettingsButton);
        space(content, 14);

        LinearLayout compatibility = card(content, "DEVICE SUPPORT", null);
        deviceSupport = statusLine("Checking Android, biometrics and hardware key support…");
        compatibility.addView(deviceSupport);
        space(content, 14);

        pendingPanel = card(content, "APPROVAL REQUEST",
            "Only approve a security-key operation you initiated on your computer.");
        pendingDescription = text("No approval is waiting.", 15, foreground, false);
        pendingPanel.addView(pendingDescription);
        pendingPanel.setVisibility(View.GONE);
        space(content, 14);

        LinearLayout catalog = card(content, "SAVED CREDENTIALS",
            "Accounts registered with MobileFIDO");
        credentialCount = text("Checking keys…", 19, foreground, true);
        catalog.addView(credentialCount);
        space(catalog, 10);
        catalogSearch = new EditText(this);
        catalogSearch.setSingleLine(true);
        catalogSearch.setHint("Search website or account");
        catalogSearch.setTextSize(14);
        catalogSearch.setTextColor(foreground);
        catalogSearch.setHintTextColor(muted);
        catalogSearch.setBackgroundTintList(ColorStateList.valueOf(accent));
        catalogSearch.setContentDescription("Search saved security-key credentials");
        catalogSearch.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count,
                                                    int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before,
                                                int count) { renderCredentialCatalog(); }
            @Override public void afterTextChanged(Editable editable) {}
        });
        catalog.addView(catalogSearch);
        space(catalog, 9);
        credentialRows = new LinearLayout(this);
        credentialRows.setOrientation(LinearLayout.VERTICAL);
        catalog.addView(credentialRows);
        space(catalog, 12);
        refreshButton = button("Refresh credentials", false);
        refreshButton.setOnClickListener(view -> refreshCredentials());
        catalog.addView(refreshButton);
        space(content, 14);

        LinearLayout backup = card(content, "BACKUP & RECOVERY",
            "Encrypted recovery for your portable credentials");
        TextView warning = text(
            "Keep your backup file and its password safe: together they can restore "
            + "your passkeys. Older device-bound credentials cannot be backed up.",
            14, foreground, false);
        warning.setPadding(dp(12), dp(12), dp(12), dp(12));
        warning.setBackground(shape(warningSurface, 12, warningBorder));
        warning.setContentDescription("Protect both the encrypted recovery archive "
            + "and its password. Legacy device-bound credentials are not recoverable.");
        backup.addView(warning);
        space(backup, 14);
        backupFreshness = text("Checking recovery archive freshness…", 14, foreground, true);
        backupFreshness.setPadding(dp(12), dp(11), dp(12), dp(11));
        backupFreshness.setBackground(shape(surface, 12, border));
        backup.addView(backupFreshness);
        space(backup, 12);
        exportButton = button("Export recovery archive", true);
        exportButton.setOnClickListener(view -> startExport());
        backup.addView(exportButton);
        space(backup, 8);
        importButton = button("Restore from backup", false);
        importButton.setOnClickListener(view -> startImport());
        backup.addView(importButton);
        space(backup, 8);
        verifyButton = button("Verify saved backup", false);
        verifyButton.setOnClickListener(view -> startVerify());
        backup.addView(verifyButton);
        space(backup, 10);
        space(content, 18);
        content.addView(text(
            "Privacy · No INTERNET permission. You choose where encrypted "
            + "recovery files are saved through Android's file picker.",
            12, muted, false));
        setContentView(scroll);
        // PhoneWindow#getInsetsController requires an installed DecorView.
        // Calling it earlier during onCreate crashed this Android 17 ROM
        // before ANY approval Activity could appear. Colors are cosmetic;
        // never let an optional system-bar appearance API break consent.
        WindowInsetsController bars = getWindow().getDecorView()
            .getWindowInsetsController();
        if (bars != null) {
            int lightBarFlags = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
            bars.setSystemBarsAppearance(dark ? 0 : lightBarFlags, lightBarFlags);
        }
        renderNotificationState();
        // Permission must be asked from a visible Activity, not the FGS or
        // boot receiver. Denial affects background alerts, never key policy.
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            notificationPermissionPending = true;
            requestPermissions(new String[] {
                Manifest.permission.POST_NOTIFICATIONS
            }, 601);
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private GradientDrawable shape(int fill, int radius, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radius));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView result = new TextView(this);
        result.setText(value);
        result.setTextSize(sp);
        result.setTextColor(color);
        result.setLineSpacing(dp(2), 1.0f);
        if (bold) result.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return result;
    }

    /** One typography role for all three live Key Status rows. */
    private TextView statusLine(String value) {
        return text(value, 14, muted, false);
    }

    /** Probes existing capabilities without creating or replacing a key. */
    private void refreshDeviceSupport() {
        if (deviceSupport == null) return;
        deviceSupport.setText("Checking device capabilities…");
        diagnosticsExecutor.execute(() -> {
            final DeviceCapabilities.Snapshot snapshot;
            try {
                snapshot = DeviceCapabilities.detect(this);
            } catch (RuntimeException unavailable) {
                runOnUiThread(() -> {
                    if (!isFinishing() && !isDestroyed() && deviceSupport != null) {
                        deviceSupport.setText("Device capability check unavailable. "
                            + "This does not invalidate your saved credentials.");
                    }
                });
                return;
            }
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed() || deviceSupport == null) return;
                StringBuilder details = new StringBuilder();
                details.append("Android API ").append(snapshot.sdk)
                    .append(snapshot.sdk >= 31 ? " · supported version" : " · unsupported version");
                details.append("\n").append(snapshot.strongBiometrics
                    == DeviceCapabilities.State.AVAILABLE
                        ? "● Strong biometric ready"
                        : snapshot.strongBiometrics == DeviceCapabilities.State.UNAVAILABLE
                            ? "○ Strong biometric unavailable or not enrolled"
                            : "○ Strong biometric status not confirmed");
                details.append("\n")
                    .append(snapshot.strongBoxObserved == DeviceCapabilities.State.AVAILABLE
                        ? "● StrongBox verified by a saved credential"
                        : snapshot.strongBoxFeature == DeviceCapabilities.State.AVAILABLE
                            ? "○ StrongBox advertised · key import still needs verification"
                            : "○ No StrongBox feature reported · verified TEE may work");
                details.append("\n")
                    .append(snapshot.teeObserved == DeviceCapabilities.State.AVAILABLE
                        ? "● TEE verified by a saved credential"
                        : "○ TEE support not yet verified");
                details.append("\n")
                    .append(snapshot.hidDevice == DeviceCapabilities.State.AVAILABLE
                        ? "● USB HID device visible · host detection not tested"
                        : "○ USB HID unavailable to app or not configured");
                // Root/USB configuration belongs to the separate KernelSU
                // module, not this regular-UID helper. Showing an app root
                // status here could misleadingly encourage granting app root.
                deviceSupport.setText(details.toString());
                deviceSupport.setContentDescription(details.toString());
            });
        });
    }

    private static void space(LinearLayout parent, int heightDp) {
        // Height already passed as dp-independent design unit, so convert
        // using the parent's current display density.
        int pixels = Math.round(heightDp
            * parent.getResources().getDisplayMetrics().density);
        parent.addView(new View(parent.getContext()),
            new LinearLayout.LayoutParams(1, pixels));
    }

    private LinearLayout card(LinearLayout container, String heading, String subtitle) {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(18), dp(18), dp(18), dp(18));
        panel.setBackground(shape(surface, 18, border));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        container.addView(panel, params);
        TextView title = text(heading, 12, accent, true);
        title.setLetterSpacing(0.07f);
        panel.addView(title);
        space(panel, 7);
        if (subtitle != null && !subtitle.isEmpty()) {
            panel.addView(text(subtitle, 13, muted, false));
            space(panel, 14);
        }
        return panel;
    }

    private Button button(String label, boolean filled) {
        Button control = new Button(this);
        control.setText(label);
        control.setAllCaps(false);
        control.setTextSize(14);
        control.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        control.setMinHeight(dp(48));
        control.setTextColor(filled ? (dark ? background
            : getColor(android.R.color.system_neutral1_0)) : secondaryButtonText);
        control.setBackground(new RippleDrawable(ColorStateList.valueOf(
            (accent & 0x00ffffff) | 0x33000000),
            shape(filled ? accent : secondaryButtonSurface, 12,
                filled ? accent : secondaryButtonBorder), null));
        control.setContentDescription(label);
        return control;
    }

    /** Compact trailing action used inside credential cards. */
    private TextView credentialDeleteAction(String account, String rpId) {
        TextView control = text("×", 25, destructive, false);
        control.setGravity(Gravity.CENTER);
        control.setMinWidth(dp(48));
        control.setMinHeight(dp(48));
        control.setBackground(new RippleDrawable(ColorStateList.valueOf(
            (destructive & 0x00ffffff) | 0x26000000),
            shape(destructiveSurface, 14, destructiveBorder), null));
        control.setContentDescription("Delete credential " + account + " for " + rpId);
        return control;
    }

    /**
     * App-owned Material-like dialog content. BiometricPrompt and Android's
     * document picker deliberately remain system UI and are not skinned.
     */
    private LinearLayout dialogContent(String label, String title, String message,
                                       View body, boolean destructiveTone) {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(dp(24), dp(22), dp(24), dp(8));
        int tone = destructiveTone ? destructive : accent;
        TextView eyebrow = text(label, 11, tone, true);
        eyebrow.setLetterSpacing(0.08f);
        panel.addView(eyebrow);
        space(panel, 9);
        panel.addView(text(title, 22, foreground, true));
        if (message != null && !message.isEmpty()) {
            space(panel, 10);
            panel.addView(text(message, 14, muted, false));
        }
        if (body != null) {
            space(panel, 16);
            panel.addView(body);
        }
        return panel;
    }

    private AlertDialog.Builder styledDialog(String label, String title, String message,
                                             View body, boolean destructiveTone) {
        return new AlertDialog.Builder(this)
            .setView(dialogContent(label, title, message, body, destructiveTone));
    }

    private void styleDialog(AlertDialog dialog, boolean destructiveAction) {
        if (dialog == null) return;
        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawable(shape(surface, 26, border));
        }
        Button positive = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
        if (positive != null) {
            int fill = destructiveAction ? destructive : accent;
            int ink = dark ? background : getColor(android.R.color.system_neutral1_0);
            positive.setAllCaps(false);
            positive.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            positive.setTextColor(ink);
            positive.setMinHeight(dp(44));
            positive.setBackground(new RippleDrawable(ColorStateList.valueOf(
                (fill & 0x00ffffff) | 0x33000000), shape(fill, 12, fill), null));
        }
        Button negative = dialog.getButton(AlertDialog.BUTTON_NEGATIVE);
        if (negative != null) {
            negative.setAllCaps(false);
            negative.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            negative.setTextColor(secondaryButtonText);
            negative.setMinHeight(dp(44));
            negative.setBackground(new RippleDrawable(ColorStateList.valueOf(
                (accent & 0x00ffffff) | 0x22000000),
                shape(secondaryButtonSurface, 12, secondaryButtonBorder), null));
        }
        Button neutral = dialog.getButton(AlertDialog.BUTTON_NEUTRAL);
        if (neutral != null) {
            neutral.setAllCaps(false);
            neutral.setTextColor(secondaryButtonText);
        }
    }

    private void openNotificationSettings() {
        try {
            Intent intent = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS);
            intent.putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName());
            startActivity(intent);
        } catch (RuntimeException unavailable) {
            showStatus("Open Android Settings → Apps → security-key helper → Notifications.");
        }
    }

    private void renderNotificationState() {
        if (notificationStatus == null) return;
        NotificationManager manager = getSystemService(NotificationManager.class);
        boolean granted = Build.VERSION.SDK_INT < 33
            || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED;
        boolean enabled = manager != null && manager.areNotificationsEnabled();
        NotificationChannel approvals = manager == null ? null
            : manager.getNotificationChannel("ctap3b_authorization");
        boolean channelEnabled = approvals != null
            && approvals.getImportance() != NotificationManager.IMPORTANCE_NONE;
        boolean ready = granted && enabled && channelEnabled;
        String message = ready
            ? "●  Approval notifications enabled"
            : "○  Approval notifications disabled · keep the app open to approve requests";
        notificationStatus.setText(message);
        notificationStatus.setTextColor(ready ? accent : muted);
        if (notificationSettingsButton != null) {
            notificationSettingsButton.setVisibility(ready ? View.GONE : View.VISIBLE);
        }
    }

    private void renderListenerStatus() {
        if (listenerStatus == null) return;
        boolean ready = binder != null && binder.status()
            .startsWith("root-only socket ready:");
        listenerStatus.setText(ready
            ? "●  Local security-key service ready"
            : "○  Connecting to security-key service…");
        listenerStatus.setTextColor(ready ? accent : muted);
        updateButtons();
    }

    private void updateButtons() {
        boolean ready = helper != null && helper.keys != null
            && !backupBusy && !backupFlowActive && !deletionBusy
            && deletionSignal == null && recoverySignal == null;
        // The biometric and secure file picker must never compete for screen
        // focus or cause a second approval while an operation is active.
        boolean operationPending = displayed != null && !displayed.isDone();
        if (refreshButton != null) {
            refreshButton.setEnabled(ready && !operationPending);
            refreshButton.setAlpha(ready && !operationPending ? 1f : 0.5f);
        }
        if (exportButton != null) {
            exportButton.setEnabled(ready && !operationPending);
            exportButton.setAlpha(ready && !operationPending ? 1f : 0.5f);
        }
        if (importButton != null) {
            importButton.setEnabled(ready && !operationPending);
            importButton.setAlpha(ready && !operationPending ? 1f : 0.5f);
        }
        if (verifyButton != null) {
            verifyButton.setEnabled(ready && !operationPending);
            verifyButton.setAlpha(ready && !operationPending ? 1f : 0.5f);
        }
    }

    private void refreshCredentials() {
        long refresh = ++credentialRefreshId;
        HelperService service = helper;
        if (credentialCount == null || credentialRows == null) return;
        if (deletionBusy || deletionSignal != null
            || (displayed != null && !displayed.isDone())) {
            // Prioritize the 60-second biometric CTAP request over potentially
            // slow OEM KeyInfo catalog inspection.
            return;
        }
        if (service == null || service.keys == null) {
            credentialCount.setText("Service not ready");
            credentialRows.removeAllViews();
            updateButtons();
            return;
        }
        credentialCount.setText("Checking AndroidKeyStore references…");
        CryptoKeyManager keys = service.keys;
        cryptoExecutor.execute(() -> {
            try {
                List<CryptoKeyManager.CredentialInfo> entries = keys.listCredentials();
                CryptoKeyManager.BackupStatus backup = keys.backupStatus(entries);
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed() || refresh != credentialRefreshId) return;
                    cachedCatalog = new ArrayList<>(entries);
                    cachedBackupStatus = backup;
                    renderCredentialCatalog();
                    renderBackupFreshness();
                    updateButtons();
                });
            } catch (Exception failed) {
                runOnUiThread(() -> {
                    if (isFinishing() || isDestroyed() || refresh != credentialRefreshId) return;
                    credentialCount.setText("Credential catalog unavailable");
                    if (backupFreshness != null) {
                        backupFreshness.setText("Backup status unavailable · do not assume a backup is current");
                    }
                    credentialRows.removeAllViews();
                    credentialRows.addView(text("No keys were modified.",
                        13, muted, false));
                    updateButtons();
                });
            }
        });
    }

    private static String credentialAccount(CryptoKeyManager.CredentialInfo entry) {
        if (entry.userName != null) return entry.userName;
        if (entry.displayName != null) return entry.displayName;
        String id = entry.credentialId == null ? "" : entry.credentialId;
        return "Account key " + id.substring(0, Math.min(12, id.length())) + "…";
    }

    private void renderBackupFreshness() {
        if (backupFreshness == null || cachedBackupStatus == null) return;
        CryptoKeyManager.BackupStatus backup = cachedBackupStatus;
        String last = backup.lastVerifiedAtMillis > 0L
            ? DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
                .format(new Date(backup.lastVerifiedAtMillis))
            : "None verified by this installation";
        String message = "Last verified recovery archive: " + last
            + "\n" + backup.lastVerifiedCount + " credentials in that archive · "
            + backup.recoverableCount + " recoverable on this phone";
        if (backup.needVerifiedBackup > 0) {
            message += "\n⚠ " + backup.needVerifiedBackup
                + " credential" + (backup.needVerifiedBackup == 1 ? " has" : "s have")
                + " no locally recorded, read-back-verified export. "
                + "Export again before deleting them or wiping this phone.";
        } else if (backup.recoverableCount > 0) {
            message += "\n✓ All current recoverable credentials were included "
                + "in a locally verified export.";
        }
        if (backup.legacyCount > 0) {
            message += "\n" + backup.legacyCount
                + " legacy device-bound credential(s) cannot be backed up.";
        }
        backupFreshness.setText(message);
        backupFreshness.setContentDescription(message);
    }

    private void renderCredentialCatalog() {
        if (credentialRows == null || credentialCount == null) return;
        String query = catalogSearch == null ? "" : catalogSearch.getText().toString()
            .toLowerCase(java.util.Locale.ROOT).trim();
        Map<String, List<CryptoKeyManager.CredentialInfo>> grouped = new TreeMap<>();
        int shown = 0;
        for (CryptoKeyManager.CredentialInfo entry : cachedCatalog) {
            String searchable = entry.rpId + " " + credentialAccount(entry) + " "
                + (entry.displayName == null ? "" : entry.displayName);
            if (!query.isEmpty() && !searchable.toLowerCase(java.util.Locale.ROOT)
                .contains(query)) continue;
            grouped.computeIfAbsent(entry.rpId, ignored -> new ArrayList<>()).add(entry);
            shown++;
        }
        credentialRows.removeAllViews();
        credentialCount.setText(cachedCatalog.size() + " credential"
            + (cachedCatalog.size() == 1 ? "" : "s") + " on this phone"
            + (query.isEmpty() ? "" : " · " + shown + " matching"));
        if (shown == 0) {
            credentialRows.addView(text(cachedCatalog.isEmpty()
                ? "No hardware credentials are stored yet."
                : "No matching website or account.", 14, muted, false));
            return;
        }
        for (Map.Entry<String, List<CryptoKeyManager.CredentialInfo>> group
                : grouped.entrySet()) {
            credentialRows.addView(text(group.getKey() + "  ·  " + group.getValue().size()
                + " account" + (group.getValue().size() == 1 ? "" : "s"),
                15, accent, true));
            space(credentialRows, 5);
            for (CryptoKeyManager.CredentialInfo entry : group.getValue()) {
                LinearLayout row = new LinearLayout(this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(Gravity.CENTER_VERTICAL);
                row.setPadding(dp(12), dp(10), dp(12), dp(10));
                row.setBackground(shape(surface, 12, border));
                String account = credentialAccount(entry);
                LinearLayout details = new LinearLayout(this);
                details.setOrientation(LinearLayout.VERTICAL);
                LinearLayout.LayoutParams detailsParams = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                row.addView(details, detailsParams);
                details.addView(text(account, 15, entry.available ? foreground : muted, true));
                if (entry.userName != null && entry.displayName != null
                    && !entry.userName.equals(entry.displayName)) {
                    details.addView(text(entry.displayName, 13, muted, false));
                }
                String created = entry.createdAtMillis > 0
                    ? DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
                        .format(new Date(entry.createdAtMillis))
                    : "Date unknown (legacy registration)";
                String recovery;
                if (!entry.recoverable) {
                    recovery = "Device-bound legacy · Not recoverable";
                } else if (!entry.recoveryMaterialAvailable) {
                    recovery = "Recoverable credential · Local recovery material unavailable";
                } else if (entry.verifiedBackupAtMillis > 0L) {
                    recovery = "Recoverable · Verified archive "
                        + DateFormat.getDateTimeInstance(DateFormat.MEDIUM,
                            DateFormat.SHORT).format(new Date(entry.verifiedBackupAtMillis));
                } else if (entry.backedUp) {
                    recovery = "Recoverable · Archive recorded, readback not verified here";
                } else {
                    recovery = "Recoverable · Backup needed (no verified export)";
                }
                details.addView(text((entry.available ? "● Available" : "○ Original key unavailable")
                    + " · " + (entry.discoverable ? "Discoverable passkey" : "Security-key credential")
                    + "\n" + (entry.securityLevel == null ? "Unknown hardware" : entry.securityLevel)
                    + " · " + created + "\n" + recovery, 13, muted, false));
                TextView delete = credentialDeleteAction(account, entry.rpId);
                delete.setEnabled(!deletionBusy && deletionSignal == null
                    && !backupBusy && !backupFlowActive
                    && (displayed == null || displayed.isDone()));
                delete.setAlpha(delete.isEnabled() ? 1f : 0.45f);
                delete.setOnClickListener(view -> confirmCredentialDeletion(entry));
                LinearLayout.LayoutParams deleteParams = new LinearLayout.LayoutParams(
                    dp(48), dp(48));
                deleteParams.gravity = Gravity.CENTER_VERTICAL;
                deleteParams.setMarginStart(dp(12));
                row.addView(delete, deleteParams);
                credentialRows.addView(row);
                space(credentialRows, 8);
            }
            space(credentialRows, 6);
        }
    }

    private void confirmCredentialDeletion(CryptoKeyManager.CredentialInfo entry) {
        if (deletionBusy || deletionSignal != null
            || backupBusy || backupFlowActive || binder == null
            || helper == null || (displayed != null && !displayed.isDone())) {
            showStatus("Finish the pending security-key or backup operation first.");
            return;
        }
        final String account = credentialAccount(entry);
        String recoveryNotice;
        if (entry.recoverable && entry.verifiedBackupAtMillis > 0L) {
            recoveryNotice = "This removes the working StrongBox/TEE copy and local metadata. "
                + "A recovery archive verified AFTER this credential was registered can "
                + "re-import the same FIDO credential later. Keep that archive and its "
                + "passphrase safe.";
        } else if (entry.recoverable && entry.backedUp) {
            recoveryNotice = "An earlier recovery archive was recorded for this "
                + "credential, but its saved file has not been read-back verified "
                + "by this version. Verify the existing file or export and verify "
                + "a fresh one before deleting the only working copy.";
        } else if (entry.recoverable) {
            recoveryNotice = "This credential is designed to be recoverable, but MobileFIDO "
                + "does not currently know of a completed archive containing it. Export a "
                + "recovery archive first or deletion can permanently lock you out.";
        } else {
            recoveryNotice = "This is a legacy device-bound credential. Its private key was "
                + "generated nonexportable in Android Keystore, so deleting it is permanent.";
        }
        AlertDialog promptDialog = styledDialog("DELETE CREDENTIAL",
            "Permanently delete this security key?",
            account + " — " + entry.rpId + "\n\n"
                + recoveryNotice + "\n\n"
                + "Other credentials are unaffected. Make sure another sign-in or recovery "
                + "method exists before deleting an important credential.\n\n"
                + "Confirm using a strong fingerprint.", null, true)
            .setNegativeButton("Keep credential", (dialog, which) -> {})
            .setPositiveButton("Verify fingerprint to delete", (dialog, which) ->
                authorizeCredentialDeletion(entry))
            .create();
        promptDialog.show();
        styleDialog(promptDialog, true);
    }

    private void authorizeCredentialDeletion(CryptoKeyManager.CredentialInfo entry) {
        if (deletionBusy || deletionSignal != null
            || backupBusy || backupFlowActive || binder == null
            || helper == null || (displayed != null && !displayed.isDone())) return;
        BiometricManager biometrics = getSystemService(BiometricManager.class);
        if (biometrics == null || biometrics.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG)
                != BiometricManager.BIOMETRIC_SUCCESS) {
            showStatus("An enrolled STRONG fingerprint is required to delete a credential.");
            return;
        }
        final CancellationSignal signal = new CancellationSignal();
        deletionSignal = signal;
        updateButtons();
        renderCredentialCatalog();
        BiometricPrompt prompt = new BiometricPrompt.Builder(this)
            .setTitle("Delete hardware security key")
            .setSubtitle(credentialAccount(entry) + " · " + entry.rpId)
            .setNegativeButton("Keep credential", getMainExecutor(),
                (dialog, which) -> signal.cancel())
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build();
        prompt.authenticate(signal, getMainExecutor(),
            new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(
                        BiometricPrompt.AuthenticationResult result) {
                    if (deletionSignal != signal || signal.isCanceled() || deletionBusy
                        || isFinishing() || helper == null || binder == null) return;
                    deletionSignal = null;
                    deletionBusy = true;
                    updateButtons();
                    renderCredentialCatalog();
                    HelperService.LocalBinder authorizedBinder = binder;
                    cryptoExecutor.execute(() -> {
                        String outcome;
                        try {
                            authorizedBinder.deleteCredential(entry.credentialId, entry.rpId);
                            outcome = "Permanently deleted " + credentialAccount(entry)
                                + " for " + entry.rpId + ". Other credentials remain intact.";
                        } catch (Exception failure) {
                            outcome = "Credential deletion not completed. No other keys "
                                + "were modified. If the hardware key is now unavailable, "
                                + "retry removal of its stale catalog entry.";
                        }
                        final String message = outcome;
                        runOnUiThread(() -> {
                            deletionBusy = false;
                            if (message.startsWith("Permanently deleted")) {
                                if (entry.credentialId.equals(getPreferences(MODE_PRIVATE)
                                        .getString("lastDemoCredential", null))) {
                                    getPreferences(MODE_PRIVATE).edit()
                                        .remove("lastDemoCredential").apply();
                                }
                            }
                            if (!isFinishing() && !isDestroyed()) {
                                showStatus(message);
                                scheduleCatalogRefresh();
                                updateButtons();
                            }
                        });
                    });
                }

                @Override public void onAuthenticationError(int code, CharSequence reason) {
                    if (deletionSignal == signal) deletionSignal = null;
                    showStatus("Credential preserved; deletion fingerprint not completed.");
                    updateButtons();
                    renderCredentialCatalog();
                }
            });
    }

    private void scheduleCatalogRefresh() {
        // Binder.attach dispatches a pending CTAP operation via main.post.
        // Give it precedence rather than queueing up to 256 KeyInfo probes
        // in front of the per-use CryptoObject operation.
        uiHandler.postDelayed(() -> {
            if (!isFinishing() && !isDestroyed() && resumed && !backupBusy
                && !backupFlowActive && (displayed == null || displayed.isDone())) {
                refreshCredentials();
            }
        }, 750L);
    }

    private void showPasswordDialog(boolean exporting, Consumer<char[]> onConfirmed) {
        if (isFinishing() || isDestroyed()) return;
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        String guidance = exporting
            ? "Use a unique recovery passphrase of at least 16 characters. The archive "
                + "can recreate MobileFIDO 5 passkeys after a reset, so protect this passphrase "
                + "like a security key. It is not stored by MobileFIDO or sent to your provider."
            : "Enter the passphrase used when this archive was created. MobileFIDO 5 recovery "
                + "archives require 16+ characters; legacy 4.x metadata archives may use "
                + "their original 12+ character passphrase.";
        EditText password = passwordField("Backup passphrase");
        form.addView(password);
        EditText confirm = null;
        if (exporting) {
            space(form, 9);
            confirm = passwordField("Confirm passphrase");
            form.addView(confirm);
        }
        final EditText confirmation = confirm;
        AlertDialog dialog = styledDialog("RECOVERY BACKUP",
            exporting ? "Protect this recovery archive" : "Unlock recovery archive",
            guidance, form, false)
            .setNegativeButton("Cancel", (clickedDialog, which) -> {
                password.getText().clear();
                if (confirmation != null) confirmation.getText().clear();
                endBackupFlow();
                showStatus("Backup operation cancelled. No keys were changed.");
            })
            .setOnCancelListener(canceledDialog -> {
                password.getText().clear();
                if (confirmation != null) confirmation.getText().clear();
                endBackupFlow();
            })
            // The framework's default positive-button callback dismisses the
            // dialog even if validation fails. Keep this SAME dialog and its
            // editable fields until the password is actually valid.
            .setPositiveButton(exporting ? "Encrypt and save archive" : "Continue restore",
                null)
            .create();
        dialog.show();
        styleDialog(dialog, false);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
                char[] passphrase = editableChars(password.getText());
                char[] repeated = confirmation == null ? null
                    : editableChars(confirmation.getText());
                try {
                    int minimum = exporting ? 16 : 12;
                    if (passphrase.length < minimum) {
                        password.setError("Enter at least " + minimum + " characters");
                        password.requestFocus();
                        return;
                    }
                    if (repeated != null && !Arrays.equals(passphrase, repeated)) {
                        confirmation.setError("Passphrases do not match");
                        confirmation.requestFocus();
                        return;
                    }
                    password.getText().clear();
                    if (confirmation != null) confirmation.getText().clear();
                    dialog.dismiss();
                    // Ownership passes to exportRecovery/restoreRecovery, which
                    // wipe passphrase after PBKDF2 or on any failure.
                    char[] accepted = passphrase;
                    passphrase = null;
                    try {
                        onConfirmed.accept(accepted);
                    } catch (RuntimeException failed) {
                        Arrays.fill(accepted, '\0');
                        endBackupFlow();
                        showStatus("Backup could not start. No keys were changed.");
                    }
                } finally {
                    if (passphrase != null) Arrays.fill(passphrase, '\0');
                    if (repeated != null) Arrays.fill(repeated, '\0');
                }
            });
    }

    private EditText passwordField(String label) {
        EditText field = new EditText(this);
        field.setHint(label);
        field.setSingleLine(true);
        field.setTextSize(16);
        field.setTextColor(foreground);
        field.setHintTextColor(muted);
        field.setBackgroundTintList(ColorStateList.valueOf(accent));
        field.setInputType(InputType.TYPE_CLASS_TEXT
            | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        field.setSaveEnabled(false);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        field.setContentDescription(label);
        return field;
    }

    private static char[] editableChars(Editable text) {
        // Never construct an immutable Java String containing the passphrase.
        char[] out = new char[text.length()];
        for (int i = 0; i < out.length; i++) out[i] = text.charAt(i);
        return out;
    }

    private void startExport() {
        if (backupBusy || backupFlowActive || deletionBusy || deletionSignal != null
            || recoverySignal != null
            || binder == null || helper == null || helper.keys == null
            || (displayed != null && !displayed.isDone())) {
            showStatus("Finish the current security-key request before exporting.");
            return;
        }
        boolean anyRecoverable = false;
        for (CryptoKeyManager.CredentialInfo info : cachedCatalog) {
            if (info.recoverable) {
                anyRecoverable = true;
                break;
            }
        }
        if (!anyRecoverable) {
            AlertDialog promptDialog = styledDialog("RECOVERY BACKUP",
                "No recoverable credentials yet",
                "Credentials created by MobileFIDO 4.x were generated nonexportable "
                    + "inside Android Keystore and cannot be converted after the fact. "
                    + "Register a new credential with MobileFIDO 5 first; it will be marked "
                    + "Recoverable and can be included in a FIDO CXF recovery archive.",
                null, false)
                .setPositiveButton("OK", null)
                .create();
            promptDialog.show();
            styleDialog(promptDialog, false);
            return;
        }
        clearNotificationIntent();
        backupFlowActive = true;
        updateButtons();
        AlertDialog promptDialog = styledDialog("RECOVERY BACKUP",
            "Export recovery archive",
            "This encrypted archive contains the PKCS#8 recovery copy defined by "
                + "FIDO Credential Exchange Format 1.0 and can recreate your MobileFIDO 5 "
                + "passkeys after a reset. "
                + "Normal authentication still uses the StrongBox/TEE copy. "
                + "Anyone who obtains both the archive and its passphrase can recreate "
                + "those passkeys, so store both carefully. Legacy 4.x keys are excluded. "
                + "Save each new archive as a separate file until the latest one "
                + "is verified; do not overwrite your only working backup.", null, false)
            .setNegativeButton("Cancel", (dialog, which) -> endBackupFlow())
            .setOnCancelListener(dialog -> endBackupFlow())
            .setPositiveButton("Choose save location", (dialog, which) -> {
                // Choose a destination FIRST. Otherwise SAF can background or
                // recreate this Activity while it owns a live passphrase,
                // silently discarding it and asking the user to enter it again.
                // Passwords are created only after RESULT_OK from the picker.
                Intent picker = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                picker.addCategory(Intent.CATEGORY_OPENABLE);
                picker.setType("application/octet-stream");
                // A unique filename reduces accidental overwrite of the only
                // known-good recovery archive if SAF crashes mid-export.
                String suffix = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss",
                    Locale.US).format(new Date());
                picker.putExtra(Intent.EXTRA_TITLE,
                    "MobileFIDO-Recovery-" + suffix + "-"
                    + (System.currentTimeMillis() % 1000L) + ".mobilefido");
                try {
                    startActivityForResult(picker, CREATE_BACKUP);
                } catch (RuntimeException unavailable) {
                    endBackupFlow();
                    showStatus("No document provider is available to save the backup.");
                }
            })
            .create();
        promptDialog.show();
        styleDialog(promptDialog, false);
    }

    private void startImport() {
        if (backupBusy || backupFlowActive || deletionBusy || deletionSignal != null
            || recoverySignal != null
            || binder == null || helper == null || helper.keys == null
            || (displayed != null && !displayed.isDone())) {
            showStatus("Finish the current security-key request before restoring.");
            return;
        }
        clearNotificationIntent();
        backupFlowActive = true;
        updateButtons();
        AlertDialog promptDialog = styledDialog("RECOVERY BACKUP",
            "Restore from backup",
            "A MobileFIDO 5 recovery archive can re-import the original FIDO "
                + "private key into this phone's StrongBox/TEE and recreate the same "
                + "credential ID after deletion, app-data loss or factory reset. Existing "
                + "matching credentials are preserved. Older 4.x metadata-only archives "
                + "remain readable, but they still cannot recreate a deleted legacy key.",
            null, false)
            .setNegativeButton("Cancel", (dialog, which) -> endBackupFlow())
            .setOnCancelListener(dialog -> endBackupFlow())
            .setPositiveButton("Choose backup file", (dialog, which) -> {
                Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                picker.addCategory(Intent.CATEGORY_OPENABLE);
                picker.setType("*/*"); // Cloud providers vary in MIME support.
                try {
                    startActivityForResult(picker, OPEN_BACKUP);
                } catch (RuntimeException unavailable) {
                    endBackupFlow();
                    showStatus("No document provider is available to open the backup.");
                }
            }).create();
        promptDialog.show();
        styleDialog(promptDialog, false);
    }

    private void startVerify() {
        if (backupBusy || backupFlowActive || deletionBusy || deletionSignal != null
            || recoverySignal != null || binder == null || helper == null
            || helper.keys == null || (displayed != null && !displayed.isDone())) {
            showStatus("Finish the current security-key request before verifying a backup.");
            return;
        }
        clearNotificationIntent();
        backupFlowActive = true;
        updateButtons();
        AlertDialog promptDialog = styledDialog("RECOVERY BACKUP",
            "Verify saved backup",
            "Choose an existing .mobilefido file. MobileFIDO will check its "
                + "password, authenticated contents, recoverable private/public key pairs "
                + "and coverage of credentials currently on this phone. "
                + "This READ-ONLY check never imports or deletes a key. "
                + "Legacy 4.x metadata-only archives cannot pass this full-recovery check.",
            null, false)
            .setNegativeButton("Cancel", (dialog, which) -> endBackupFlow())
            .setOnCancelListener(dialog -> endBackupFlow())
            .setPositiveButton("Choose saved archive", (dialog, which) -> {
                Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                picker.addCategory(Intent.CATEGORY_OPENABLE);
                picker.setType("*/*");
                try {
                    startActivityForResult(picker, VERIFY_BACKUP);
                } catch (RuntimeException unavailable) {
                    endBackupFlow();
                    showStatus("No document provider is available to read the archive.");
                }
            }).create();
        promptDialog.show();
        styleDialog(promptDialog, false);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == CREATE_BACKUP) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null) {
                Uri document = data.getData();
                backupFlowActive = true;
                updateButtons();
                showPasswordDialog(true, passphrase ->
                    authorizeRecoveryOperation("Authorize recovery export",
                        "Archive contains passkey recovery material", 16, passphrase,
                        authorized -> exportRecovery(document, authorized)));
            } else {
                endBackupFlow();
                showStatus("Export cancelled. Original keys and metadata unchanged.");
            }
        } else if (requestCode == OPEN_BACKUP && resultCode == RESULT_OK
            && data != null && data.getData() != null) {
            Uri document = data.getData();
            showPasswordDialog(false, passphrase ->
                authorizeRecoveryOperation("Authorize passkey restore",
                    "Recovered keys will be imported into StrongBox/TEE", 12, passphrase,
                    authorized -> restoreRecovery(document, authorized)));
        } else if (requestCode == VERIFY_BACKUP && resultCode == RESULT_OK
            && data != null && data.getData() != null) {
            Uri document = data.getData();
            showPasswordDialog(false, passphrase -> {
                if (passphrase.length < 16) {
                    Arrays.fill(passphrase, '\0');
                    endBackupFlow();
                    showStatus("Full recovery archives require the original "
                        + "16+ character user-chosen recovery passphrase. "
                        + "Legacy metadata-only archives cannot verify as full backups.");
                    return;
                }
                authorizeRecoveryOperation("Authorize archive verification",
                    "Read-only inspection of encrypted passkey recovery data", 16,
                    passphrase, authorized -> verifySavedRecovery(document, authorized));
            });
        } else if (requestCode == VERIFY_BACKUP) {
            endBackupFlow();
            showStatus("Archive verification cancelled. No keys were changed.");
        } else if (requestCode == OPEN_BACKUP) {
            endBackupFlow();
            showStatus("Restore cancelled. No keys were changed.");
        }
    }

    private void endBackupFlow() {
        backupFlowActive = false;
        if (recoveryMaintenanceActive) {
            recoveryMaintenanceActive = false;
            HelperService.LocalBinder owner = recoveryMaintenanceBinder;
            recoveryMaintenanceBinder = null;
            long token = recoveryMaintenanceToken;
            recoveryMaintenanceToken = 0L;
            if (owner != null && token != 0L) owner.endRecoveryMaintenance(token);
        }
        updateButtons();
        // A CTAP request may have arrived while Android's SAF UI or password
        // dialog covered us. Reconcile it only after the backup flow ends.
        if (binder != null) binder.uiStateChanged(this);
    }

    private void authorizeRecoveryOperation(String title, String subtitle,
            int minimumPassphraseLength, char[] passphrase, Consumer<char[]> onAuthorized) {
        if (passphrase == null || passphrase.length < minimumPassphraseLength
            || minimumPassphraseLength < 12 || minimumPassphraseLength > 16
            || recoverySignal != null
            || isFinishing() || isDestroyed() || !resumed || helper == null || binder == null
            || (displayed != null && !displayed.isDone())) {
            if (passphrase != null) Arrays.fill(passphrase, '\0');
            endBackupFlow();
            showStatus("Recovery operation was not authorized. No credentials changed.");
            return;
        }
        HelperService.LocalBinder maintenanceBinder = binder;
        long maintenanceToken = maintenanceBinder.beginRecoveryMaintenance();
        if (maintenanceToken == 0L) {
            Arrays.fill(passphrase, '\0');
            endBackupFlow();
            showStatus("A security-key request is active. Finish it before recovery export/import.");
            return;
        }
        recoveryMaintenanceActive = true;
        recoveryMaintenanceBinder = maintenanceBinder;
        recoveryMaintenanceToken = maintenanceToken;
        BiometricManager biometrics = getSystemService(BiometricManager.class);
        if (biometrics == null || biometrics.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG)
                != BiometricManager.BIOMETRIC_SUCCESS) {
            Arrays.fill(passphrase, '\0');
            endBackupFlow();
            showStatus("A STRONG enrolled biometric is required for passkey recovery export/import.");
            return;
        }
        final CancellationSignal signal = new CancellationSignal();
        recoverySignal = signal;
        updateButtons();
        BiometricPrompt prompt = new BiometricPrompt.Builder(this)
            .setTitle(title)
            .setSubtitle(subtitle)
            .setDescription("This operation handles encrypted passkey recovery material.")
            .setNegativeButton("Cancel", getMainExecutor(), (dialog, which) -> signal.cancel())
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build();
        prompt.authenticate(signal, getMainExecutor(),
            new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(
                        BiometricPrompt.AuthenticationResult result) {
                    if (recoverySignal != signal || signal.isCanceled() || isFinishing()
                        || isDestroyed() || helper == null) {
                        Arrays.fill(passphrase, '\0');
                        if (recoverySignal == signal) recoverySignal = null;
                        endBackupFlow();
                        return;
                    }
                    recoverySignal = null;
                    updateButtons();
                    try {
                        onAuthorized.accept(passphrase);
                    } catch (RuntimeException failed) {
                        Arrays.fill(passphrase, '\0');
                        endBackupFlow();
                        showStatus("Recovery operation could not start. No credentials changed.");
                    }
                }

                @Override public void onAuthenticationError(int code, CharSequence reason) {
                    if (recoverySignal == signal) recoverySignal = null;
                    Arrays.fill(passphrase, '\0');
                    endBackupFlow();
                    showStatus("Recovery operation cancelled; passphrase and key material were discarded.");
                }
            });
    }

    private void exportRecovery(Uri document, char[] passphrase) {
        HelperService service = helper;
        if (backupBusy || service == null || service.keys == null) {
            Arrays.fill(passphrase, '\0');
            endBackupFlow();
            showStatus("Service unavailable. Recovery export not started.");
            return;
        }
        backupBusy = true;
        updateButtons();
        showStatus("Building encrypted FIDO recovery archive…");
        CryptoKeyManager keys = service.keys;
        cryptoExecutor.execute(() -> {
            RecoverableBackupManager.ExportResult exported = null;
            char[] verifyPassword = passphrase.clone();
            String result;
            boolean saved = false;
            boolean fileWritten = false;
            try {
                exported = RecoverableBackupManager.exportEncrypted(keys, passphrase);
                if (exported.blob == null || exported.blob.length == 0
                    || exported.blob.length > MAX_BACKUP_BYTES) {
                    throw new IOException("recovery archive size invalid");
                }
                try (OutputStream output =
                        getContentResolver().openOutputStream(document, "wt")) {
                    if (output == null) throw new IOException("document not writable");
                    output.write(exported.blob);
                    output.flush();
                }
                fileWritten = true;
                // A successful SAF write/flush alone does not prove a cloud
                // provider actually saved a complete restorable archive.
                // Read the selected document back through the provider, then
                // authenticate/decode CXF using the user's same passphrase.
                String fingerprint;
                try (InputStream savedFile = getContentResolver()
                        .openInputStream(document)) {
                    fingerprint = RecoveryArchiveVerifier.verifyReadback(
                        savedFile, exported.blob, MAX_BACKUP_BYTES);
                }
                RecoverableBackupManager.InspectionResult inspected =
                    RecoverableBackupManager.verifyEncrypted(exported.blob,
                        verifyPassword, exported.credentialIds);
                if (inspected.credentialIds.size() != exported.credentialIds.size()
                    || !keys.markRecoveryArchiveVerified(exported.credentialIds,
                        fingerprint, System.currentTimeMillis())) {
                    throw new IOException("Verified archive status could not be committed");
                }
                saved = true;
                result = "Recovery archive SAVED AND VERIFIED: " + exported.credentialIds.size()
                    + " recoverable FIDO credential"
                    + (exported.credentialIds.size() == 1 ? "" : "s") + ". "
                    + (exported.legacySkipped == 0 ? ""
                        : exported.legacySkipped + " legacy device-bound credential"
                            + (exported.legacySkipped == 1 ? " was" : "s were")
                            + " excluded because their private keys are nonexportable. ")
                    + " The document was read back byte-for-byte and its "
                    + "encrypted passkeys were authenticated. Keep this archive "
                    + "and your chosen passphrase secure.";
            } catch (Exception failed) {
                result = fileWritten
                    ? "A file may have been written, but MobileFIDO COULD NOT "
                        + "VERIFY IT or record its freshness. Do not delete credentials "
                        + "or wipe your phone relying on that file. Retain your previous "
                        + "backup and export again to a readable document provider."
                    : "Recovery export was interrupted or failed; the chosen file "
                        + "may be incomplete. Do not rely on it. Original signing "
                        + "keys and credentials were not changed.";
            } finally {
                Arrays.fill(passphrase, '\0');
                Arrays.fill(verifyPassword, '\0');
                if (exported != null && exported.blob != null) {
                    Arrays.fill(exported.blob, (byte) 0);
                }
            }
            final String message = result;
            final boolean refresh = saved;
            runOnUiThread(() -> {
                backupBusy = false;
                endBackupFlow();
                showStatus(message);
                if (refresh) refreshCredentials();
                if (!isFinishing() && !isDestroyed()) {
                    AlertDialog resultDialog = styledDialog(
                        refresh ? "BACKUP VERIFIED" : "BACKUP WARNING",
                        refresh ? "Recovery archive saved and verified"
                            : "Recovery archive not verified",
                        message, null, !refresh)
                        .setPositiveButton("OK", null)
                        .create();
                    resultDialog.show();
                    styleDialog(resultDialog, false);
                }
            });
        });
    }

    private static byte[] readRecoveryDocument(InputStream input) throws IOException {
        if (input == null) throw new IOException("Recovery document unavailable");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        try {
            int size;
            while ((size = input.read(chunk)) != -1) {
                if (size == 0) {
                    // A buggy SAF cloud provider may repeatedly produce empty
                    // array reads. Consume one byte or EOF instead of spinning
                    // forever while holding recovery maintenance.
                    int one = input.read();
                    if (one == -1) break;
                    if (buffer.size() >= MAX_BACKUP_BYTES) {
                        throw new IOException("Encrypted recovery archive exceeds limit");
                    }
                    buffer.write(one);
                    continue;
                }
                if (size > MAX_BACKUP_BYTES - buffer.size()) {
                    throw new IOException("Encrypted recovery archive exceeds limit");
                }
                buffer.write(chunk, 0, size);
            }
            return buffer.toByteArray();
        } finally {
            Arrays.fill(chunk, (byte) 0);
        }
    }

    private void verifySavedRecovery(Uri document, char[] passphrase) {
        HelperService service = helper;
        if (backupBusy || service == null || service.keys == null) {
            Arrays.fill(passphrase, '\0');
            endBackupFlow();
            showStatus("Service unavailable. Archive inspection not started.");
            return;
        }
        backupBusy = true;
        updateButtons();
        showStatus("Verifying saved recovery archive without importing keys…");
        CryptoKeyManager keys = service.keys;
        cryptoExecutor.execute(() -> {
            byte[] archive = null;
            String message;
            boolean valid = false;
            try (InputStream input = getContentResolver().openInputStream(document)) {
                archive = readRecoveryDocument(input);
                if (!RecoverableBackupManager.looksLikeArchive(archive)) {
                    throw new IOException("Not a full recoverable passkey archive");
                }
                RecoverableBackupManager.InspectionResult inspection =
                    RecoverableBackupManager.inspectEncrypted(keys, archive, passphrase);
                CryptoKeyManager.ArchiveCoverage coverage = inspection.coverage;
                boolean completeAndVerified = coverage.missingFromArchive == 0
                    && coverage.conflictsOnPhone == 0
                    && coverage.archivedNotOnPhone == 0
                    && !inspection.credentialIds.isEmpty();
                boolean freshnessSaved = false;
                if (completeAndVerified) {
                    String fingerprint = RecoveryArchiveVerifier.encryptedFingerprint(
                        archive, MAX_BACKUP_BYTES);
                    freshnessSaved = keys.markRecoveryArchiveVerified(
                        inspection.credentialIds, fingerprint, System.currentTimeMillis());
                }
                message = "Encrypted archive authenticated; "
                    + inspection.credentialIds.size() + " recoverable credential(s) "
                    + "passed CXF and private/public key validation.\n"
                    + coverage.matchingOnPhone + " match this phone · "
                    + coverage.missingFromArchive + " current recoverable credential(s) "
                    + "missing from this file · "
                    + coverage.conflictsOnPhone + " mismatch/unavailable on this phone · "
                    + coverage.archivedNotOnPhone + " in archive but not on this phone.\n"
                    + (completeAndVerified && freshnessSaved
                        ? "All current recoverable credentials are covered by "
                            + "this file. Verified backup dates updated."
                        : completeAndVerified
                        ? "This archive matches all current recoverable credentials, "
                            + "but verified dates could not be saved. Keep the file."
                        : "This archive is not a complete, matching backup "
                            + "of the current phone. Export a fresh one before a reset.")
                    + "\nVerification did not import, replace, sign with or delete any key.";
                valid = true;
            } catch (Exception failed) {
                message = "Recovery file failed validation or could not be read. "
                    + "Check the chosen passphrase, file and document provider. "
                    + "No signing keys or credentials were modified.";
            } finally {
                Arrays.fill(passphrase, '\0');
                if (archive != null) Arrays.fill(archive, (byte) 0);
            }
            final String result = message;
            final boolean verified = valid;
            runOnUiThread(() -> {
                backupBusy = false;
                endBackupFlow();
                showStatus(result);
                if (verified) refreshCredentials();
                if (!isFinishing() && !isDestroyed()) {
                    AlertDialog resultDialog = styledDialog(
                        verified ? "BACKUP VERIFIED" : "BACKUP WARNING",
                        verified ? "Archive integrity checked"
                            : "Archive verification failed",
                        result, null, !verified)
                        .setPositiveButton("OK", null).create();
                    resultDialog.show();
                    styleDialog(resultDialog, false);
                }
            });
        });
    }

    private void restoreRecovery(Uri document, char[] passphrase) {
        HelperService service = helper;
        if (backupBusy || service == null || service.keys == null) {
            Arrays.fill(passphrase, '\0');
            endBackupFlow();
            showStatus("Service unavailable. Recovery restore not started.");
            return;
        }
        backupBusy = true;
        updateButtons();
        showStatus("Reading and verifying encrypted recovery archive…");
        CryptoKeyManager keys = service.keys;
        cryptoExecutor.execute(() -> {
            byte[] ciphertext = null;
            String result;
            boolean restored = false;
            boolean legacyArchive = false;
            boolean legacyMissingKeys = false;
            try (InputStream input = getContentResolver().openInputStream(document)) {
                if (input == null) throw new IOException("document unavailable");
                ciphertext = readRecoveryDocument(input);
                if (RecoverableBackupManager.looksLikeArchive(ciphertext)) {
                    RecoverableBackupManager.RestoreResult outcome =
                        RecoverableBackupManager.restoreEncrypted(keys, ciphertext, passphrase);
                    result = "Recovery complete. Restored FIDO credentials: " + outcome.restored
                        + " · Already present: " + outcome.alreadyPresent
                        + ". Restored signing keys were imported into this phone's "
                        + "StrongBox/TEE and require per-use STRONG biometric approval.";
                } else {
                    legacyArchive = true;
                    BackupManager.RestoreResult outcome =
                        BackupManager.restoreEncrypted(keys, ciphertext, passphrase);
                    legacyMissingKeys = outcome.unavailable > 0;
                    result = "Legacy 4.x metadata archive checked. Restored metadata: "
                        + outcome.restored + " · Already present: " + outcome.alreadyPresent
                        + " · Missing original hardware keys: " + outcome.unavailable + ". "
                        + "This older archive never contained private keys, so deleted or "
                        + "factory-reset legacy credentials cannot be recreated.";
                }
                restored = true;
            } catch (Exception failed) {
                result = "Recovery failed or passphrase/archive validation was rejected. "
                    + "No unverified credential was made usable.";
            } finally {
                Arrays.fill(passphrase, '\0');
                if (ciphertext != null) Arrays.fill(ciphertext, (byte) 0);
            }
            final String message = result;
            final boolean refresh = restored;
            final boolean oldArchive = legacyArchive;
            final boolean missingHardware = legacyMissingKeys;
            runOnUiThread(() -> {
                backupBusy = false;
                endBackupFlow();
                showStatus(message);
                if (refresh) refreshCredentials();
                if (!isFinishing() && !isDestroyed()) {
                    boolean warning = !refresh || (oldArchive && missingHardware);
                    AlertDialog resultDialog = styledDialog(
                        warning ? "RECOVERY WARNING" : "RECOVERY COMPLETE",
                        !refresh ? "Recovery failed"
                            : oldArchive && missingHardware
                                ? "Legacy keys cannot be recovered"
                                : oldArchive ? "Legacy metadata restored"
                                : "FIDO credentials restored",
                        message, null, warning)
                        .setPositiveButton("OK", null)
                        .create();
                    resultDialog.show();
                    styleDialog(resultDialog, false);
                }
            });
        });
    }

    @Override public void onStart() {
        super.onStart();
        Intent service = new Intent(this, HelperService.class);
        try {
            // A normal background Service will be reclaimed after the app
            // leaves foreground. Start a user-visible specialUse FGS once the
            // user opens the app; never request background Activity launch.
            startForegroundService(service);
            attached = bindService(service, connection, BIND_AUTO_CREATE);
            if (!attached) showStatus("Could not bind the hardware-key service");
        } catch (RuntimeException rejected) {
            Log.w(LOG_TAG, "Service startup rejected: " +
                rejected.getClass().getSimpleName());
            showStatus("Android blocked the hardware-key listener. " +
                "Open the app and check foreground-service/notification settings.");
        }
    }

    @Override public void onResume() {
        super.onResume();
        resumed = true;
        renderNotificationState();
        renderListenerStatus();
        uiHandler.removeCallbacks(listenerRefresh);
        uiHandler.post(listenerRefresh);
        if (helper != null && !backupBusy && !backupFlowActive) {
            scheduleCatalogRefresh();
        }
        // Binding may have completed while permission UI covered us; ask the
        // service to redeliver its pending operation on this visible screen.
        if (binder != null) binder.uiStateChanged(this);
        maybeAuthorize();
    }

    @Override public void onPause() {
        resumed = false;
        uiHandler.removeCallbacks(listenerRefresh);
        // The Activity can remain bound between onPause and onStop. Previously
        // ui != null caused a request arriving in this window to be lost:
        // no notification and no biometric prompt until foregrounded again.
        if (binder != null) binder.uiStateChanged(this);
        super.onPause();
    }

    @Override public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        // An explicit notification tap brings THIS Activity forward. The
        // local Binder gives it only the current live operation (no request
        // parameters or secret data are ever trusted from this Intent).
        maybeAuthorize();
    }

    private void clearNotificationIntent() {
        // An old PendingIntent must not constrain a later user-initiated
        // launcher/demo request after the previous approval has completed.
        setIntent(new Intent(this, MainActivity.class).setAction(Intent.ACTION_MAIN));
    }

    @Override public void onRequestPermissionsResult(int requestCode,
            String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != 601) return;
        notificationPermissionPending = false;
        renderNotificationState();
        if (grantResults.length == 0
            || grantResults[0] != PackageManager.PERMISSION_GRANTED) {
            showStatus("Notifications not allowed: keep this Activity visible " +
                "for CTAP requests, or enable notifications in app settings.");
        }
        maybeAuthorize();
        if (binder != null) binder.uiStateChanged(this);
    }

    @Override public void onStop() {
        if (deletionSignal != null) {
            deletionSignal.cancel();
            deletionSignal = null;
        }
        if (recoverySignal != null) {
            recoverySignal.cancel();
            recoverySignal = null;
            // No recovery crypto task owns the maintenance lock until the
            // biometric succeeds. If this Activity disappears mid-prompt,
            // release immediately so CTAP cannot remain blocked indefinitely.
            if (!backupBusy) endBackupFlow();
        }
        // An unclaimed account chooser must not retain a dead Activity or
        // authorize the eventual request in the background.
        if (accountDialog != null) accountDialog.dismiss();
        accountDialog = null;
        accountDialogOperation = null;
        ++credentialRefreshId; // Discard stale catalog callbacks for this screen.
        if (binder != null) {
            binder.detach(this); // cancel claimed biometric; notify if unclaimed
            binder = null;
        }
        helper = null;
        if (attached) {
            unbindService(connection);
            attached = false;
        }
        displayed = null;
        super.onStop();
    }

    @Override public void onDestroy() {
        uiHandler.removeCallbacks(listenerRefresh);
        diagnosticsExecutor.shutdownNow();
        cryptoExecutor.shutdownNow();
        super.onDestroy();
    }

    void showStatus(String text) {
        runOnUiThread(() -> {
            if (status != null) status.setText(text);
            renderApprovalPanel();
        });
    }

    @Override public boolean isReadyForPrompt() {
        return resumed && attached && binder != null && helper != null
            && !notificationPermissionPending && !backupBusy
            && !backupFlowActive && !deletionBusy && deletionSignal == null
            && recoverySignal == null
            && !isFinishing();
    }

    private void renderApprovalPanel() {
        if (pendingPanel == null || pendingDescription == null) return;
        HelperService.Operation operation = displayed;
        boolean active = operation != null && !operation.isDone();
        pendingPanel.setVisibility(active ? View.VISIBLE : View.GONE);
        if (!active) return;
        String title = "makeCredential".equals(operation.op)
            ? "New credential requested for " + operation.rpId
            : "Authentication requested for " + operation.rpId;
        pendingDescription.setText(title + "\n\n"
            + (operation.discoverable ? "Discoverable account request · " : "")
            + (operation.promptClaimed.get()
                ? "Preparing per-use hardware signature and biometric approval…"
                : "Open the approval notification to confirm with fingerprint.")
            + "\nStrong biometric required · No silent signing"
            + (operation.up ? "" : " · Windows up=false preflight"));
    }

    @Override public void onOperation(HelperService.Operation operation) {
        if (!attached || binder == null || isFinishing() || operation.isDone()) {
            operation.cancel("NOT_ALLOWED");
            return;
        }
        if (displayed == operation) {
            renderApprovalPanel();
            maybeAuthorize();
            return;
        }
        if (displayed != null && !displayed.isDone()) {
            // The service permits one operation at a time; refuse a second
            // delivery instead of opening overlapping biometric prompts.
            operation.cancel("NOT_ALLOWED");
            return;
        }
        displayed = operation;
        updateButtons();
        renderApprovalPanel();
        if (!RelyingPartyPolicy.valid(operation.rpId)) {
            operation.cancel("NOT_ALLOWED");
            return;
        }
        maybeAuthorize();
    }

    private void maybeAuthorize() {
        HelperService.Operation operation = displayed;
        if (operation == null || operation.isDone() || !attached ||
            binder == null || helper == null || isFinishing() || !resumed ||
            notificationPermissionPending || backupBusy || backupFlowActive
            || deletionBusy || deletionSignal != null || recoverySignal != null) {
            return;
        }
        Intent launch = getIntent();
        if (launch != null && HelperService.ACTION_OPEN_APPROVAL.equals(launch.getAction())) {
            String token = launch.getStringExtra(HelperService.EXTRA_APPROVAL_TOKEN);
            if (!operation.notificationToken.equals(token)) {
                // Race: a just-expired notification was tapped while a NEW
                // request became active. Never auto-authorize the newer
                // request using an old tap. Leave its own alert untouched.
                showStatus("That security-key request expired. " +
                    "Tap the latest approval notification or reopen the app.");
                return;
            }
            // Consume the one-time launch token before another operation can
            // arrive while this Activity remains on screen.
            clearNotificationIntent();
        }
        if ("getAssertion".equals(operation.op) && operation.discoverable
            && operation.credentialId == null) {
            chooseDiscoverableAccount(operation);
            return;
        }
        if (!operation.promptClaimed.compareAndSet(false, true)) {
            return; // Activity resume/notification re-tap must NOT reprompt.
        }
        renderApprovalPanel();
        binder.approvalClaimed(operation, this);
        if (operation.excluded) {
            operation.cancel("CREDENTIAL_EXCLUDED");
            showStatus("Credential already registered for " + operation.rpId);
            return;
        }
        showStatus("Authorize " + operation.op + " for " + operation.rpId + " with " +
            "STRONG biometric" + (operation.up ? "" :
            " (Windows up=false preflight; UP remains false)"));
        // No intermediate Continue button or silent signature: immediately
        // prepare an authenticated, per-use AndroidKeyStore CryptoObject.
        prepareSignature(operation);
    }

    private void chooseDiscoverableAccount(HelperService.Operation operation) {
        if (operation.isDone() || accountDialogOperation == operation) return;
        List<CryptoKeyManager.CredentialInfo> choices = operation.accountChoices;
        if (choices.size() < 2) {
            operation.cancel("NO_CREDENTIALS");
            return;
        }
        String[] labels = new String[choices.size()];
        for (int i = 0; i < choices.size(); i++) {
            CryptoKeyManager.CredentialInfo info = choices.get(i);
            labels[i] = credentialAccount(info) + " — " + info.rpId
                + "  ·  " + info.securityLevel;
        }
        // No account selection comes from the Windows host, notifications,
        // saved Activity state, or untrusted Intents. Choose on THIS phone,
        // then prepare that RP's key for a fresh biometric CryptoObject.
        accountDialogOperation = operation;
        accountDialog = new AlertDialog.Builder(this)
            .setCustomTitle(dialogContent("CHOOSE ACCOUNT",
                "Choose a " + operation.rpId + " account",
                "Select the credential to use. Your fingerprint will be required next.",
                null, false))
            .setItems(labels, (dialog, index) -> {
                accountDialog = null;
                accountDialogOperation = null;
                if (!operation.selectAccount(choices.get(index).credentialId)) {
                    operation.cancel("NOT_ALLOWED");
                    return;
                }
                maybeAuthorize();
            })
            .setNegativeButton("Deny", (dialog, which) -> {
                accountDialog = null;
                accountDialogOperation = null;
                operation.cancel("CANCELLED");
            })
            .setOnCancelListener(dialog -> {
                accountDialog = null;
                accountDialogOperation = null;
                if (!operation.isDone()) operation.cancel("CANCELLED");
            })
            .create();
        accountDialog.show();
        styleDialog(accountDialog, false);
    }

    private void prepareSignature(HelperService.Operation operation) {
        BiometricManager biometrics = getSystemService(BiometricManager.class);
        if (biometrics == null || biometrics.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG)
                != BiometricManager.BIOMETRIC_SUCCESS) {
            operation.cancel("NOT_ALLOWED");
            showStatus("A strong enrolled biometric is required");
            return;
        }
        showStatus("Preparing AndroidKeyStore per-use ES256 operation …");
        // Keep a stable manager reference through Activity.onStop(): an
        // asynchronous StrongBox generation may finish AFTER the foreground
        // user dismisses the Activity and helper is cleared. The uncommitted
        // key must still be removed rather than orphaned in AndroidKeyStore.
        HelperService service = helper;
        if (service == null || service.keys == null) {
            operation.cancel("CANCELLED");
            return;
        }
        CryptoKeyManager keyManager = service.keys;
        cryptoExecutor.execute(() -> {
            try {
                Signature signature;
                if ("makeCredential".equals(operation.op)) {
                    CryptoKeyManager.CreatedKey created =
                        keyManager.prepareRegistration(operation.rpId, operation.userId,
                            operation.discoverable, operation.userName,
                            operation.displayName);
                    synchronized (operation) {
                        if (operation.isDone()) {
                            keyManager.discardUncommitted(created);
                            return;
                        }
                        operation.newKey = created;
                    }
                    signature = created.signature;
                } else {
                    signature = keyManager
                        .prepareAssertion(operation.credentialId, operation.rpId).signature;
                }
                runOnUiThread(() -> {
                    if (operation.isDone() || isFinishing() || !attached || !resumed) {
                        operation.cancel("CANCELLED");
                    } else {
                        authenticateCrypto(operation, signature);
                    }
                });
            } catch (Exception denied) {
                String safe = CryptoKeyManager.safeDiagnostic(denied);
                Log.w(LOG_TAG, "Key preparation failed: " + safe);
                operation.cancel("NOT_ALLOWED");
                showStatus("Hardware key preparation failed: " + safe);
            }
        });
    }

    // Filled by the local Binder connection; no external Binder or Service
    // instance can inject a key manager reference.
    private HelperService helper;

    private HelperService getServicePlaceholder() {
        if (helper == null) throw new IllegalStateException("service not bound");
        return helper;
    }

    private void authenticateCrypto(HelperService.Operation operation, Signature signature) {
        BiometricPrompt prompt = new BiometricPrompt.Builder(this)
            .setTitle("MobileFIDO • " + operation.op)
            .setSubtitle(operation.up
                ? "Confirm hardware-key operation for " + operation.rpId
                : "Verify " + operation.rpId + " (preflight, up=false)")
            .setNegativeButton("Deny", getMainExecutor(),
                (dialog, which) -> operation.cancel("CANCELLED"))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build();
        prompt.authenticate(
            new BiometricPrompt.CryptoObject(signature),
            operation.cancelSignal,
            getMainExecutor(),
            new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(
                    BiometricPrompt.AuthenticationResult result) {
                    Signature authorized = result.getCryptoObject() == null
                        ? null : result.getCryptoObject().getSignature();
                    if (authorized == null) {
                        operation.cancel("NOT_ALLOWED");
                        return;
                    }
                    try {
                        synchronized (operation) {
                            if (operation.isDone()) return;
                            if ("makeCredential".equals(operation.op)) {
                                completeRegistration(operation, authorized);
                            } else {
                                completeAssertion(operation, authorized);
                            }
                        }
                    } catch (Exception failure) {
                        operation.cancel("OTHER");
                        showStatus("Hardware signature or local storage failed");
                    }
                }
                @Override public void onAuthenticationError(int code, CharSequence reason) {
                    operation.cancel("CANCELLED");
                    showStatus("Biometric authorization ended without a signature");
                }
            }
        );
    }

    private void completeRegistration(HelperService.Operation operation,
                                      Signature authorized) throws Exception {
        CryptoKeyManager.CreatedKey key = operation.newKey;
        if (key == null) throw new IllegalStateException("no registration key");
        byte[] proof = getServicePlaceholder().keys.registrationProof(
            operation.rpId, operation.clientDataHash, operation.userId);
        authorized.update(proof);
        authorized.sign(); // Device hardware verifies per-use biometric authorization.
        if (operation.isDone()) return;
        if (!getServicePlaceholder().keys.commitRegistration(key)) {
            operation.cancel("OTHER");
            return;
        }
        JSONObject publicData = new JSONObject();
        publicData.put("credentialId", key.credentialId);
        publicData.put("publicKey", new JSONObject()
            .put("x", CryptoKeyManager.encode(key.x))
            .put("y", CryptoKeyManager.encode(key.y)));
        publicData.put("userVerified", true);
        publicData.put("userPresent", true);
        publicData.put("securityLevel", key.securityLevel);
        publicData.put("backupEligible", key.recoverable);
        publicData.put("backedUp", key.backedUp);
        getPreferences(MODE_PRIVATE).edit()
            .putString("lastDemoCredential", key.credentialId).apply();
        operation.success(publicData);
        showStatus("Registered " + operation.rpId + " key " + key.credentialId.substring(0, 12) +
            "… • " + key.securityLevel + " / per-use STRONG biometric. "
            + (key.recoverable
                ? "Recoverable passkey created · export a recovery archive now."
                : "Device-bound legacy credential."));
        scheduleCatalogRefresh();
    }

    private void completeAssertion(HelperService.Operation operation,
                                   Signature authorized) throws Exception {
        byte[] authData = getServicePlaceholder().keys.assertionData(
            operation.credentialId, operation.rpId, operation.up);
        authorized.update(authData);
        authorized.update(operation.clientDataHash);
        byte[] der = authorized.sign();
        if (operation.isDone()) return;
        JSONObject signed = new JSONObject();
        signed.put("credentialId", operation.credentialId);
        signed.put("authData", CryptoKeyManager.encode(authData));
        signed.put("signature", CryptoKeyManager.encode(der));
        signed.put("userVerified", true);
        signed.put("userPresent", operation.up);
        signed.put("backupEligible",
            getServicePlaceholder().keys.isRecoverable(operation.credentialId));
        signed.put("backedUp",
            getServicePlaceholder().keys.isBackedUp(operation.credentialId));
        if (operation.discoverable) {
            byte[] user = getServicePlaceholder().keys.userForDiscoverable(
                operation.credentialId, operation.rpId);
            signed.put("userId", CryptoKeyManager.encode(user));
            signed.put("discoverable", true);
            Arrays.fill(user, (byte) 0);
        }
        operation.success(signed);
        showStatus("Hardware signature returned after STRONG biometric; UP=" +
            operation.up + " / UV=true");
    }
}
