package org.pocof7.ctap3b;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;
import android.os.Process;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.io.File;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;

/** Read-only, best-effort capability snapshot; safe to call off the UI thread. */
final class DeviceCapabilities {
    enum State { AVAILABLE, UNAVAILABLE, UNKNOWN }

    static final class Snapshot {
        final int sdk;
        final State strongBiometrics;
        final int biometricStatus;
        final State strongBoxFeature;
        final State teeObserved;
        final State strongBoxObserved;
        final State configfsGadget;
        final State hidFunction;
        final State hidDevice;
        final State rootAccess;
        final State kernelSu;

        Snapshot(int sdk, State strongBiometrics, int biometricStatus,
                 State strongBoxFeature, State teeObserved, State strongBoxObserved,
                 State configfsGadget, State hidFunction, State hidDevice,
                 State rootAccess, State kernelSu) {
            this.sdk = sdk;
            this.strongBiometrics = strongBiometrics;
            this.biometricStatus = biometricStatus;
            this.strongBoxFeature = strongBoxFeature;
            this.teeObserved = teeObserved;
            this.strongBoxObserved = strongBoxObserved;
            this.configfsGadget = configfsGadget;
            this.hidFunction = hidFunction;
            this.hidDevice = hidDevice;
            this.rootAccess = rootAccess;
            this.kernelSu = kernelSu;
        }
    }

    private DeviceCapabilities() { }

    /** Does not generate keys, run su, request privileges or change USB state. */
    static Snapshot detect(Context context) {
        int sdk = Build.VERSION.SDK_INT;
        BiometricManager manager = context.getSystemService(BiometricManager.class);
        int biometricStatus = manager == null ? -1 : manager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG);
        State biometrics = manager == null ? State.UNKNOWN
            : biometricStatus == BiometricManager.BIOMETRIC_SUCCESS ? State.AVAILABLE
            : biometricStatus == BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE
                ? State.UNKNOWN : State.UNAVAILABLE;

        boolean strongBox = context.getPackageManager().hasSystemFeature(
            PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        State[] observed = observeExistingSigningKeys();
        File gadget = new File("/sys/kernel/config/usb_gadget");
        State gadgetState = directoryStatus(gadget);
        State hidFunction = gadgetState == State.UNAVAILABLE ? State.UNAVAILABLE
            : detectHidFunction(gadget);
        State hidDevice = fileStatus(new File("/dev/hidg0"));

        // File visibility and installed-manager package visibility are restricted
        // on modern Android. Neither a su binary nor a manager proves usable root.
        return new Snapshot(sdk, biometrics, biometricStatus,
            strongBox ? State.AVAILABLE : State.UNAVAILABLE,
            observed[0], observed[1], gadgetState, hidFunction, hidDevice,
            Process.myUid() == 0 ? State.AVAILABLE : State.UNKNOWN,
            new File("/sys/kernel/ksu").exists() ? State.AVAILABLE : State.UNKNOWN);
    }

    private static State[] observeExistingSigningKeys() {
        boolean tee = false;
        boolean strongBox = false;
        try {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            Enumeration<String> aliases = store.aliases();
            KeyFactory factory = KeyFactory.getInstance("EC", "AndroidKeyStore");
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!alias.matches("ctap3b-[0-9a-fA-F-]{36}")) continue;
                java.security.Key key = store.getKey(alias, null);
                if (!(key instanceof PrivateKey)) continue;
                try {
                    KeyInfo info = factory.getKeySpec((PrivateKey) key, KeyInfo.class);
                    tee |= info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
                    strongBox |= info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX;
                } catch (Exception ignored) {
                    // A key may have been invalidated; continue inspecting others.
                }
            }
        } catch (Exception ignored) {
            // No conclusion about hardware availability is possible on failure.
        }
        return new State[] {tee ? State.AVAILABLE : State.UNKNOWN,
            strongBox ? State.AVAILABLE : State.UNKNOWN};
    }

    private static State directoryStatus(File path) {
        if (path.isDirectory()) return State.AVAILABLE;
        // SELinux can hide configfs even when the kernel supports it.
        return State.UNKNOWN;
    }

    private static State fileStatus(File path) {
        return path.exists() ? State.AVAILABLE : State.UNKNOWN;
    }

    private static State detectHidFunction(File gadget) {
        File[] gadgets = gadget.listFiles();
        if (gadgets == null) return State.UNKNOWN;
        for (File item : gadgets) {
            File[] functions = new File(item, "functions").listFiles();
            if (functions == null) continue;
            for (File function : functions) {
                if (function.getName().startsWith("hid.")) return State.AVAILABLE;
            }
        }
        return State.UNKNOWN;
    }
}
