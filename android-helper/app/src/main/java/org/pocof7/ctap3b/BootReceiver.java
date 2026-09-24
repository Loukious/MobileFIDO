package org.pocof7.ctap3b;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.UserManager;
import android.util.Log;

/**
 * Recreates only the root-only IPC foreground listener after first unlock.
 * Never opens MainActivity, does not approve/sign, and never accesses keys or
 * credential-encrypted metadata from locked-boot/direct-boot context.
 */
public final class BootReceiver extends BroadcastReceiver {
    private static final String LOG_TAG = "Ctap3bHelper";

    @Override public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            return;
        }
        UserManager users = context.getSystemService(UserManager.class);
        if (users == null || !users.isUserUnlocked()) {
            // ACTION_BOOT_COMPLETED is delivered after user unlock on
            // Direct-Boot devices. Do not attempt early Keystore access or
            // move private credentials into device-protected storage.
            Log.w(LOG_TAG, "Boot listener not started: user storage locked");
            return;
        }
        try {
            Intent service = new Intent(context, HelperService.class);
            context.startForegroundService(service);
            Log.i(LOG_TAG, "User-unlocked boot: starting foreground CTAP listener");
        } catch (RuntimeException restricted) {
            // Android/OEM can block background FGS startup (battery policy,
            // force stop, restricted app, changed platform type restrictions).
            // No background Activity fallback or implicit biometric approval.
            Log.w(LOG_TAG, "Boot listener start denied: " +
                restricted.getClass().getSimpleName());
        }
    }
}
