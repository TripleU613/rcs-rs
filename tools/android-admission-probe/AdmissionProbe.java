package org.rcsrs.admissionprobe;

import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.os.Process;
import android.os.Build;
import android.provider.Telephony;
import android.telephony.TelephonyManager;
import org.json.JSONObject;
import java.security.MessageDigest;

/** Self-targeted ordinary-UID diagnostics. Subscriber values never leave readStatus(). */
public final class AdmissionProbe extends Instrumentation {
    private static final String PACKAGE = "org.rcsrs.admissionprobe";
    private static final String[] PERMISSIONS = {
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "READ_PRIVILEGED_PHONE_STATE",
        "USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER", "USE_ICC_AUTH", "INTERNET",
        "ACCESS_NETWORK_STATE", "CHANGE_NETWORK_STATE"
    };
    private interface StringRead { String read(); }

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    private static JSONObject failure(String status, RuntimeException error) throws Exception {
        return new JSONObject().put("status", status)
            .put("exception", error.getClass().getName());
    }

    private static JSONObject readStatus(StringRead reader) throws Exception {
        try {
            String value = reader.read();
            return new JSONObject().put("status",
                value == null || value.isEmpty() ? "absent" : "present");
        } catch (SecurityException error) {
            return failure("denied", error);
        } catch (RuntimeException error) {
            return failure("unavailable", error);
        }
    }

    private static TelephonyManager requireTelephony(TelephonyManager manager) {
        if (manager == null) throw new UnsupportedOperationException();
        return manager;
    }

    private static JSONObject carrierStatus(TelephonyManager manager) throws Exception {
        try {
            return new JSONObject().put("status", "available")
                .put("value", requireTelephony(manager).hasCarrierPrivileges());
        } catch (SecurityException error) {
            return failure("denied", error);
        } catch (RuntimeException error) {
            return failure("unavailable", error);
        }
    }

    private static String certificateSha1(PackageInfo info) throws Exception {
        if (info.signingInfo == null) throw new IllegalStateException();
        Signature[] signatures = info.signingInfo.getApkContentsSigners();
        if (signatures == null || signatures.length != 1) throw new IllegalStateException();
        byte[] digest = MessageDigest.getInstance("SHA-1").digest(signatures[0].toByteArray());
        StringBuilder hex = new StringBuilder(40);
        for (byte value : digest) {
            hex.append(Character.forDigit((value >>> 4) & 15, 16));
            hex.append(Character.forDigit(value & 15, 16));
        }
        return hex.toString();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        int resultCode = 1;
        String json = "{}";
        try {
            Context context = getTargetContext();
            String instrumentationPackage = getContext().getPackageName();
            String targetPackage = context.getPackageName();
            int uid = Process.myUid();
            ApplicationInfo application = context.getApplicationInfo();
            int systemFlags = ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP;
            if (!PACKAGE.equals(instrumentationPackage) || !PACKAGE.equals(targetPackage)
                    || !instrumentationPackage.equals(targetPackage) || uid < 10000
                    || uid % 100000 < 10000 || application.uid != uid
                    || (application.flags & systemFlags) != 0) {
                throw new IllegalStateException();
            }
            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageInfo(targetPackage, PackageManager.GET_SIGNING_CERTIFICATES);
            JSONObject permissions = new JSONObject();
            for (String permission : PERMISSIONS) {
                permissions.put(permission, context.checkSelfPermission("android.permission." + permission)
                    == PackageManager.PERMISSION_GRANTED);
            }
            JSONObject features = new JSONObject()
                .put("telephony", pm.hasSystemFeature("android.hardware.telephony"))
                .put("telephony_subscription", pm.hasSystemFeature("android.hardware.telephony.subscription"))
                .put("ims", pm.hasSystemFeature("android.hardware.telephony.ims"))
                .put("ims_single_registration", pm.hasSystemFeature("android.hardware.telephony.ims.singlereg"));
            TelephonyManager manager = context.getSystemService(TelephonyManager.class);
            JSONObject readings = new JSONObject()
                .put("imsi", readStatus(() -> requireTelephony(manager).getSubscriberId()))
                .put("imei", readStatus(() -> requireTelephony(manager).getImei()))
                .put("own_number", readStatus(() -> requireTelephony(manager).getLine1Number()));
            JSONObject output = new JSONObject()
                .put("schema_version", 1).put("package", targetPackage)
                .put("instrumentation_package", instrumentationPackage).put("target_package", targetPackage)
                .put("certificate_sha1", certificateSha1(info))
                .put("version_code", info.getLongVersionCode()).put("version_name", info.versionName)
                .put("sdk_int", Build.VERSION.SDK_INT).put("uid", uid)
                .put("default_sms", PACKAGE.equals(Telephony.Sms.getDefaultSmsPackage(context)))
                .put("permissions", permissions).put("features", features)
                .put("carrier_privileges", carrierStatus(manager)).put("readings", readings);
            json = output.toString();
            resultCode = 0;
        } catch (Exception ignored) {
            // Fail closed without exception messages, subscriber data, or log output.
        }
        result.putString("rcs_admission", json);
        finish(resultCode, result);
    }
}
