"""Host-only encrypted metadata format tests. No APK, Android runtime, adb or phone.

The production BackupManager.java is compiled against a minimal in-memory
CryptoKeyManager test double in a temporary directory, then exercised by a
plain Java main. This tests the REAL encryption/parser code while the
AndroidKeyStore KeyInfo/alias checks are separately static-audited here.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BACKUP = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/BackupManager.java"
RP_POLICY = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/RelyingPartyPolicy.java"
CRYPTO = ROOT / "android-helper/app/src/main/java/org/pocof7/ctap3b/CryptoKeyManager.java"
JDK = Path("/tmp/jdk-17.0.20.1+1/bin")

STUB = r'''
package org.pocof7.ctap3b;
import java.util.*;
final class CryptoKeyManager {
    static String safeAccountLabel(String label) {
        if(label==null || label.trim().isEmpty()) return null;
        if(label.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>128)
            throw new IllegalArgumentException("label size");
        for(int i=0;i<label.length();) {
            int cp=label.codePointAt(i);
            if(Character.isISOControl(cp) || cp==0x061c || cp==0x200e || cp==0x200f
               || cp>=0x202a && cp<=0x202e || cp>=0x2066 && cp<=0x2069
               || cp>=0xd800 && cp<=0xdfff)
                throw new IllegalArgumentException("label controls");
            i+=Character.charCount(cp);
        }
        return label.trim();
    }
    static final class BackupEntry {
        final byte[] credentialId, userId, publicX, publicY;
        final String alias, rpId, securityLevel;
        final boolean discoverable;
        final String userName, displayName;
        final long createdAtMillis;
        BackupEntry(byte[] id,String rpId,String alias,byte[] user,byte[] x,byte[] y,String level) {
            this(id,rpId,alias,user,x,y,level,false);
        }
        BackupEntry(byte[] id,String rpId,String alias,byte[] user,byte[] x,byte[] y,
                    String level,boolean discoverable) {
            this(id,rpId,alias,user,x,y,level,discoverable,null,null,0L);
        }
        BackupEntry(byte[] id,String rpId,String alias,byte[] user,byte[] x,byte[] y,
                    String level,boolean discoverable,String userName,String displayName,
                    long createdAtMillis) {
            credentialId=id.clone();this.rpId=RelyingPartyPolicy.require(rpId);
            this.alias=alias;userId=user.clone();
            publicX=x.clone();publicY=y.clone();securityLevel=level;
            this.discoverable=discoverable;
            this.userName=userName;this.displayName=displayName;
            this.createdAtMillis=createdAtMillis;
        }
    }
    static final class BackupCatalog {
        final List<BackupEntry> entries; final long counter;
        BackupCatalog(List<BackupEntry> entries,long counter) {
            this.entries=entries;this.counter=counter;
        }
    }
    BackupEntry live;
    BackupEntry saved;
    long counter = 12L;
    CryptoKeyManager(BackupEntry live) { this.live=live; }
    synchronized BackupCatalog snapshotBackup() {
        if (live==null) throw new IllegalStateException("No hardware credentials available to back up");
        return new BackupCatalog(Arrays.asList(new BackupEntry(live.credentialId,
            live.rpId,live.alias,live.userId,live.publicX,live.publicY,
            live.securityLevel,live.discoverable,live.userName,live.displayName,
            live.createdAtMillis)),42L);
    }
    synchronized int[] restoreBackupCatalog(List<BackupEntry> entries,long backupCounter) {
        int restored=0,already=0,unavailable=0;
        for (BackupEntry entry:entries) {
            if (live==null || !live.alias.equals(entry.alias)
                || !live.rpId.equals(entry.rpId)
                || !Arrays.equals(live.publicX,entry.publicX)
                || !Arrays.equals(live.publicY,entry.publicY)
                || !live.securityLevel.equals(entry.securityLevel)
                || live.discoverable!=entry.discoverable) {unavailable++;continue;}
            if (saved==null) {saved=entry;restored++;}
            else {already++;}
        }
        if (already+restored>0) counter=Math.max(counter,backupCounter);
        return new int[]{restored,already,unavailable};
    }
    static String encode(byte[] data) { return Base64.getEncoder().encodeToString(data); }
    static boolean validAlias(String alias) {
        if (alias==null || !alias.startsWith("ctap3b-")) return false;
        try {
            return UUID.fromString(alias.substring(7)).toString().equals(alias.substring(7));
        } catch(IllegalArgumentException ex) {return false;}
    }
}
'''

HARNESS = r'''
package org.pocof7.ctap3b;
import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
final class BackupCodecHostTest {
    private static void ok(boolean value, String msg) {
        if(!value) throw new AssertionError(msg);
    }
    private static char[] pass() {return "safe password at least 12 chars!".toCharArray();}
    private static void zero(char[] c) {
        for(char item:c) ok(item=='\0',"password char[] not consumed");
    }
    private static void reject(CryptoKeyManager destination,byte[] blob,char[] password) {
        try {
            BackupManager.restoreEncrypted(destination,blob,password);
            throw new AssertionError("invalid catalog was accepted");
        } catch (AssertionError invalid) {
            throw invalid;
        } catch (Exception expected) {
            zero(password);
        }
    }
    private static byte[] plaintext(int count,boolean duplicate,boolean trailing)
            throws IOException {
        ByteArrayOutputStream output=new ByteArrayOutputStream();
        DataOutputStream data=new DataOutputStream(output);
        data.write("CTAPCAT4".getBytes(StandardCharsets.US_ASCII));
        data.writeInt(2);data.writeShort(count);
        byte[] alias="ctap3b-12345678-1234-1234-1234-123456789abc"
            .getBytes(StandardCharsets.US_ASCII);
        for(int i=0;i<Math.min(count,2);i++) {
            byte[] id=new byte[32];
            id[0]=(byte)(duplicate?1:i+1);
            data.write(id);data.writeByte(9);data.write("localhost".getBytes(StandardCharsets.US_ASCII));
            data.writeByte(alias.length);data.write(alias);
            data.writeByte(1);data.writeByte(7);data.writeByte(0);data.writeByte(2);
            data.write(new byte[32]);data.write(new byte[32]);
            data.writeByte(0);data.writeByte(0);data.writeLong(0);
        }
        if (trailing) data.writeByte(99);
        data.flush();
        return output.toByteArray();
    }
    private static void invalidPlain(byte[] plain) throws Exception {
        Method method=BackupManager.class.getDeclaredMethod("decodeCatalog",byte[].class);
        method.setAccessible(true);
        try {
            method.invoke(null,(Object)plain);
            throw new AssertionError("malformed plaintext was accepted");
        } catch (InvocationTargetException expected) {
            ok(expected.getCause() instanceof IllegalArgumentException,
                "wrong strict parser failure");
        }
    }
    /** Real v1/v2/v3 authenticated on-disk layout, generated independently of
     * the new v4 production serializer to detect migration regressions. */
    private static byte[] olderBlob(int version,byte[] id,String rpId,String alias,
                                    byte[] user,byte[] x,byte[] y)
            throws Exception {
        ByteArrayOutputStream plaintext=new ByteArrayOutputStream();
        DataOutputStream catalog=new DataOutputStream(plaintext);
        catalog.write((version==1?"CTAPCAT1":version==2?"CTAPCAT2":"CTAPCAT3")
            .getBytes(StandardCharsets.US_ASCII));
        catalog.writeInt(45); catalog.writeShort(1);
        catalog.write(id);
        if(version>=2) {
            catalog.writeByte(rpId.length());
            catalog.write(rpId.getBytes(StandardCharsets.US_ASCII));
        }
        catalog.writeByte(alias.length());
        catalog.write(alias.getBytes(StandardCharsets.US_ASCII));
        catalog.writeByte(user.length);catalog.write(user);
        if(version>=3) catalog.writeByte(1); // original v3 discoverability
        catalog.writeByte(2);catalog.write(x);catalog.write(y);
        byte[] salt=new byte[16],nonce=new byte[12];
        new java.security.SecureRandom().nextBytes(salt);
        new java.security.SecureRandom().nextBytes(nonce);
        byte[] header=new byte[45];
        java.nio.ByteBuffer h=java.nio.ByteBuffer.wrap(header);
        h.put((version==1?"CTAP3BM1":version==2?"CTAP3BM2":"CTAP3BM3")
            .getBytes(StandardCharsets.US_ASCII));
        h.put((byte)version); h.putInt(240000); h.put(salt);h.put(nonce);
        h.putInt(plaintext.size()+16);
        PBEKeySpec spec=new PBEKeySpec(pass(),salt,240000,256);
        byte[] key;
        try {key=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec).getEncoded();} finally {spec.clearPassword();}
        Cipher aes=Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
        aes.updateAAD(header);
        byte[] cipher=aes.doFinal(plaintext.toByteArray());
        ByteArrayOutputStream archive=new ByteArrayOutputStream();
        archive.write(header);archive.write(cipher);
        Arrays.fill(key,(byte)0);
        return archive.toByteArray();
    }
    public static void main(String[] args) throws Exception {
        byte[] id=new byte[32],x=new byte[32],y=new byte[32];
        id[0]=1;x[0]=2;y[0]=3;
        String alias="ctap3b-12345678-1234-1234-1234-123456789abc";
        CryptoKeyManager.BackupEntry entry=new CryptoKeyManager.BackupEntry(
            id,"localhost",alias,new byte[]{6,7},x,y,"STRONGBOX");
        CryptoKeyManager source=new CryptoKeyManager(entry);
        char[] password=pass();
        byte[] encrypted=BackupManager.exportEncrypted(source,password);
        zero(password);
        ok(new String(encrypted,0,8,StandardCharsets.US_ASCII).equals("CTAP3BM4"),
            "4.6 account-metadata archives must be versioned v4");
        ok(encrypted.length < 131072 && encrypted.length>60,"bounded format");
        ok(!new String(encrypted,StandardCharsets.ISO_8859_1).contains(alias),
            "plaintext alias leaked");
        byte[] second=BackupManager.exportEncrypted(source,pass());
        ok(!Arrays.equals(encrypted,second),"salt/nonce reused");

        CryptoKeyManager samePhone=new CryptoKeyManager(entry);
        BackupManager.RestoreResult result=BackupManager.restoreEncrypted(
            samePhone,encrypted,pass());
        ok(result.restored==1 && result.alreadyPresent==0 && result.unavailable==0,
            "same-device restore");
        ok(!samePhone.saved.discoverable,"legacy credential unexpectedly made discoverable");
        CryptoKeyManager.BackupEntry resident=new CryptoKeyManager.BackupEntry(
            id,"example.com",alias,new byte[]{6,7},x,y,"STRONGBOX",true);
        CryptoKeyManager residentSource=new CryptoKeyManager(resident);
        byte[] residentBlob=BackupManager.exportEncrypted(residentSource,pass());
        CryptoKeyManager residentPhone=new CryptoKeyManager(resident);
        BackupManager.RestoreResult residentResult=BackupManager.restoreEncrypted(
            residentPhone,residentBlob,pass());
        ok(residentResult.restored==1 && residentPhone.saved.discoverable,
            "discoverability flag lost during authenticated backup");
        CryptoKeyManager.BackupEntry named=new CryptoKeyManager.BackupEntry(
            id,"github.com",alias,new byte[]{6,7},x,y,"STRONGBOX",true,
            "alice@example.com","Alice",1750000000000L);
        CryptoKeyManager namedPhone=new CryptoKeyManager(named);
        BackupManager.RestoreResult namedResult=BackupManager.restoreEncrypted(
            namedPhone,BackupManager.exportEncrypted(new CryptoKeyManager(named),pass()),pass());
        ok(namedResult.restored==1 && namedPhone.saved.discoverable
            && "alice@example.com".equals(namedPhone.saved.userName)
            && "Alice".equals(namedPhone.saved.displayName)
            && namedPhone.saved.createdAtMillis==1750000000000L,
            "encrypted account label/date metadata lost in v4 archive");
        ok(samePhone.counter==42,"counter was not advanced to backup max");
        CryptoKeyManager originalPhone=new CryptoKeyManager(entry);
        BackupManager.RestoreResult legacy=BackupManager.restoreEncrypted(originalPhone,
            olderBlob(1,id,"localhost",alias,new byte[]{6,7},x,y),pass());
        ok(legacy.restored==1 && originalPhone.counter==45,
            "legacy v1 localhost metadata archive was not preserved");
        CryptoKeyManager.BackupEntry secondSite=new CryptoKeyManager.BackupEntry(
            id,"webauthn.io",alias,new byte[]{6,7},x,y,"STRONGBOX");
        CryptoKeyManager priorSitePhone=new CryptoKeyManager(secondSite);
        BackupManager.RestoreResult v2=BackupManager.restoreEncrypted(priorSitePhone,
            olderBlob(2,id,"webauthn.io",alias,new byte[]{6,7},x,y),pass());
        ok(v2.restored==1 && !priorSitePhone.saved.discoverable,
            "v2 real-site archives must import as non-discoverable");
        CryptoKeyManager residentV3Phone=new CryptoKeyManager(resident);
        BackupManager.RestoreResult v3=BackupManager.restoreEncrypted(residentV3Phone,
            olderBlob(3,id,"example.com",alias,new byte[]{6,7},x,y),pass());
        ok(v3.restored==1 && residentV3Phone.saved.discoverable
            && residentV3Phone.saved.userName==null
            && residentV3Phone.saved.createdAtMillis==0L,
            "4.5 v3 discoverable archives must remain importable without fake account metadata");
        samePhone.counter=100;
        result=BackupManager.restoreEncrypted(samePhone,encrypted,pass());
        ok(result.restored==0 && result.alreadyPresent==1,"idempotent restore");
        ok(samePhone.counter==100,"signature counter regressed");

        reject(samePhone,encrypted,"wrong password!".toCharArray());
        for(int index:new int[]{0,8,10,14,29,42,encrypted.length-1}) {
            byte[] corrupt=encrypted.clone();corrupt[index]^=1;
            reject(samePhone,corrupt,pass());
        }
        byte[] truncated=Arrays.copyOf(encrypted,encrypted.length-1);
        reject(samePhone,truncated,pass());
        byte[] appended=Arrays.copyOf(encrypted,encrypted.length+1);
        reject(samePhone,appended,pass());
        CryptoKeyManager otherPhone=new CryptoKeyManager(null);
        char[] emptyBackupPass=pass();
        try {
            BackupManager.exportEncrypted(otherPhone,emptyBackupPass);
            throw new AssertionError("empty backup allowed");
        } catch (IllegalStateException expected) {
            // Do not present a zero-credential catalog as a successful backup.
            zero(emptyBackupPass);
        }
        result=BackupManager.restoreEncrypted(otherPhone,encrypted,pass());
        ok(result.unavailable==1 && result.restored==0 && otherPhone.counter==12,
            "new phone cannot relink a nonexportable key");
        CryptoKeyManager.BackupEntry changed=new CryptoKeyManager.BackupEntry(
            id,"localhost",alias,new byte[]{6,7},new byte[32],y,"STRONGBOX");
        CryptoKeyManager.BackupEntry otherRp=new CryptoKeyManager.BackupEntry(
            id,"example.com",alias,new byte[]{6,7},x,y,"STRONGBOX");
        CryptoKeyManager wrongRp=new CryptoKeyManager(otherRp);
        result=BackupManager.restoreEncrypted(wrongRp,encrypted,pass());
        ok(result.unavailable==1 && result.restored==0,
            "wrong RP must not recover existing alias/credential mapping");
        CryptoKeyManager mismatched=new CryptoKeyManager(changed);
        result=BackupManager.restoreEncrypted(mismatched,encrypted,pass());
        ok(result.unavailable==1 && result.restored==0,
            "public-point mismatch did not fail closed");
        invalidPlain(plaintext(2,true,false));  // duplicate ID and alias
        invalidPlain(plaintext(257,false,false)); // bounded record count
        invalidPlain(plaintext(1,false,true));  // trailing bytes
        invalidPlain(Arrays.copyOf(plaintext(1,false,false),20)); // truncation
        byte[] invalidFlag=plaintext(1,false,false);
        invalidFlag[8+4+2+32+1+9+1+43+1+1]=2;
        invalidPlain(invalidFlag); // malformed discoverability bit
        byte[] invalidLabelSize=plaintext(1,false,false);
        invalidLabelSize[8+4+2+32+1+9+1+43+1+1+1+1+32+32]=(byte)129;
        invalidPlain(invalidLabelSize); // account metadata length exceeds 128
        byte[] invalidDate=plaintext(1,false,false);
        java.nio.ByteBuffer.wrap(invalidDate).putLong(invalidDate.length-8,-1L);
        invalidPlain(invalidDate); // negative creation timestamp
        try {
            char[] weak="tiny".toCharArray();
            BackupManager.exportEncrypted(source,weak);
            throw new AssertionError("weak passphrase allowed");
        } catch (IllegalArgumentException expected) {
            // The caller-supplied buffer is cleared on success AND failure.
        }
        System.out.println("PASS: AES-GCM metadata codec roundtrip, nonce, passphrase wipe, "+
            "wrong password, version/length/tamper, hardware-alias and public-point "+
            "nonportability, counter monotonicity, duplicate/bounds/trailing/truncation");
    }
}
'''


class BackupCodecHostTests(unittest.TestCase):
    def test_production_java_codec_with_host_only_test_double(self):
        javac = str(JDK / "javac") if (JDK / "javac").exists() else shutil.which("javac")
        java = str(JDK / "java") if (JDK / "java").exists() else shutil.which("java")
        if not javac or not java:
            self.skipTest("host-only Java 17 unavailable")
        with tempfile.TemporaryDirectory(prefix="ctap-backup-host-") as folder:
            root = Path(folder)
            package = root / "org/pocof7/ctap3b"
            package.mkdir(parents=True)
            (package / "BackupManager.java").write_bytes(BACKUP.read_bytes())
            (package / "RelyingPartyPolicy.java").write_bytes(RP_POLICY.read_bytes())
            (package / "CryptoKeyManager.java").write_text(STUB)
            (package / "BackupCodecHostTest.java").write_text(HARNESS)
            command = subprocess.run(
                [javac, "-d", str(root), *(str(p) for p in package.glob("*.java"))],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(command.returncode, 0, command.stderr)
            command = subprocess.run(
                [java, "-cp", str(root), "org.pocof7.ctap3b.BackupCodecHostTest"],
                capture_output=True, text=True, timeout=40, check=False,
            )
            self.assertEqual(command.returncode, 0, command.stderr + command.stdout)
            self.assertIn("PASS: AES-GCM metadata codec", command.stdout)

    def test_android_keystore_policy_and_restore_are_fail_closed_by_inspection(self):
        source = CRYPTO.read_text()
        codec = BACKUP.read_text()
        for invariant in (
            "KeyStore.getInstance(\"AndroidKeyStore\")",
            "requireHardwareAndPerUseAuth(privateKey)",
            "if (live == null || !live.level.equals(entry.securityLevel)",
            "!Arrays.equals(live.x, entry.publicX)",
            "!Arrays.equals(live.y, entry.publicY)",
            "if (backupCounter > existing)",
            "if (storedRecord == null && existingAliases.contains(entry.alias))",
            "if (!edit.commit())",
        ):
            self.assertIn(invariant, source)
        for forbidden in ("getPrivateKey().getEncoded()", "KeyPairGenerator", "generateKeyPair",
                          "getPrivateKey()", "INTERNET", "GoogleAuth"):
            self.assertNotIn(forbidden, codec)
        # PBKDF2 SecretKey.getEncoded() is necessary to obtain the temporary
        # password-derived AES key. AndroidKeyStore private keys are untouched.
        self.assertIn("generateSecret(spec).getEncoded()", codec)
        self.assertIn("PBKDF2WithHmacSHA256", codec)
        self.assertIn("AES/GCM/NoPadding", codec)
        self.assertIn("cipher.updateAAD(blob, 0, HEADER_LENGTH)", codec)
        self.assertIn("Arrays.fill(password, '\\0')", codec)


if __name__ == "__main__":
    unittest.main()
