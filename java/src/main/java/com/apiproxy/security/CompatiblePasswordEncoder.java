package com.apiproxy.security;

import org.bouncycastle.crypto.generators.SCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 兼容 Python 现有密码哈希格式的 PasswordEncoder。
 *
 * Python apikey.py 的 hash_password() 优先用 Scrypt ($scrypt$ 格式)，
 * 同时 verify_password() 兼容 bcrypt ($2b$/$2a$/$2y$) 和 Werkzeug pbkdf2。
 * Java 版必须能验证数据库中已有的全部格式，否则历史用户无法登录。
 *
 * - encode():  新密码用 BCrypt(rounds=12)，与 Python bcrypt.checkpw 互通
 * - matches(): $scrypt$ → BouncyCastle SCrypt；$2 → BCrypt；pbkdf2: → JDK PBKDF2
 *
 * 参数对齐 Python apikey.py：
 *   SCRYPT_N=2^17, R=8, P=1, LEN=64，salt=32 字节随机
 */
@Component
public class CompatiblePasswordEncoder implements PasswordEncoder {

    private static final int SCRYPT_N = 1 << 17;  // 131072
    private static final int SCRYPT_R = 8;
    private static final int SCRYPT_P = 1;
    private static final int SCRYPT_LEN = 64;

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);

    @Override
    public String encode(CharSequence rawPassword) {
        return bcrypt.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String storedHash) {
        if (storedHash == null || storedHash.isEmpty()) {
            return rawPassword == null || rawPassword.length() == 0;
        }
        String password = rawPassword == null ? "" : rawPassword.toString();

        // 1. Scrypt ($scrypt$base64_salt$base64_hash)
        if (storedHash.startsWith("$scrypt$")) {
            return verifyScrypt(password, storedHash);
        }
        // 2. bcrypt ($2b$/$2a$/$2y$)
        if (storedHash.startsWith("$2")) {
            return verifyBcrypt(password, storedHash);
        }
        // 3. Werkzeug pbkdf2 (pbkdf2:sha256$...)
        if (storedHash.startsWith("pbkdf2:")) {
            return verifyPbkdf2(password, storedHash);
        }
        // 未知格式一律拒绝（不降级到明文）
        return false;
    }

    private boolean verifyScrypt(String password, String storedHash) {
        try {
            String[] parts = storedHash.split("\\$");
            if (parts.length != 4) return false;
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] storedKey = Base64.getDecoder().decode(parts[3]);
            byte[] derived = SCrypt.generate(
                    password.getBytes(StandardCharsets.UTF_8),
                    salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_LEN);
            return MessageDigest.isEqual(derived, storedKey);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean verifyBcrypt(String password, String storedHash) {
        try {
            byte[] pwdBytes = password.getBytes(StandardCharsets.UTF_8);
            // bcrypt 限制 72 字节，超长密码先做 sha256（对齐 Python verify_password）
            if (pwdBytes.length > 72) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                pwdBytes = md.digest(pwdBytes);
            }
            return bcrypt.matches(new String(pwdBytes, StandardCharsets.ISO_8859_1), storedHash);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 验证 Werkzeug pbkdf2:sha256$iterations$salt$hash 格式。
     * 示例：pbkdf2:sha256:600000$xxxx$yyyy
     */
    private boolean verifyPbkdf2(String password, String storedHash) {
        try {
            // Werkzeug 格式：pbkdf2:sha256:<iterations>$<salt>$<hash>
            String body = storedHash.substring("pbkdf2:".length());
            String[] headerSplit = body.split("\\$", 2);
            if (headerSplit.length != 2) return false;
            String algoIter = headerSplit[0];  // sha256:600000 或 sha256
            String saltHash = headerSplit[1];
            String[] sh = saltHash.split("\\$", 2);
            if (sh.length != 2) return false;
            String salt = sh[0];
            String hashB64 = sh[1];

            int iterations = 600000;  // Werkzeug 默认
            String algorithm = "sha256";
            if (algoIter.contains(":")) {
                String[] ai = algoIter.split(":");
                algorithm = ai[0];
                iterations = Integer.parseInt(ai[1]);
            }

            String pbkdf2Algo = "PBKDF2With" + Character.toUpperCase(algorithm.charAt(0)) + algorithm.substring(1);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(pbkdf2Algo);
            PBEKeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt.getBytes(StandardCharsets.UTF_8),
                    iterations,
                    256);  // sha256 = 256 bits
            byte[] derived = skf.generateSecret(spec).getEncoded();
            byte[] stored = Base64.getDecoder().decode(hashB64);
            return MessageDigest.isEqual(derived, stored);
        } catch (Exception e) {
            return false;
        }
    }
}
