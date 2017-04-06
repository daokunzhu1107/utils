package com.dk.encrypt;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

/**
 * Created by DK on 17/3/20 15:50.
 * doc:
 */
public class AESUtil {
    private static final Logger logger = LoggerFactory.getLogger(AESUtil.class);
    private static final String defaultCharset = "UTF-8";
    private static final String KEY_AES = "AES";
    private static final String KEY_MD5 = "MD5";

    /**
     * 加密
     *
     * @param data 需要加密的内容
     * @param key  加密密码
     * @return
     */
    public static String encrypt(String data, String key) {
        return doAES(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     *
     * @param data 待解密内容
     * @param key  解密密钥
     * @return
     */
    public static String decrypt(String data, String key) {
        return doAES(data, key, Cipher.DECRYPT_MODE);
    }

    /**
     * 加解密
     *
     * @param data
     * @param key
     * @param mode
     * @return
     */
    private static String doAES(String data, String key, int mode) {
        try {
            if (StringUtils.isBlank(data) || StringUtils.isBlank(key)) {
                return null;
            }
            boolean encrypt = mode == Cipher.ENCRYPT_MODE;
            byte[] content;
            if (encrypt) {
                content = data.getBytes(defaultCharset);
            } else {
                content = Base64.decodeBase64(data);
            }
            // MessageDigest.getInstance(KEY_MD5)获取的实例非线程安全，每次加密需重新获取
            SecretKeySpec keySpec = new SecretKeySpec(MessageDigest.getInstance(KEY_MD5).digest(key.getBytes(defaultCharset)), KEY_AES);
            Cipher cipher = Cipher.getInstance(KEY_AES);// 创建密码器
            cipher.init(mode, keySpec);// 初始化
            byte[] result = cipher.doFinal(content);
            if (encrypt) {
                return Base64.encodeBase64String(result);
            } else {
                return new String(result, defaultCharset);
            }
        } catch (Exception e) {
            logger.error("AES密文处理异常", e);
        }
        return null;
    }
}
