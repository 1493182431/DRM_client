import java.io.File;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * @description: RSA数字签名工具类
 * @author：Favor
 * @date: 2024/5/31
 */
public class SignatureUtil {
    /**
     * 验证签名
     *
     * @param src
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean rsaVerify(String src) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        File keyFile = new File(SerializeUtil.TARGET_PATH + File.separator + "PublicKey");
        if (!keyFile.exists()) {
            throw new RuntimeException("PublicKey文件不存在: " + keyFile.getAbsolutePath());
        }
        File snFile = new File(SerializeUtil.TARGET_PATH + File.separator + "SN");
        if (!snFile.exists()) {
            throw new RuntimeException("SN文件不存在: " + snFile.getAbsolutePath());
        }
        RSAPublicKey rsaPublicKey = SerializeUtil.deserializeObjectFromFile(String.valueOf(keyFile));
        String sn = SerializeUtil.deserializeObjectFromFile(String.valueOf(snFile));
        byte[] result = hexStringToByteArray(sn);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(src.getBytes());
        boolean bool = signature.verify(result);
        if (bool) {
            System.out.println("序列号认证通过");
        } else {
            System.out.println("序列号认证未通过");
        }
        return bool;
    }

    /**
     * 将十六进制字符串转换为字节数组
     *
     * @param hexString
     * @return
     */
    public static byte[] hexStringToByteArray(String hexString) {
        if (hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("序列号长度错误，请检查！");
        }
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            String hex = hexString.substring(i, i + 2);
            bytes[i / 2] = (byte) Integer.parseInt(hex, 16);
        }

        return bytes;
    }
}
