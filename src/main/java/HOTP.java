import org.apache.commons.codec.binary.Base64;
import sun.security.krb5.internal.PAData;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.regex.Pattern;

/**
 * Created by rc452 on 2017/2/28.
 */
public class HOTP {
    public enum MacAlgorithmEnum {
        MD5("HmacMD5"),
        SHA1("HmacSHA1"),
        SHA256("HmacSHA256"),
        SHA384("HmacSHA256"),
        SHA512("HmacSHA512");
        private String name;

        private MacAlgorithmEnum(String name) {
            this.name = name;
        }

        public String getName() {
            return this.name;
        }

    }

    public enum BitEnum {
        FOUR(4, "%04d"),
        FIVE(5, "%05d"),
        SIX(6, "%06d"),
        SEVEN(7, "%07d"),
        EIGHT(8, "%08d");
        private String ftm;
        private int length;

        private BitEnum(int lenght, String ftm) {
            this.ftm = ftm;
            this.length = lenght;
        }

        public String getFtm() {
            return this.ftm;
        }

        public int getLength() {
            return this.length;
        }
    }

    private String key = "MBNWWOXPX6667P55LHX37PLI56733357XXL2" +
            "J357XXX37PJG56733UUPPTX37PLB56732GK6ALX37" +
            "PPPX66RP357XXX37PLW56733357XXX37PJ6K3X37P" +
            "JDJVJO7P55FLX37PPPX6667P55FRVC6GQWCXX37PL" +
            "656732Z7PX66QR357XXX37PIT56732OQ";

    private int clock = 30;

    public static final long UID = 10203405609l;

    public HOTP(String key) {
        this.key = key;
    }
    public HOTP(String key,int clock){
        this.key = key;
        this.clock = clock;
    }
    /**
     *  return 60bit HmacSHA1 key
     */
    public static byte[] generatorKeyBytes() throws NoSuchAlgorithmException {
        // 初始化HmacSHA1摘要算法的密钥产生器
        KeyGenerator generator = KeyGenerator.getInstance("HmacSHA1");
        // 产生密钥
        SecretKey secretKey = generator.generateKey();
        // 获得密钥
        byte[] key = secretKey.getEncoded();
        return key;
    }

    /**
     * return key with Base64
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String generatorKeyString() throws NoSuchAlgorithmException {
        return Base64.encodeBase64String(generatorKeyBytes());
    }

    public byte[] get8BitBytes(long data) {
        byte[] result = new byte[8];
        int[] shift = {56, 48, 40, 32, 24, 16, 8, 0};
        long mask = 0xFF;
        for (int i = 0; i < 8; i++) {
            result[i] = (byte) ((data >> shift[i]) & mask);
        }
        return result;
    }

    /**
     * HmacSHA1摘要算法
     * 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
     */
    public byte[] encodeHmacSHA(byte[] data, byte[] key) throws Exception {
        // 还原密钥
        SecretKey secretKey = new SecretKeySpec(key, MacAlgorithmEnum.SHA1.getName());
        // 实例化Mac
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        //初始化mac
        mac.init(secretKey);
        //执行消息摘要
        byte[] digest = mac.doFinal(data);
        return digest;
    }

    /*
    生成密码
     */
    public String next() throws Exception {
        long date = new Date().getTime() / (clock * 1000);
        // System.out.println(String.valueOf(date));
        // byte[] data = get8BitBytes(date);
        // TODO int类型HmacSHA1在Java 和 CryptoJs里加密后表现不一致
        byte[] sha1 = encodeHmacSHA(String.valueOf(date).getBytes(), this.key.getBytes());
        // System.out.println(Base64.encodeBase64String(sha1));
        byte[] dt = dynamicTruncation(sha1);
        int snum = bytesToInt(dt);
        snum = digist(BitEnum.FOUR, snum);
        // System.out.println(snum);
        return generatorPayCode(fmt(BitEnum.FOUR, snum));
    }

    // -- |--------|-----------|-------
    // 28 |  x     |  y        |  z
    // -- |--------|-----------|-------
    // AI  4 digits  8 digits   4 digits  => 18 digits
    public String generatorPayCode(String otp) {
        final int factor = 5;
        int x = Integer.valueOf(otp);
        int y = (int) (UID / x + factor * x);
        int z = (int) (UID % x);
        return String.format("28%04d%08d%04d", x, y, z);
    }

    public String verify(String code){
//        String regEx = "28([0-9]{4})([0-9]{8})([0-9]{4})";
//        Pattern pattern = Pattern.compile(regEx);
//        int x = Integer.valueOf(pattern.matcher(code).group(1));
//        int y = Integer.valueOf(pattern.matcher(code).group(2));
//        int z = Integer.valueOf(pattern.matcher(code).group(3));
        final int factor = 5;
        int x = Integer.valueOf(code.substring(2,6));
        int y = Integer.valueOf(code.substring(6,14));
        int z = Integer.valueOf(code.substring(14,18));
        long result = (long)(y - (factor *x)) *  x;
        result += z;
        return String.valueOf(result);
    }

    public String fmt(BitEnum bit, int snum) {
        return rightPadding(bit, snum);
    }

    public byte[] dynamicTruncation(byte[] arg) {
        int offset = arg[19] & 0xF;
        byte[] P = {arg[offset], arg[offset + 1], arg[offset + 2], arg[offset + 3]};
        return P;
    }

    public int digist(BitEnum bit, int num) {
        return (int) (num % Math.pow(10, bit.getLength()));
    }

    public int bytesToInt(byte[] arg) {
        assert arg.length == 4 : "byte array lenght must be 4!";
        // TODO java 2's complement has sign so we extend a large type to fix sign
        return (int) (((short)(arg[0] & 0x7F) << 24)
                | ((short)(arg[1] & 0xFF) << 16)
                | ((short)(arg[2] & 0xFF) << 8)
                | ((short)(arg[3] & 0xFF) << 0));
    }

    public String leftPadding(BitEnum bit, int otp) {
        return String.format(bit.getFtm(), otp);
    }

    public String rightPadding(BitEnum bit,int otp){
        int result = otp;
        while(result < Math.pow(10,BitEnum.FOUR.getLength()-1)){
            result *= 10;
        }
        return String.valueOf(result);
    }
}
