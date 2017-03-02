import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

/**
 * Created by rc452 on 2017/2/28.
 */
public class HOTP {
    public enum MacAlgorithm {
        MD5("HmacMD5"),
        SHA1("HmacSHA1"),
        SHA256("HmacSHA256"),
        SHA384("HmacSHA256"),
        SHA512("HmacSHA512");
        private String name;

        private MacAlgorithm(String name) {
            this.name = name;
        }

        public String getName() {
            return this.name;
        }

    }
    public enum Bit{
        FOUR(4,"%04d"),
        FIVE(5,"%05d"),
        SIX(6,"%06d"),
        SEVEN(7,"%07d"),
        EIGHT(8,"%08d");
        private String ftm;
        private int length;
        private Bit(int lenght,String ftm){
            this.ftm = ftm;
            this.length = lenght;
        }
        public String getFtm(){
            return this.ftm;
        }

        public int getLength(){
            return this.length;
        }
    }

    private String key;
    public static final long UID = 10203405609l;

    /**
     * 产生HmacSHA1摘要算法的密钥
     */
    public static byte[] initHmacSHAKey() throws NoSuchAlgorithmException {
        // 初始化HmacMD5摘要算法的密钥产生器
        KeyGenerator generator = KeyGenerator.getInstance("HmacSHA1");
        // 产生密钥
        SecretKey secretKey = generator.generateKey();
        // 获得密钥
        byte[] key = secretKey.getEncoded();
        return key;
    }

    public static byte[] get8BitBytes(long data) {
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
    public static byte[] EncodeHmacSHA(byte[] data, byte[] key) throws Exception {
        // 还原密钥
        SecretKey secretKey = new SecretKeySpec(key, MacAlgorithm.SHA1.getName());
        // 实例化Mac
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        //初始化mac
        mac.init(secretKey);
        //执行消息摘要
        byte[] digest = mac.doFinal(data);
        return digest;
    }



    public static void HMac() throws Exception {
//        byte[] key = initHmacSHAKey();
        String key = "MBNWWOXPX6667P55LHX37PLI56733357XXL2" +
                "J357XXX37PJG56733UUPPTX37PLB56732GK6ALX37" +
                "PPPX66RP357XXX37PLW56733357XXX37PJ6K3X37P" +
                "JDJVJO7P55FLX37PPPX6667P55FRVC6GQWCXX37PL" +
                "656732Z7PX66QR357XXX37PIT56732OQ";
        for (int i = 0; i < 10; i++) {
            long date = new Date().getTime() / (5 * 1000);
            byte[] data = get8BitBytes(date);
            byte[] sha1 = EncodeHmacSHA(data, Base32.getInstance().decodeInternal(key));
//            System.out.println(new String(sha1));
            int snum = BytesToInt(DynamicTruncation(sha1));
            System.out.println(ProceePayCode(fmt(Bit.FOUR,snum)));
            Thread.sleep(1000);
        }
    }

    // -- |--------|-----------|-------
    // 28 |  x     |  y        |  z
    // -- |--------|-----------|-------
    // AI  4 digits  9 digits   3 digits  => 18 digits
    public static String ProceePayCode(String otp){
        final int factor = 5;
        int x = Integer.valueOf(otp);
        int y = (int) (UID/x+factor*x);
        int z = (int) (UID % x);
        return String.format("28%04d%09d%03d",x,y,z);
    }
    public static String fmt(Bit bit,int snum){
        return leftPadding(bit,Digist(bit,snum));
    }
    public static byte[] DynamicTruncation(byte[] arg) {
        int offset = arg[19] & 0xF;
        byte[] P = {arg[offset], arg[offset + 1], arg[offset + 2], arg[offset + 3]};
        return P;
    }
    public static int Digist(Bit bit,int num){
        return (int) (num % Math.pow(10, bit.getLength()));
    }
    public static int BytesToInt(byte[] arg) {
        assert arg.length == 4 : "byte array lenght must be 4!";
        return (int) ((arg[0] & 0x7F<<24)
                | ((arg[1] & 0xFF) << 16)
                | ((arg[2] & 0xFF) << 8)
                | ((arg[3] & 0xFF) << 0));
    }
    public static String leftPadding(Bit bit,int otp){
        return String.format(bit.getFtm(), otp);
    }
    public static void main(String[] args) throws Exception {
        HMac();
    }

}
