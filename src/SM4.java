import java.math.*;
import java.io.*;
import java.util.Objects;

public class SM4 {
    public static void main (String[] args) throws IOException {
        System.out.println("P: 00112233445566778899aabbccddeeff");
        System.out.println("Key: 0123456789abcdeffedcba9876543210");
        System.out.println(SM4("00112233445566778899aabbccddeeff", "0123456789abcdeffedcba9876543210", 0));
        System.out.println("P: 2233445566778899aabbccddeeff0011");
        System.out.println("Key: 456789abcdeffedcba98765432100123");
        System.out.println(SM4("2233445566778899aabbccddeeff0011", "456789abcdeffedcba98765432100123", 0));
        System.out.println("C: 58ab414d84fb3008b0bee987f97021e6");
        System.out.println("Key: 456789abcdeffedcba98765432100123");
        System.out.println(SM4("58ab414d84fb3008b0bee987f97021e6", "456789abcdeffedcba98765432100123", 1));
        System.out.println("C: 09325c4853832dcb9337a5984f671b9a");
        System.out.println("Key: 0123456789abcdeffedcba9876543210");
        System.out.println(SM4("09325c4853832dcb9337a5984f671b9a", "0123456789abcdeffedcba9876543210", 1));

        ECB("input.txt", "ECBoutput.txt", "0123456789abcdeffedcba9876543210", 0);
        CBC("input.txt", "CBCoutput.txt", "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", 0);
        CTR("input.txt", "CTRoutput.txt", "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210");
        OFB("input.txt", "OFBoutput.txt", "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210");
        CFB("input.txt", "CFBoutput.txt", "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", 0);
    }

    //以下函数实现SM4的ECB工作模式
    public static void ECB (String inputName, String outputName, String key, int flag) throws IOException {
        File inputFile = new File(inputName);
        Reader reader = null;
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputName, true), "UTF-8"));
        try {
            String block = "";
            reader = new InputStreamReader(new FileInputStream(inputFile));
            int tem;
            while ((tem = reader.read()) != -1) {
                if (block.length() == 32) {
                    bw.write(SM4(block, key, flag));
                    block = "";
                }
                block += (char)tem;
            }
            if (block.length() == 32) {
                if (flag == 0) {
                    //此时除了加密这一块之外，还需要额外填充一个块，全部为块长度
                    bw.write(SM4(block, key, flag));
                    bw.write(SM4("10101010101010101010101010101010", key, flag));
                }
                else {
                    //解密时需要把加密时填充的部分去掉
                    String str = SM4(block, key, flag);
                    if (Integer.parseInt(str.substring(30), 16) != 16)
                        bw.write(str.substring(0, (16-Integer.parseInt(str.substring(30), 16)) * 2));
                }

            }
            else {//如果最后一块长度不完整，则肯定是加密模式
                //此时需要填充
                int pad = (32 - block.length()) / 2;
                String padding = "0" + Integer.toString(pad, 16);
                while (block.length() < 32)
                    block += padding;
                bw.write(SM4(block, key, flag));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        bw.close();
        reader.close();
        //最后一定要关闭文件操作，否则不能得到输出
    }

    //以下函数实现SM4的CBC工作模式
    public static void CBC (String inputName, String outputName, String key, String IV, int flag) throws IOException{
        File inputFile = new File(inputName);
        Reader reader = null;
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputName, true), "UTF-8"));
        try {
            String block = "";
            reader = new InputStreamReader(new FileInputStream(inputFile));
            int tem;
            String temC = IV;//temC用来存储上一组密文用于异或，初始值设定为IV

            while ((tem = reader.read()) != -1) {
                if (block.length() == 32) {
                    if (flag == 0) {
                        temC = SM4(XOR(block, temC), key, flag);
                        bw.write(temC);
                    }
                    else {
                        bw.write((XOR(temC, SM4(block, key, flag))));
                        temC = block;
                    }
                    block = "";
                }
                block += (char)tem;
            }

            if (block.length() == 32) {
                if (flag == 0) {
                    temC = SM4(XOR(block, temC), key, flag);
                    bw.write(temC);
                    bw.write(SM4(XOR(temC, "10101010101010101010101010101010"), key, flag));
                }
                else {
                    String str = XOR(SM4(block, key, flag), temC);
                    if (Integer.parseInt(str.substring(30), 16) != 16)
                        bw.write(str.substring(0, (16-Integer.parseInt(str.substring(30), 16)) * 2));
                }
            }
            else {//此时需要填充
                int pad = (32 - block.length()) / 2;
                String padding = "0" + Integer.toString(pad, 16);
                while (block.length() < 32)
                    block += padding;
                bw.write(SM4(XOR(block, temC), key, flag));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        bw.close();
        reader.close();
    }

    //以下函数实现SM4的CTR工作模式
    public static void CTR (String inputName, String outputName, String key, String IV) throws IOException{
        File inputFile = new File(inputName);
        Reader reader = null;
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputName, true), "UTF-8"));
        try {
            String block = "";
            reader = new InputStreamReader(new FileInputStream(inputFile));
            int tem;

            while ((tem = reader.read()) != -1) {
                if (block.length() == 32) {
                    bw.write(XOR(SM4(IV, key, 0), block));
                    IV = ADD(IV);
                    block = "";
                }
                block += (char)tem;
            }
            //CTR不需要考虑填充的问题，而且只需要加密函数即可
            bw.write(XOR(block, SM4(IV, key, 0).substring(0, block.length())));
        } catch (Exception e) {
            e.printStackTrace();
        }
        bw.close();
        reader.close();
    }

    //以下函数实现SM4加密算法的OFB工作模式
    public static void OFB (String inputName, String outputName, String key, String IV) throws IOException {
        File inputFile = new File(inputName);
        Reader reader = null;
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputName, true), "UTF-8"));
        try {
            String block = "";
            reader = new InputStreamReader(new FileInputStream(inputFile));
            int tem;
            String temC = IV;//temC记录输出反馈值，其初始值设定为IV
            while ((tem = reader.read()) != -1) {
                if (block.length() == 32) {
                    temC = SM4(temC, key, 0);
                    bw.write(XOR(block, temC));
                    block = "";
                }
                block += (char)tem;
            }
            temC = SM4(temC, key, 0);
            bw.write(XOR(block, temC.substring(0, block.length())));
        } catch (Exception e) {
            e.printStackTrace();
        }
        bw.close();
        reader.close();
    }

    //以下函数实现SM4算法的CFB工作模式
    public static void CFB (String inputName, String outputName, String key, String IV, int flag) throws IOException {
        File inputFile = new File(inputName);
        Reader reader = null;
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputName, true), "UTF-8"));
        try {
            String block = "";
            reader = new InputStreamReader(new FileInputStream(inputFile));
            int tem;
            String temC = IV;//temC记录密文反馈值，其初始值设定为IV
            while ((tem = reader.read()) != -1) {
                if (block.length() == 32) {
                    if (flag ==0) {
                        temC = XOR(block, SM4(temC, key, 0));
                        bw.write(temC);
                    }
                    else {
                        bw.write(XOR(block, SM4(temC, key, 0)));
                        temC = block;
                    }
                    block = "";
                }
                block += (char)tem;
            }
            //CFB模式也不需要考虑填充问题，但是最后一组需要特殊处理
            temC = SM4(temC, key, 0);
            bw.write(XOR(block, temC.substring(0, block.length())));
        } catch (Exception e) {
            e.printStackTrace();
        }
        bw.close();
        reader.close();
    }

    //以下函数实现CTR模式中计数器+1的功能，按16进制处理
    public static String ADD (String COUNT) {
        String result = new BigInteger(COUNT, 16).add(BigInteger.ONE).toString(16);
        while (result.length() < 32)
            result = "0" + result;
        return result;
    }

    //以下函数辅助实现工作模式中两个分组块的异或运算（格式为16进制）
    public static String XOR (String a, String b) {
        if (a.length() != b.length()) {
            System.out.println("XOR failed!");
            return null;
        }

        //先将两个字符串转为2进制并注意补0
        String tem1 = new BigInteger(a, 16).toString(2);
        while (tem1.length() < a.length()*4)
            tem1 = "0" + tem1;

        String tem2 = new BigInteger(b, 16).toString(2);
        while (tem2.length() < b.length()*4)
            tem2 = "0" + tem2;

        if (tem1.length() != tem2.length()) {
            System.out.println("XOR failed!");
            return null;
        }

        //将结果转化为字符串，这里仍然要补0
        String result = "";
        for (int i=0;i<tem1.length();i++) {
            if (tem1.charAt(i) == tem2.charAt(i))
                result += "0";
            else
                result += "1";
        }
        result = new BigInteger(result, 2).toString(16);
        while (result.length() < a.length())
            result = "0" + result;
        return result;
    }

    //以下是SM4算法主函数
    public static String SM4 (String text, String key, int flag) {
        //flag为标记，0代表加密，1代表解密
        int[] X = new int[36];
        generateKeys(key);//生成密钥
        //输入初始数据
        for (int i=0;i<4;i++)
            X[i] = new BigInteger(text.substring(i*8, i*8+8), 16).intValue();

        //根据需求进行加密或解密操作
        if (flag == 0) {
            for (int i=0;i<32;i++){
                X[i+4] = X[i] ^ L(S(X[i+1] ^ X[i+2] ^ X[i+3] ^ roundKeys[i]));
            }
        }
        else
        {
            for (int i=0;i<32;i++){
                X[i+4] = X[i] ^ L(S(X[i+1] ^ X[i+2] ^ X[i+3] ^ roundKeys[31-i]));
            }
        }



        String result = "";
        for (int i=35;i>=32;i--) {
            String tem = new BigInteger(Integer.toBinaryString(X[i]), 2).toString(16);
            while (tem.length() < 8)
                tem = "0" + tem;
            result += tem;
        }
        return result;
    }

    public static void generateKeys(String key) {
        int[] K = new int[36];
        int[] keybit = new int[4];
        for (int i=0;i<4;i++){
            keybit[i] = new BigInteger(key.substring(i*8, i*8+8), 16).intValue();
            K[i] = keybit[i] ^ FK[i];
        }

        for (int i=0;i<32;i++) {
            roundKeys[i] = K[i] ^ L$(S(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]));
            K[i+4] = roundKeys[i];
        }
    }

    //以下是密钥生成算法中的合成置换L‘
    public static int L$ (int B) {
        int tem1 = (B << 13) ^ ((B >> 19) & 0b1111111111111);
        int tem2 = (B << 23) ^ ((B >> 9) & 0b11111111111111111111111);
        return (B ^ tem1 ^ tem2);
    }

    //以下是加解密算法中的合成置换L
    public static int L (int B) {
        int tem1 = (B << 2) ^ ((B >> 30) & 0b11);
        int tem2 = (B << 10) ^ ((B >> 22) & 0b1111111111);
        int tem3 = (B << 18) ^ ((B >> 14) & 0b111111111111111111);
        int tem4 = (B << 24) ^ ((B >> 8) & 0b111111111111111111111111);
        return (B ^ tem1 ^ tem2 ^ tem3 ^ tem4);
    }

    //以下是S变换函数
    public static int S (int W) {
        int W1, W2, W3, W4;
        W1 = (W >> 24) & 0b11111111;
        W2 = (W >> 16) & 0b11111111;
        W3 = (W >> 8) & 0b11111111;
        W4 = W & 0b11111111;
        return ((sbox(W1) << 24) + (sbox(W2) << 16) + (sbox(W3) << 8) + sbox(W4));
    }

    //以下是sbox置换函数
    public static int sbox (int a) {
        return SBOX[a>>4][a&0b1111];
    }

    public static int[] roundKeys = new int[32];

    public static final int[] FK = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

    public static final int[] CK =
            {0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279};

    public static final int[][] SBOX=
            {{0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
             {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
             {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
             {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
             {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
             {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
             {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
             {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
             {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
             {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
             {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
             {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
             {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
             {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
             {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
             {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
    };


}
