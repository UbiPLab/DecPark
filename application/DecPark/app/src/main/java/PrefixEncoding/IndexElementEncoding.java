package PrefixEncoding;

import java.util.ArrayList;
import java.util.List;

public class IndexElementEncoding {
    public static String[] prefix(int bitsize, int x) throws Exception{//F(6) = { 0110,011*,01**,0***,**** }
        if(Math.pow(2, bitsize) - 1 < x){
            throw new Exception();
        }
        String result = Integer.toBinaryString(x);//整型转换为二进制，返回二进制的字符串形式
        StringBuffer tempsb =new StringBuffer();//可变字符串
        if (result.length()<bitsize){
            for (int i = 0;i < bitsize - result.length();i++){
                tempsb.append(0);
            }
        }
        tempsb.append(result);
        String[] list = new String[bitsize + 1];
        for (int i = 0;i < bitsize; i++){
            list[i] = tempsb.toString();
            tempsb.replace(bitsize - i - 1, bitsize - i, "*");
        }
        list[bitsize] = tempsb.toString();
        return list;
    }
    public static String[] range(int bitesize, int down, int up){// range[down,up] of bitsize bit S[0,8] = { 0***,1000 }
        String[] str =new String[up - down + 1];
        for (int i = 0; i < str.length; i++){
            String result = Integer.toBinaryString(down + i);
            StringBuffer tempsb = new StringBuffer();
            if (result.length() < bitesize){
                for (int j = 0; j< bitesize - result.length(); j++){
                    tempsb.append(0);
                }
            }
            tempsb.append(result);
            str[i] = tempsb.toString();//StringBuffer 转换为String
        }
        double time = Math.floor(Math.log(str.length) / Math.log(2));//向下取整
        String[] temp = new String[str.length];
        temp = str;
        do {
            int k =temp.length;
            for (int j = 1; j < k; j++){
                String s = prefix(temp[j - 1], temp[j]);
                if (s.length() > 0 ){
                    StringBuffer tempsb = new StringBuffer();
                    tempsb.append(temp[j]);
                    tempsb.replace(s.length(), bitesize, "*");

                    temp[j - 1] = tempsb.toString();
                    temp[j - 1] = add(temp[j - 1], bitesize);
                    temp[j] = temp[j - 1];
                    j++;

                }
            }
            String[] t2 = Repeat(temp);
            temp = t2;
            time--;
        }while (time > 0);
        return temp;
    }




    public static String add(String str, int strLength) {       //补全
        int strLen = str.length();
        if (strLen < strLength) {
            while (strLen < strLength) {
                StringBuffer sb = new StringBuffer();
                //sb.append("0").append(str);// 左补0
                sb.append(str).append("*");//右补*
                str = sb.toString();
                strLen = str.length();
            }
        }

        return str;
    }

    public static String prefix(String s1, String s2) {          //相同前缀
        String str = "";
        int samebit = 0;
        int min = (s1.length() < s2.length()) ? s1.length() : s2.length();
        char[] ch1 = s1.toCharArray();
        char[] ch2 = s2.toCharArray();
        for (int i = 0; i < min; i++) {
            if (ch1[i] == ch2[i]) {
                str = str + ch1[i];
            } else {
                break;
            }
        }
        for (int i = 0; i < min; i++) {
            if (ch1[i] == ch2[i]) {
                samebit++;
            }
        }
        if (samebit == s1.length() - 1) {
            return str;
        } else {
            str = "";
            return str;
        }
    }

    public static String[] Repeat(String[] arr) {       //一个数组中去除相同元素
        //创建一个集合
        List list = new ArrayList();
        //遍历数组往集合里存元素
        for (int i = 0; i < arr.length; i++) {
            //如果集合里面没有相同的元素才往里存
            if (!list.contains(arr[i])) {
                list.add(arr[i]);
            }
        }
        //toArray()方法会返回一个包含集合所有元素的Object类型数组
        Object[] newArr = list.toArray();
        String[] dest = new String[newArr.length];
        for (int i = 0; i < dest.length; i++)
            dest[i] = newArr[i].toString();
        return dest;
    }

    public static String[] RepeatS(String[] s1, String[] s2) {//两个数组中取相同元素
        List list = new ArrayList();
        for (int i = 0; i < s1.length; i++) {
            for (int j = 0; j < s2.length; j++) {
                if (s1[i].equals(s2[j]))
                    list.add(s1[i]);
            }
        }
        Object[] newArr = list.toArray();
        String[] dest = new String[newArr.length];
        for (int i = 0; i < dest.length; i++)
            dest[i] = newArr[i].toString();
        String[] result = Repeat(dest);
        return result;


    }

    public static void main(String[] args) {
        String[] a = IndexElementEncoding.range(4, 6,8);
        for (int i = 0; i < a.length; i++){
            System.out.println(a[i]);
        }
    }
























}

