package utilits;

import Leaf.Param;

import java.util.Random;

public class CommonUtilit {



    public static String getRandomString(int length){

        String str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        Random random=new Random();

        StringBuffer sb=new StringBuffer();

        for(int i=0;i<length;i++){

            int number=random.nextInt(62);

            sb.append(str.charAt(number));

        }

        return sb.toString();
    }

    public static double random_double(double MIN, double MAX) {
        int s = 0;
        if (MAX<0){
            int min= (int) (MAX*10000000*(-1));
            int max=(int) (MIN*10000000*(-1));
            Random random = new Random();
            s = random.nextInt(max)%(max-min+1) + min;
            double v = (double) s/10000000;
            return v*(-1);

        }else {
            int max= (int) (MAX*10000000);
            int min=(int) (MIN*10000000);
            Random random = new Random();
            s = random.nextInt(max)%(max-min+1) + min;
            double v = (double) s/10000000;
            return v;
        }


    }




    public static void main(String[] args) {

        double lat = CommonUtilit.random_double(Param.LAT1,Param.LAT2);
        double lng = CommonUtilit.random_double(Param.LON1,Param.LON2);
        System.out.println(lat);
        System.out.println(lng);
    }

}
