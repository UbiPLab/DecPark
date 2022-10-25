package Leaf;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Param {
    public static String K0 = "eOkQeH2G4kSzvyEi0V2fuCpnhfFxmLpN";
    public static String AESkey = "123";
    public static int ibflength = 9140;
    public static String[] keylist = {"p0NBcQ9eM7bVsU12PJQXsYjkaHud8hKz", "Iy8Q9QQs84YitIJRVuFDPtibqJZSXw7E", "gioMTiUMkJ7AmJi1GImdD3tVpDntd4WQ","y5AOKHMSTqyTawEqCNyUw52r1Q2IUQuo","JzudOShm0QN0GPUVJkdjWCGsso97CIbX","CU5g5D0y8LSwwgTBNNBwwLoG2eaQJBRP"};
    //LosAnge
    public static int data_number = 62;
    public static int[] rb_list = getRandom();
    public static double LON1 = 116.371064;//大
    public static double LON2 = 116.620705;//小
    public static double LAT1 = 39.906636;//小
    public static double LAT2 = 39.94754;//大


    /**
     * 从list中随机抽取不重复的元素
     * @param paramList 要抽取的list
     * @param count 要抽取的个数
     * @return
     */
    public static ArrayList<Double> getRandomList(ArrayList<Double> paramList,int count){
        if(paramList.size()<count){
            return  paramList;
        }
        Random random=new Random();
        List<Integer> tempList=new ArrayList<>();
        ArrayList<Double> newList=new ArrayList<>();
        int temp=0;
        for(int i=0;i<count;i++){
            temp=random.nextInt(paramList.size());
            if(!tempList.contains(temp)){
                tempList.add(temp);
                newList.add(paramList.get(temp));
            }
            else{
                i--;
            }
        }
        return newList;
    }







    public static int[] getRandom(){
        int[] rb_list = new int[3*data_number];
        for (int i = 1; i < 3*data_number; i++) {
            rb_list[i] = i;
        }
        return rb_list;
    }


}
