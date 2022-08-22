package Leaf;

import PrefixEncoding.IndexElementEncoding;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

public class LocationEncoding {
    //LosAngel
    static double LON1 = Param.LON1;
    static double LON2 = Param.LON2;
    static double LAT1 = Param.LAT1;
    static double LAT2 = Param.LAT2;

    public static int generalID(double lat, double lon, int column_num, int  row_num){
        if (lon <= LON1 || lon >= LON2 || lat <= LAT1 || lat >= LAT2){
            return -1;
        }
        double column = (LON2 - LON1) /column_num;
        double row = (LAT2 - LAT1) / row_num;
        return (int)((lon - LON1) / column) + 1 + (int)((LAT2 - lat) / row) * column_num;
    }


}
