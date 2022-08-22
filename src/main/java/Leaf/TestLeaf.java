package Leaf;

import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
public class TestLeaf {

    public static void main(String[] args) throws Exception {
        ArrayList<PLs> pl_list = PLs.parseInfoFromInputFile("src/main/resources/LosAngelParkingLots.xlsx", 0,14);
        String[][] prefixs = new String[pl_list.size()][];
        PLs[] data    = new PLs[pl_list.size()];
        for (int i = 0; i < pl_list.size(); i++) {
            PLs pl = pl_list.get(i);
            ArrayList<String> t1 = Leafhandle.get_Prefixs(pl.id, pl.lat, pl.lng, Param.K0);
            String[] str = t1.toArray(new String[t1.size()]);
            prefixs[i] = str;
            data[i]  = pl;
        }
        for (int i = 0; i < prefixs.length; i++) {
            System.out.println(Arrays.toString(prefixs[i]));
        }


    }
}
