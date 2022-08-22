package Leaf;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.FileInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;

public class PLs {
    int id;
    double lat;
    double lng;
    int ps;
    String price;

    public PLs(int id, double lat, double lng, int ps, String price) {
        this.id = id;
        this.lat = lat;
        this.lng = lng;
        this.ps = ps;
        this.price = price;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public double getLat() {
        return lat;
    }

    public void setLat(double lat) {
        this.lat = lat;
    }

    public double getLng() {
        return lng;
    }

    public void setLng(double lng) {
        this.lng = lng;
    }

    public int getPs() {
        return ps;
    }

    public void setPs(int ps) {
        this.ps = ps;
    }

    public String getPrice() {
        return price;
    }

    public void setPrice(String price) {
        this.price = price;
    }

    @Override
    public String toString() {
        return "PLs{" +
                "id=" + id +
                ", lat=" + lat +
                ", lng=" + lng +
                ", ps=" + ps +
                ", price='" + price + '\'' +
                '}';
    }

    public static ArrayList<PLs> parseInfoFromInputFile(String inputFilePath, int rowBegin, int rowEnd) throws IOException {
        FileInputStream fileInput = new FileInputStream(inputFilePath);
        XSSFWorkbook wb = new XSSFWorkbook(fileInput);
        XSSFSheet sheet = wb.getSheetAt(0);
        int lastRowNum = rowEnd;
        ArrayList<PLs> PL_list = new ArrayList<>();

        for (int i = rowBegin; i <= lastRowNum; ++i) {
            XSSFRow row = sheet.getRow(i);//获取每一行
            XSSFCell cell0 = row.getCell(0);//id
            XSSFCell cell1 = row.getCell(1);//lat
            XSSFCell cell2 = row.getCell(2);//lng
            XSSFCell cell3 = row.getCell(3);//ps
            XSSFCell cell4 = row.getCell(4);//price
            cell0.setCellType(CellType.STRING);
            cell1.setCellType(CellType.STRING);
            cell2.setCellType(CellType.STRING);
            cell3.setCellType(CellType.STRING);
            cell4.setCellType(CellType.STRING);
            int id = Integer.parseInt(cell0.getRichStringCellValue().getString());
            double lat = Double.parseDouble(cell1.getRichStringCellValue().getString());
            double lng = Double.parseDouble(cell2.getRichStringCellValue().getString());
            int ps = Integer.parseInt(cell3.getRichStringCellValue().getString());
            String price = cell4.getRichStringCellValue().getString();
            PLs pl = new PLs(id, lat, lng, ps, price);
            PL_list.add(pl);
        }
        wb.close();
        fileInput.close();
        return PL_list;
    }

    public static void main(String[] args) throws IOException {
        ArrayList<PLs> pl_list = parseInfoFromInputFile("src/main/resources/LosAngelParkingLots.xlsx", 46,61);
        System.out.println(pl_list);
    }

}
