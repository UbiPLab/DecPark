package Leaf;

import android.annotation.SuppressLint;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.widget.Toast;

import java.util.ArrayList;

public class SQlite extends SQLiteOpenHelper {
    private SQLiteDatabase db;

    //带全部参数的构造函数，此构造函数必不可少
    public SQlite(Context context){
        super(context,"user",null,1);
        db = getReadableDatabase();
    }

    //构造函数完事之后，写继承的抽象类SQLiteOpenHelper中的两个抽象方法：
    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS user(" +
                "_id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT," +
                "private_key TEXT,"+
                "IdNumber TEXT,"+
                "IdCar TEXT,"+
                "Car_brand TEXT,"+
                "Authentication TEXT,"+
                "password TEXT)");
    }
    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS user");
        onCreate(db);
    }

    public void add(String name,String private_key,String IdNumber,String IdCar,String Car_brand,String Authentication,String password ){
        db.execSQL("INSERT INTO user(name,private_key,IdNumber,IdCar,Car_brand,Authentication,password)VALUES(?,?,?,?,?,?,?)",new Object[]{name,private_key,IdNumber,IdCar,Car_brand,Authentication,password});

    }

    public ArrayList<User> getAllDATA(){
        ArrayList<User> list = new ArrayList<User>();
        Cursor cursor = db.query("user",null,null,null,null,null,"name DESC");
        while(cursor.moveToNext()){
            @SuppressLint("Range") String name = cursor.getString(cursor.getColumnIndex("name"));
            @SuppressLint("Range") String private_key = cursor.getString(cursor.getColumnIndex("private_key"));
            @SuppressLint("Range") String IdNumber = cursor.getString(cursor.getColumnIndex("IdNumber"));
            @SuppressLint("Range") String IdCar = cursor.getString(cursor.getColumnIndex("IdCar"));
            @SuppressLint("Range") String Car_brand = cursor.getString(cursor.getColumnIndex("Car_brand"));
            @SuppressLint("Range") String Authentication = cursor.getString(cursor.getColumnIndex("Authentication"));
            @SuppressLint("Range") String password = cursor.getString(cursor.getColumnIndex("password"));
            list.add(new User(name,private_key,IdNumber,IdCar,Car_brand,Authentication,password));
        }
        return list;
    }


    public User get_user_info(String username){
        ArrayList<User> list = new ArrayList<User>();
        Cursor cursor = db.query("user", new String[]{"name,private_key,IdNumber,IdCar,Car_brand,Authentication,password"}, "name=?", new String[]{username}, null, null, null);

        cursor.moveToFirst();
        @SuppressLint("Range") String name = cursor.getString(cursor.getColumnIndex("name"));
        @SuppressLint("Range") String private_key = cursor.getString(cursor.getColumnIndex("private_key"));
        @SuppressLint("Range") String IdNumber = cursor.getString(cursor.getColumnIndex("IdNumber"));
        @SuppressLint("Range") String IdCar = cursor.getString(cursor.getColumnIndex("IdCar"));
        @SuppressLint("Range") String Car_brand = cursor.getString(cursor.getColumnIndex("Car_brand"));
        @SuppressLint("Range") String Authentication = cursor.getString(cursor.getColumnIndex("Authentication"));
        @SuppressLint("Range") String password = cursor.getString(cursor.getColumnIndex("password"));

        cursor.close();
        return  new User(name,private_key,IdNumber,IdCar,Car_brand,Authentication,password);
    }
}




