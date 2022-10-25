package com.example.decpark;
import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.os.Bundle;
import android.os.StrictMode;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import org.web3j.utils.Numeric;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import Leaf.Param;
import TestDecPark.UseDecPark;
import TokenCompute.User;
import TokenCompute.twinAndhkp;
import javafx.util.Pair;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //取消主线程的网络连接限制
        if (android.os.Build.VERSION.SDK_INT > 9) {
            StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
            StrictMode.setThreadPolicy(policy);
        }

        Button btn_Query = findViewById(R.id.Query_Button);
        EditText id_EditText = findViewById(R.id.Id_EditText);
        EditText lat_EditText = findViewById(R.id.Lat_EditText);
        EditText log_EditText = findViewById(R.id.Lon_EditText);
        EditText k_EditText = findViewById(R.id.K_EditText);

        //查询按钮的点击事件
        btn_Query.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    int id = Integer.parseInt(id_EditText.getText().toString());
                    double lat = Double.parseDouble(lat_EditText.getText().toString());
                    double lon = Double.parseDouble(log_EditText.getText().toString());
//                    double lat = 34.0550558;
//                    double lng = -118.2448534;
                    User user = new User(id, Param.data_number,lat,lon, Param.K0);
                    byte[] driver1 = user.getUserid_hash();
                    Log.d("driver", Numeric.toHexString(driver1));
                    ArrayList<String> t1 = user.get_T1();
                    ArrayList<String> t2 = user.get_T2();
                    ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw_locations = user.T1_raw_locations(t1);
                    ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t2_raw_locations = user.T1_raw_locations(t2);
                    HashMap<String, twinAndhkp> token1_map = user.get_token_map(t1, t1_raw_locations);
                    HashMap<String, twinAndhkp> token2_map = user.get_token_map(t2, t2_raw_locations);
                    UseDecPark.PushToken1(driver1,token1_map);
                    UseDecPark.PushToken2(driver1,token2_map);
                    Thread.sleep(5000);
                    // 获取k
                    String k = k_EditText.getText().toString();
                    //查询
                    UseDecPark.Query(driver1,new BigInteger(k));

                    Intent intent = new Intent(MainActivity.this, ResultActivity.class);
                    //将司机和查询参数k传递给结果页面
                    intent.putExtra("driver",user.getUserid_hash());
                    intent.putExtra("k",k);
                    startActivity(intent);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

}