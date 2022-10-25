package com.example.decpark;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.content.Intent;
import android.os.Bundle;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import Leaf.Param;
import TestDecPark.UseDecPark;
import Web3.User_Result;

public class ResultActivity extends AppCompatActivity {
    private List<ParkingLot> ParkingLot_List = new ArrayList<>();
    int[] imageId_list = new int[]{R.mipmap.pl4,R.mipmap.pl2,R.mipmap.pl1,R.mipmap.pl3,R.mipmap.pl5};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_result);

        Intent intent = getIntent();
        //获取查询司机和查询参数k
        byte[] driver = intent.getByteArrayExtra("driver");
        String k = intent.getStringExtra("k");
        RecyclerView recyclerView = findViewById(R.id.recycler_view);
        //获取结果
        try {
            List<User_Result> Results = UseDecPark.get_R(driver, new BigInteger(k), Param.AESkey);
            System.out.println(Results);
            //初始化数据
            initFruits(Results);
            //LayoutManager用于指定 RecyclerView的布局方式
            LinearLayoutManager layoutManager = new LinearLayoutManager(this);
            recyclerView.setLayoutManager(layoutManager);
            //接下来我们创建了ParkingLotAdapter 的实例，并将停车场数据传入 到ParkingLotAdapter 的构造函数中，
            //最后调用RecyclerView的setAdapter() 方法来完成适配器设置，这样RecyclerView和数据之间的关联就建立完成了。
            PLsAdapter adapter = new PLsAdapter(ParkingLot_List);
            recyclerView.setAdapter(adapter);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initFruits(List<User_Result>  Results){
        for (int i = 0; i < Results.size(); i++) {
            User_Result result = Results.get(i);
            ParkingLot parkingLot = new ParkingLot(result.getNo_l(),result.getPs_pre(),result.getPs_current(),result.getLat(),result.getLng(),result.getPrice(),imageId_list[i]);
            ParkingLot_List.add(parkingLot);
        }
    }


}