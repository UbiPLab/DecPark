package com.example.decpark;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import Leaf.SQlite;

public class RegisterActivity extends AppCompatActivity {
    private SQlite mSQlite;
    private Button register;
    private EditText username;
    private EditText userpassword;
    private EditText IdNumber;
    private EditText IdCar;
    private EditText Car_brand;
    private EditText Authentication;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_register);
        register = findViewById(R.id.register);
        username = findViewById(R.id.re_username);
        IdNumber = findViewById(R.id.IdNumber);
        IdCar = findViewById(R.id.IdCar);
        Car_brand = findViewById(R.id.Car_brand);
        userpassword = findViewById(R.id.re_password1);
        //返回一个SQLdatabase对象，对该对象进行增删改查
        mSQlite = new SQlite(RegisterActivity.this);

        register.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String name = username.getText().toString().trim();
                String password = userpassword.getText().toString().trim();
                String id_number = IdNumber.getText().toString().trim();
                String car_id = IdCar.getText().toString().trim();
                String car_brand = Car_brand.getText().toString().trim();

                SharedPreferences pref = getSharedPreferences("key_1", MODE_PRIVATE);
                String private_key = pref.getString("private_key", "");

                if (!TextUtils.isEmpty(name) && !TextUtils.isEmpty(password)){
                    //增加数据
                    mSQlite.add(name,private_key,id_number,car_id,car_brand,"unauthorized",password);
                    Intent intent1 = new Intent(RegisterActivity.this, LoginActivity.class);
                    startActivity(intent1);
                    finish();
                    Toast.makeText(RegisterActivity.this,"Register success",Toast.LENGTH_SHORT).show();
                }else {
                    Toast.makeText(RegisterActivity.this,"The information is incomplete, and the registration fails",Toast.LENGTH_SHORT).show();

                }

            }
        });

    }
}