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

import java.util.ArrayList;

import Leaf.SQlite;
import Leaf.User;

public class LoginActivity extends AppCompatActivity {
    private SQlite mSQlite;
    private Button login;
    private Button register;
    private EditText username;
    private EditText userpassword;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        login = findViewById(R.id.login);
        register = findViewById(R.id.register);
        username = findViewById(R.id.user_Name);
        userpassword = findViewById(R.id.userpassword);

        mSQlite = new SQlite(LoginActivity.this);

        register.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                SharedPreferences.Editor editor = getSharedPreferences("key_1",MODE_PRIVATE).edit();
//                editor.putString("private_key","0xD8Af6F8868d3cFF9E84d4089BFC8ead617B8AF55");
//                editor.putString("private_key2","0xD8Af6F8868d3cFF9E84d4089BFC8ead617B8AF55");
//                editor.apply();
                Intent intent5 = new Intent(LoginActivity.this, RegisterActivity.class);
                startActivity(intent5);
                finish();
            }
        });


        login.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String name = username.getText().toString().trim();
                String password = userpassword.getText().toString().trim();
                if (!TextUtils.isEmpty(name) && !TextUtils.isEmpty(password)){
                    ArrayList<User> data = mSQlite.getAllDATA();
                    boolean userdata = false;
                    for (int i = 0; i < data.size(); i++) {
                        User user = data.get(i);
                        if (name.equals(user.getName()) && password.equals(user.getPassword())){
                            userdata = true;
                            break;
                        }else {
                            userdata = false;
                        }
                    }
                    if (userdata){
                        Toast.makeText(LoginActivity.this,"Login Success",Toast.LENGTH_SHORT).show();
                        Intent intent = new Intent(LoginActivity.this, MainInterfaceActivity.class);
                        intent.putExtra("username", name);
                        startActivity(intent);
                    }else {
                        Toast.makeText(LoginActivity.this,"The user name or password is incorrect",Toast.LENGTH_SHORT).show();
                    }
                }else {
                    Toast.makeText(LoginActivity.this,"The user name or password cannot be empty",Toast.LENGTH_SHORT).show();
                }


            }
        });




    }
}