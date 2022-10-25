package com.example.decpark;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.ibm.zurich.idmx.utils.SystemParameters;
import com.lamductan.Test.Test;
import com.lamductan.dblacr.system.DBLACRSystem;

public class AuthenticationActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_authentication);
        DBLACRSystem dblacrSystem = DBLACRSystem.getInstance();
        SystemParameters sp = dblacrSystem.getSystemParameters();
        System.out.println("1. Test User Register");
        int nUsers = 1;
        Test.testUserRegister(nUsers);
        System.out.println("注册完成");
    }
}