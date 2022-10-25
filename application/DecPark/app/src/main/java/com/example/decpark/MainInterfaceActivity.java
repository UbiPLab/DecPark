package com.example.decpark;
import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import com.example.decpark.widget.ItemGroup;
import com.lamductan.Test.Test;
import com.lamductan.dblacr.system.DBLACRSystem;
import java.util.ArrayList;
import Leaf.SQlite;
import Leaf.User;


public class MainInterfaceActivity extends AppCompatActivity implements View.OnClickListener {
    private SQlite mSQlite;


private ItemGroup ig_plate_number,ig_id_number,ig_username,ig_car_brand,ig_authentication;

    private ArrayList<String> optionsItems_gender = new ArrayList<>();
    private ProgressBar progress_bar;
    private Button search_button;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main_interface);
        mSQlite = new SQlite(MainInterfaceActivity.this);

        ig_plate_number = (ItemGroup)findViewById(R.id.ig_Plate_number);
        ig_username = (ItemGroup)findViewById(R.id.ig_username);
        ig_id_number = (ItemGroup)findViewById(R.id.ig_ID_number);
        ig_car_brand = (ItemGroup)findViewById(R.id.ig_Car_brand);
        ig_authentication = (ItemGroup)findViewById(R.id.ig_Authentication);
        progress_bar = findViewById(R.id.progress_bar);
        progress_bar.setVisibility(View.GONE);
        initInfo();
        ig_authentication.setOnClickListener(this);
        search_button = findViewById(R.id.search_button);
        search_button.setVisibility(View.GONE);
        search_button.setOnClickListener(this);

    }

    @Override
    protected void onDestroy(){
        super.onDestroy();

    }

    //从数据库中初始化数据并展示
    private void initInfo(){
        Intent intent = getIntent();
        String username = intent.getStringExtra("username");
        User user = mSQlite.get_user_info(username);
//        User user = mSQlite.get_user_info("westbrook");
        String name = user.getName();
        String idNumber = user.getIdNumber();
        String car_brand = user.getCar_brand();
        String authentication = user.getAuthentication();
        String idCar = user.getIdCar();
        ig_plate_number.getContentEdt().setText(idCar);  //ID是int，转string
        ig_username.getContentEdt().setText(name);
        ig_id_number.getContentEdt().setText(idNumber);
        ig_car_brand.getContentEdt().setText(car_brand);
        ig_authentication.getContentEdt().setText(authentication);

    }

    public void onClick(View v){
        switch (v.getId()){
            //点击修改地区逻辑
            case R.id.ig_Authentication:
                progress_bar.setVisibility(View.VISIBLE);
                start(progress_bar);
                DBLACRSystem dblacrSystem = DBLACRSystem.getInstance();
                com.lamductan.dblacr.actor.user.User user = new com.lamductan.dblacr.actor.user.User();
                user.register();
                Log.e("registration finish","registration successful");
                int nServiceProviders = 1;
                Test.testServiceProviderJoin(nServiceProviders);
                Test.testAuthenticateUser(0, dblacrSystem);
                ig_authentication.getContentEdt().setText("successful");
                search_button.setVisibility(View.VISIBLE);
                break;
            case R.id.search_button:
                Intent intent = new Intent(MainInterfaceActivity.this, QueryActivity.class);
                startActivity(intent);
                break;
            default:
                break;
        }
    }


    // 进度条开始变化的方法
    public void start(final ProgressBar progressBar) {
        // 耗时任务放在子线程种进行
        new Thread() {
            private int nowProgress;
            private int maxProgress;
            public void run() {
                // 得到进度条当前的值
                nowProgress = progressBar.getProgress();
                // 得到进度条最大值
                maxProgress = progressBar.getMax();
                // 当当前进度小于最大进度值时
                while (nowProgress < maxProgress) {
                    nowProgress++;
                    progressBar.setProgress(nowProgress);
                    // 表示在UI线程种更新TextView因为子线程不能更新UI
                    runOnUiThread(new Runnable() {

                        @Override
                        public void run() {
//                            // 设置TextView的内容
//                            textView.setText(nowProgress + "/" + maxProgress);
                        }
                    });
                    try {
                        // 延时模拟加载进度
                        Thread.sleep(50);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            };
        }.start();
    }

}