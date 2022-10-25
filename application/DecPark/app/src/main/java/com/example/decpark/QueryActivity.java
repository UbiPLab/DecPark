package com.example.decpark;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.os.Bundle;
import android.os.StrictMode;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Toast;

import com.amap.api.location.AMapLocation;
import com.amap.api.location.AMapLocationClient;
import com.amap.api.location.AMapLocationClientOption;
import com.amap.api.location.AMapLocationListener;
import com.amap.api.maps.AMap;
import com.amap.api.maps.CameraUpdateFactory;
import com.amap.api.maps.LocationSource;
import com.amap.api.maps.MapView;
import com.amap.api.maps.UiSettings;
import com.amap.api.maps.model.BitmapDescriptorFactory;
import com.amap.api.maps.model.CameraPosition;
import com.amap.api.maps.model.Circle;
import com.amap.api.maps.model.CircleOptions;
import com.amap.api.maps.model.LatLng;
import com.amap.api.maps.model.Marker;
import com.amap.api.maps.model.MarkerOptions;
import com.amap.api.maps.model.MyLocationStyle;
import com.amap.api.services.core.AMapException;
import com.amap.api.services.core.LatLonPoint;
import com.amap.api.services.geocoder.GeocodeResult;
import com.amap.api.services.geocoder.GeocodeSearch;
import com.amap.api.services.geocoder.RegeocodeQuery;
import com.amap.api.services.geocoder.RegeocodeResult;

import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import Leaf.Param;
import TestDecPark.UseDecPark;
import TokenCompute.User;
import TokenCompute.twinAndhkp;
import Web3.User_Result;
import javafx.util.Pair;


/**
 * 拖拽定位位置,DragLocation and drop
 */
public class QueryActivity extends Activity implements
        AMap.OnMarkerClickListener,
        AMap.OnMapLoadedListener,
        AMap.OnMapClickListener,
        LocationSource,
        AMapLocationListener,
        GeocodeSearch.OnGeocodeSearchListener,
        AMap.OnCameraChangeListener
{

    private MapView mMapView;
    private AMap                                     mAMap;
    private MarkerOptions markOptions;
    private Marker mGPSMarker;             //定位位置显示

    private MarkerOptions markOptions2;
    private ArrayList<Marker> pl_marks;


    private AMapLocation                             location;
    private LocationSource.OnLocationChangedListener mListener;
    //声明AMapLocationClient类对象
    public AMapLocationClient                        mLocationClient = null;
    //声明mLocationOption对象
    public AMapLocationClientOption                  mLocationOption = null;
    //你编码对象
    private GeocodeSearch                            geocoderSearch;

    private String                                   custAddr;
    private Double                                   custLon;
    private Double                                   custLat;
    private String                                   actualAddr;
    private Double                                   actualLon;
    private Double                                   actualLat;
    private ImageView                                img_back;
    private String                                   city;

    private LatLng latLng;
    private String addressName;
    private Circle circle;
    private List<User_Result> results;

    /**
     * @param savedInstanceState
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_query);
        if (android.os.Build.VERSION.SDK_INT > 9) {
            StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
            StrictMode.setThreadPolicy(policy);
        }

        //隐私设置
        AMapLocationClient.updatePrivacyShow(this, true, true);
        AMapLocationClient.updatePrivacyAgree(this, true);
        try {
            initMap(savedInstanceState);
        } catch (AMapException e) {
            e.printStackTrace();
        }

        //控件
        img_back = (ImageView) findViewById(R.id.img_back);
        Button btn_Query = findViewById(R.id.Query_Button);
        EditText id_EditText = findViewById(R.id.Id_EditText);
        EditText k_EditText = findViewById(R.id.K_EditText);

        //查询按钮的点击事件
        btn_Query.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    // 获取k
                    String k = k_EditText.getText().toString();
                    markOptions2 = new MarkerOptions();
                    markOptions2.icon(BitmapDescriptorFactory.fromBitmap(BitmapFactory.decodeResource(getResources(), R.drawable.icon_park))).anchor(0.5f, 0.7f);
                    pl_marks = new ArrayList<>();
                    for (int i = 0; i < Integer.parseInt(k); i++) {
                        Marker marker = mAMap.addMarker(markOptions2);
                        pl_marks.add(marker);
                    }

                    int id = Integer.parseInt(id_EditText.getText().toString());
                    double lat = latLng.latitude;
                    double lon = latLng.longitude;
                    User user = new User(id, Param.data_number,lat,lon, Param.K0);
                    byte[] driver1 = user.getUserid_hash();
                    Log.e("driver", Numeric.toHexString(driver1));
                    Log.e("lat", String.valueOf(lat));
                    Log.e("lon", String.valueOf(lon));
                    ArrayList<String> t1 = user.get_T1();
                    ArrayList<String> t2 = user.get_T2();
                    ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t1_raw_locations = user.T1_raw_locations(t1);
                    ArrayList<ArrayList<Pair<BigInteger, BigInteger>>> t2_raw_locations = user.T1_raw_locations(t2);
                    HashMap<String, twinAndhkp> token1_map = user.get_token_map(t1, t1_raw_locations);
                    HashMap<String, twinAndhkp> token2_map = user.get_token_map(t2, t2_raw_locations);
                    UseDecPark.PushToken1(driver1,token1_map);
                    UseDecPark.PushToken2(driver1,token2_map);
                    Thread.sleep(5000);

                    //查询
                    UseDecPark.Query(driver1,new BigInteger(k));
                    Thread.sleep(2000);

                    results = UseDecPark.get_R(driver1, new BigInteger(k), Param.AESkey);
                    ArrayList<LatLng> latLngs = new ArrayList<>();
                    for (int i = 0; i < Integer.parseInt(k); i++) {
                        User_Result user_result = results.get(i);
                        String lat1 = user_result.getLat();
                        String lng = user_result.getLng();
                        Log.e("lat", lat1);
                        Log.e("lng", lng);
                        latLngs.add(new LatLng(Double.parseDouble(lat1), Double.parseDouble(lng)));
                    }
                    for (int i = 0; i < pl_marks.size(); i++) {
                        Marker marker = pl_marks.get(i);
                        LatLng latLng = latLngs.get(i);
                        marker.setPosition(latLng);
                        marker.setPeriod(i);

                    }
//                    pl_marks.get(0).setPosition(latLngs.get(0));
//                    pl_marks.get(1).setPosition(latLngs.get(1));
//                    pl_marks.get(2).setPosition(latLngs.get(2));
//                    pl_marks.get(3).setPosition(latLngs.get(3));
//                    pl_marks.get(4).setPosition(new LatLng(39.91451999043305,116.51063809155187));



//                    Intent intent = new Intent(QueryActivity.this, ResultActivity.class);
//                    //将司机和查询参数k传递给结果页面
//                    intent.putExtra("driver",user.getUserid_hash());
//                    intent.putExtra("k",k);
//                    startActivity(intent);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void initMap(Bundle savedInstanceState) throws AMapException {
        mMapView = (MapView) findViewById(R.id.map_view);
        mMapView.onCreate(savedInstanceState);
//        mMapView.removeViewAt(1);
        geocoderSearch = new GeocodeSearch(this);
        mAMap = mMapView.getMap();
        mAMap.setMapLanguage("en");
        // 设置定位监听
        mAMap.setOnMapLoadedListener(this);
        mAMap.setOnMarkerClickListener(this);
        mAMap.setOnMapClickListener(this);

        mAMap.setLocationSource(this);
        //设置地图拖动监听
        mAMap.setOnCameraChangeListener(this);
        // 绑定marker拖拽事件
//      mAMap.setOnMarkerDragListener(this);

        //逆编码监听事件
//              GeocodeSearch.OnGeocodeSearchListener,
        geocoderSearch.setOnGeocodeSearchListener(this);
//        drawCircle(latLng);
        //导航箭头定位的小图标，这里自定义一张图片
        MyLocationStyle myLocationStyle = new MyLocationStyle();
        myLocationStyle.myLocationIcon(BitmapDescriptorFactory.fromResource(R.drawable.icon_location));// 设置小蓝点的图标
        myLocationStyle.strokeColor(Color.BLACK);// 设置圆形的边框颜色
        myLocationStyle.radiusFillColor(Color.argb(100, 100, 100, 180));// 设置圆形的填充颜色
        // myLocationStyle.anchor(int,int)//设置小蓝点的锚点
        myLocationStyle.strokeWidth(0f);// 设置圆形的边框粗细
        myLocationStyle.anchor(0.5f, 0.7f);
        mAMap.setMyLocationStyle(myLocationStyle);
        mAMap.moveCamera(CameraUpdateFactory.zoomTo(19)); //缩放比例
        //设置amap的属性
        UiSettings settings = mAMap.getUiSettings();
        settings.setMyLocationButtonEnabled(true);// 设置默认定位按钮是否显示
        mAMap.setMyLocationEnabled(true);// 设置为true表示显示定位层并可触发定位，false表示隐藏定位层并不可触发定位，默认是false
        mAMap.moveCamera(CameraUpdateFactory.changeLatLng(new LatLng(39.914519,116.510639)));
        mAMap.getUiSettings().setLogoBottomMargin(-100);

    }

    @Override
    public void onLocationChanged(AMapLocation aMapLocation) {
        location = aMapLocation;
        if (mListener != null && location != null)
        {
            if (location != null && location.getErrorCode() == 0)
            {
                mListener.onLocationChanged(location);// 显示系统箭头

                LatLng la = new LatLng(location.getLatitude(), location.getLongitude());
                //显示出标点
                setMarket(la, location.getCity(), location.getAddress());
                this.actualAddr = location.getAddress();
                this.actualLon = location.getLongitude();
                this.actualLat = location.getLatitude();

                mLocationClient.stopLocation();
                //                this.location = location;
                // 显示导航按钮
                //                btnNav.setVisibility(View.VISIBLE);
            }
        }
        else
        {
            Toast.makeText(QueryActivity.this,"定位失败",Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * 激活定位
     */
    @Override
    public void activate(OnLocationChangedListener onLocationChangedListener) {
        mListener = onLocationChangedListener;
        //初始化定位
        try {
            mLocationClient = new AMapLocationClient(getApplicationContext());
        } catch (Exception e) {
            e.printStackTrace();
        }
        //设置定位回调监听
        mLocationClient.setLocationListener(this);
        //初始化定位参数
        mLocationOption = new AMapLocationClientOption();
        //设置定位模式为高精度模式，Battery_Saving为低功耗模式，Device_Sensors是仅设备模式
        mLocationOption.setLocationMode(AMapLocationClientOption.AMapLocationMode.Hight_Accuracy);
        //设置是否返回地址信息（默认返回地址信息）
        mLocationOption.setNeedAddress(true);
        //设置是否只定位一次,默认为false
        mLocationOption.setOnceLocation(false);
        //设置是否强制刷新WIFI，默认为强制刷新
        mLocationOption.setWifiActiveScan(true);
        //设置是否允许模拟位置,默认为false，不允许模拟位置
        mLocationOption.setMockEnable(false);
        //设置定位间隔,单位毫秒,默认为2000ms
        mLocationOption.setInterval(2000 * 10);
        //给定位客户端对象设置定位参数
        mLocationClient.setLocationOption(mLocationOption);
        //启动定位
        mLocationClient.startLocation();
    }

    /**
     * 停止定位
     */
    @Override
    public void deactivate() {
        mListener = null;
        if (mLocationClient != null)
        {
            mLocationClient.stopLocation();
            mLocationClient.onDestroy();
        }
    }

    @Override
    public void onMapClick(LatLng latLng) {
//        LatLng latLonPoint = new LatLng(latLng.latitude, latLng.longitude);
//        if (!TextUtils.isEmpty(latLonPoint.toString())) {
//            getAddress(latLonPoint);
//            Toast.makeText(QueryActivity.this,String.valueOf(latLng.latitude+" "+ latLng.longitude),Toast.LENGTH_SHORT).show();
//        } else {
//            Toast.makeText(QueryActivity.this,"拜访位置失败",Toast.LENGTH_SHORT).show();
//        }
    }

    @Override
    public void onMapLoaded() {

    }

    @Override
    public boolean onMarkerClick(Marker marker) {

        AlertDialog.Builder dialog = new AlertDialog.Builder (QueryActivity.this);
        dialog.setTitle("Parking Reservation");
        dialog.setMessage(results.get(marker.getPeriod()).toString());
        dialog.setCancelable(false);
        dialog.setIcon(R.drawable.icon_park);
        dialog.setPositiveButton("Reserve", new DialogInterface.
                OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
            }
        });
        dialog.setNegativeButton("Cancel", new DialogInterface.
                OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
            }
        });
        dialog.show();
        return false;

    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        mMapView.onSaveInstanceState(outState);
    }
    @Override
    protected void onResume() {
        super.onResume();
        mMapView.onResume();
        // aMapEx.onRegister();
    }

    @Override
    protected void onPause() {
        super.onPause();
        mMapView.onPause();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // 销毁定位
        if (mLocationClient != null)
        {
            mLocationClient.stopLocation();
            mLocationClient.onDestroy();
        }
        mMapView.onDestroy();
    }

    private void setMarket(LatLng latLng, String title, String content) {
        if (mGPSMarker != null)
        {
            mGPSMarker.remove();
            circle.remove();
        }
        drawCircle(latLng);
        //获取屏幕宽高
        WindowManager wm = this.getWindowManager();
        int width = (wm.getDefaultDisplay().getWidth()) / 2;
        int height = ((wm.getDefaultDisplay().getHeight()) / 2) - 80;
        markOptions = new MarkerOptions();
        markOptions.draggable(true);//设置Marker可拖动
        markOptions.icon(BitmapDescriptorFactory.fromBitmap(BitmapFactory.decodeResource(getResources(), R.drawable.icon_marka))).anchor(0.5f, 0.7f);
        mGPSMarker = mAMap.addMarker(markOptions);
        //设置marker在屏幕的像素坐标

        mGPSMarker.setPosition(latLng);
//        circle.setCenter(latLng);
        mGPSMarker.setTitle(title);
        mGPSMarker.setSnippet(content);

        //设置像素坐标
        mGPSMarker.setPositionByPixels(width, height);
        mMapView.invalidate();
    }

    /**
     * 绘制圆圈
     *
     * @param latLng
     */
    public void drawCircle(LatLng latLng) {
        String color = "#26b637";
        StringBuilder sb = new StringBuilder(color);// 构造一个StringBuilder对象
        sb.insert(1, "50");// 在指定的位置10，插入指定的字符串
        if (circle != null) {
            circle = null;
        }
        circle = mAMap.addCircle(new CircleOptions()
                .center(latLng)
                .radius(200)
                .fillColor(Color.parseColor(sb.toString()))
                .strokeColor(Color.parseColor(color))
                .strokeWidth(5));
    }
    @Override
    public void onCameraChange(CameraPosition cameraPosition) {

    }

    @Override
    public void onCameraChangeFinish(CameraPosition cameraPosition) {
        latLng= cameraPosition.target;
        double latitude= latLng.latitude;
        double longitude= latLng.longitude;
        Log.e("latitude",latitude+"");
        Log.e("longitude",longitude+"");
        getAddress(latLng);


    }
    /**
     * 根据经纬度得到地址
     */
    public void getAddress(final LatLng latLng) {
        LatLonPoint latLonPoint = new LatLonPoint(latLng.latitude, latLng.longitude);
//        LatLonPoint latLonPoint = new LatLonPoint(39.914519, 116.510639);
        // 第一个参数表示一个Latlng，第二参数表示范围多少米，第三个参数表示是火系坐标系还是GPS原生坐标系
        RegeocodeQuery query = new RegeocodeQuery(latLonPoint, 500, GeocodeSearch.AMAP);
        geocoderSearch.getFromLocationAsyn(query);// 设置同步逆地理编码请求
    }

    /**
     * 逆地理编码回调
     */
    @Override
    public void onRegeocodeSearched(RegeocodeResult result, int rCode) {
        if (rCode == 1000) {
            if (result != null && result.getRegeocodeAddress() != null
                    && result.getRegeocodeAddress().getFormatAddress() != null) {

                addressName = result.getRegeocodeAddress().getFormatAddress(); // 逆转地里编码不是每次都可以得到对应地图上的opi
                Log.e("逆地理编码回调  得到的地址：" , addressName);

//              mAddressEntityFirst = new AddressSearchTextEntity(addressName, addressName, true, convertToLatLonPoint(mFinalChoosePosition));
                setMarket(latLng, location.getCity(), addressName);

            }
        }
    }

    /**
     * 地理编码查询回调
     */
    @Override
    public void onGeocodeSearched(GeocodeResult result, int rCode) {
    }
}