package com.example.decpark;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.List;

public class PLsAdapter extends RecyclerView.Adapter<PLsAdapter.ViewHolder>{
    private List<ParkingLot> mParkingLot;

    static class ViewHolder extends RecyclerView.ViewHolder {
        ImageView PL_image;
        TextView PL_id_spots;
        TextView PL_price;
        TextView PL_lat;
        TextView PL_lng;

        //传入每个子项的布局，存储每个子项的图片和名字
        public ViewHolder(View view) {
            super(view);
            PL_image = view.findViewById(R.id.PL_image);
            PL_id_spots = view.findViewById(R.id.id_spots_tv);
            PL_price = view.findViewById(R.id.prices_tv);
            PL_lat = view.findViewById(R.id.lat_tv);
            PL_lng = view.findViewById(R.id.lng_tv);

        }

    }

    //数据源传进来， 并赋值给一个全局变量mParkingLot
    public PLsAdapter(List<ParkingLot> PL_List) {
        mParkingLot = PL_List;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.parkinglot_item, parent, false);
        ViewHolder holder = new ViewHolder(view);
        return holder;
    }

    //onBindViewHolder() 方法是用于对 RecyclerView子项的数据进行赋值的，会在每个子项被滚动到屏幕内的时候执行
    //在这里显示停车场图片和名字
    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        ParkingLot parkingLot = mParkingLot.get(position);
        holder.PL_image.setImageResource(parkingLot.getImageId());
        holder.PL_id_spots.setText(parkingLot.getNo_l());
        holder.PL_price.setText(parkingLot.getPrice());
        holder.PL_lat.setText(parkingLot.getLat());
        holder.PL_lng.setText(parkingLot.getLng());

    }

    @Override
    public int getItemCount() {
        return mParkingLot.size();
    }



}
