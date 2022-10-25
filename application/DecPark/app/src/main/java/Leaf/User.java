package Leaf;

import com.ibm.zurich.idmx.dm.Nym;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.blockchain.BlockchainObject;
import com.lamductan.dblacr.lib.blockchain.RegistrationRecord;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.IProof;

import java.math.BigInteger;

public class User {
    private int id;
    private String name;
    private String private_key;
    private String IdNumber;
    private String IdCar;
    private String Car_brand;
    private String Authentication;
    private String password;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPrivate_key() {
        return private_key;
    }

    public void setPrivate_key(String private_key) {
        this.private_key = private_key;
    }

    public String getIdNumber() {
        return IdNumber;
    }

    public void setIdNumber(String idNumber) {
        IdNumber = idNumber;
    }

    public String getIdCar() {
        return IdCar;
    }

    public void setIdCar(String idCar) {
        IdCar = idCar;
    }

    public String getCar_brand() {
        return Car_brand;
    }

    public void setCar_brand(String car_brand) {
        Car_brand = car_brand;
    }

    public String getAuthentication() {
        return Authentication;
    }

    public void setAuthentication(String authentication) {
        Authentication = authentication;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public User(String name, String private_key, String idNumber, String idCar, String car_brand, String authentication, String password) {
        this.name = name;
        this.private_key = private_key;
        IdNumber = idNumber;
        IdCar = idCar;
        Car_brand = car_brand;
        Authentication = authentication;
        this.password = password;
    }



    @Override
    public String toString() {
        return "User{id =" + id + ", name = " + name + ",password =" + password + "}";
    }
}