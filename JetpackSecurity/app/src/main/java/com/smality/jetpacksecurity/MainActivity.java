package com.smality.jetpacksecurity;

import androidx.appcompat.app.AppCompatActivity;
import androidx.security.crypto.*;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Log;
import android.view.View;
import android.widget.*;
import java.io.*;
import java.security.GeneralSecurityException;

public class MainActivity extends AppCompatActivity {
    TextView result;
    EditText edt_data;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btn_saveFile=(Button)findViewById(R.id.save_file);
        Button btn_readFile=(Button)findViewById(R.id.read_file);
        Button btn_encryptionSharedP=(Button)findViewById(R.id.encryption_sp);
        result=(TextView)findViewById(R.id.result);
        edt_data=(EditText)findViewById(R.id.data);

        //Olusturulacak dosya ismi File sınıfına atandı
        String fileToWrite = "my_sensitive_data.txt";
        final File secret_file = new File(this.getFilesDir(), fileToWrite);

        btn_saveFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
               String data= edt_data.getText().toString();
               saveFileEncryption(data,secret_file);
            }
        });

        btn_readFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                readFile(secret_file);
            }
        });

        btn_encryptionSharedP.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String dataShared= edt_data.getText().toString();
                sharedPreferencesEncryption(dataShared);
            }
        });
    }

    public void saveFileEncryption(String data,File secretFile){

        //Key üretmek için, MasterKeys class’ına AES256-GCM şifreleme algoritmasını tanımladık
        KeyGenParameterSpec keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC;
        //Şifreleme algoritmasını kullanarak, dosyayı şifreleyerek oluşturma
        try {
            if(!secretFile.exists()) {
                String masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec);
                EncryptedFile encryptedFile = new EncryptedFile.Builder(
                        secretFile,
                        this,
                        masterKeyAlias,
                        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
                ).build();


            // Oluşturalan dosya içine, veriyi şifreli halde yazma
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    encryptedFile.openFileOutput()));
            writer.write(data);
            writer.close();
            }

        }  catch (Exception ex) {
            //Yaptığımız işlemle ilgili herhangi bir hata karşışında derleyici bu alana gelecektir
            ex.printStackTrace();
        }
    }

    //Oluşturulmuş dosya içeriğini okuma işlemi
    public void readFile(File secretFile) {
        try {

            StringBuilder text = new StringBuilder();
            BufferedReader br = new BufferedReader(new FileReader(secretFile));
            String line;

            while ((line = br.readLine()) != null) {
                text.append(line);
                text.append('\n');
            }
            br.close();
            result.setText(text.toString());
        }  catch (IOException ex) {
            //Yaptığımız işlemle ilgili herhangi bir hata karşışında derleyici bu alana gelecektir
        }

    }
    //SharedPreferences şifreleme, şifrelenmiş SharedPreferences değer atama ve değer çağırma
    public void sharedPreferencesEncryption(String data){
        SharedPreferences sharedPreferences = null;
        try {
            //Key üretmek için, MasterKeys class’ına AES256-GCM şifreleme algoritmasını tanımladık
            String masterKeyAlias2 = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);
            sharedPreferences = EncryptedSharedPreferences.create(
                    "secret_shared_prefs",
                    masterKeyAlias2,
                    this,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Şifrelenmiş SharedPreferences'a veri ekledim
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString("UserName", data);
        editor.commit();
        //Şifrelenmiş SharedPreferences'daki veriyi çağırdım(getirdim)
        String name =sharedPreferences.getString("UserName","default");
        result.setText(name);
    }
}
