package io.mosip.residentapp;
import expo.modules.ReactActivityDelegateWrapper;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.RequiresApi;
import com.facebook.react.ReactActivity;
import com.facebook.react.ReactActivityDelegate;
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint;
import com.facebook.react.defaults.DefaultReactActivityDelegate;

import java.util.Objects;

/**
 * IMPORTANT NOTE: The Android permission flow here works
 * for Android 10 and below, and Android 11,
 * and under continuous investigation if other manufacturers
 * fails to work, etc.
 */
public class MainActivity extends ReactActivity {

  private static final String[] REQUIRED_PERMISSIONS = new String[] {
    Manifest.permission.BLUETOOTH,
    Manifest.permission.BLUETOOTH_ADMIN,
    Manifest.permission.ACCESS_WIFI_STATE,
    Manifest.permission.CHANGE_WIFI_STATE,
    Manifest.permission.CHANGE_WIFI_MULTICAST_STATE
  };

  private static final int REQUEST_CODE_REQUIRED_PERMISSIONS = 1;

  // IDPerú integration
  private static ActivityResultLauncher<Intent> idPeruLauncher;
  private static IdPeruResultListener idPeruResultListener;

  public interface IdPeruResultListener {
    void onSuccess(String authCode);
    void onCancel(String reason);
    void onError(String message);
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    // Set the theme to AppTheme BEFORE onCreate to support
    // coloring the background, status bar, and navigation bar.
    // This is required for expo-splash-screen.
    setTheme(R.style.AppTheme);
    super.onCreate(null);
    Intent intent = getIntent();
    handleIntent(intent);

    // Register IDPerú launcher
    idPeruLauncher = registerForActivityResult(
      new ActivityResultContracts.StartActivityForResult(),
      result -> {
        android.util.Log.d("IDPerú", "========== IDPerú RESULT RECEIVED ==========");
        android.util.Log.d("IDPerú", "Result code: " + result.getResultCode());
        android.util.Log.d("IDPerú", "RESULT_OK value: " + RESULT_OK + " (expected: -1)");
        android.util.Log.d("IDPerú", "RESULT_CANCELED value: " + RESULT_CANCELED + " (expected: 0)");
        android.util.Log.d("IDPerú", "Result data is null: " + (result.getData() == null));
        if (result.getData() != null) {
          android.util.Log.d("IDPerú", "Result Intent: " + result.getData().toString());
          android.os.Bundle extras = result.getData().getExtras();
          if (extras != null) {
            android.util.Log.d("IDPerú", "Result has extras");
            for (String key : extras.keySet()) {
              Object value = extras.get(key);
              android.util.Log.d("IDPerú", "  Extra: " + key + " = " + value);
            }
          } else {
            android.util.Log.d("IDPerú", "Result has NO extras");
          }
        } else {
          android.util.Log.d("IDPerú", "Result Intent is NULL");
        }
        android.util.Log.d("IDPerú", "===========================================");
        
        if (idPeruResultListener == null) {
          android.util.Log.e("IDPerú", "ERROR: idPeruResultListener is NULL!");
          return;
        }
    
        if (result.getResultCode() == RESULT_OK && result.getData() != null) {
          String code = result.getData().getStringExtra("auth_code");
          android.util.Log.d("IDPerú", "Extracted auth_code: " + (code != null ? "PRESENT (length=" + code.length() + ")" : "NULL"));
          
          if (code != null) {
            idPeruResultListener.onSuccess(code);
          } else {
            idPeruResultListener.onError("Missing auth_code in result intent");
          }
        } else if (result.getResultCode() == RESULT_CANCELED) {
          android.util.Log.w("IDPerú", "IDPerú returned RESULT_CANCELED");
          idPeruResultListener.onCancel("User canceled or no result");
        } else {
          android.util.Log.e("IDPerú", "Unknown result code: " + result.getResultCode());
          idPeruResultListener.onError("Unknown result");
        }
        idPeruResultListener = null;
      }
    );
  }

  @Override
  public void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    handleIntent(intent);
  }

  private void handleIntent(Intent intent) {
    if (intent == null || intent.getData() == null) return;

    Uri data = intent.getData();
    String scheme = data.getScheme();
    IntentData intentData = IntentData.getInstance();

    if (scheme == null) return;

    switch (scheme) {
      case "io.mosip.residentapp.inji":
        intentData.setQrData(data.toString());
        break;
      case "openid4vp":
        intentData.setOVPQrData(data.toString());
        break;
      default:
        break;
    }
  }

  /**
   * Returns the name of the main component registered from JavaScript. This is used to schedule
   * rendering of the component.
   */
  @Override
  protected String getMainComponentName() {
    return "main";
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  @Override
  protected void onStart() {
    super.onStart();

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      if (!hasPermissions(this, REQUIRED_PERMISSIONS)) {
        this.requestPermissions(REQUIRED_PERMISSIONS, REQUEST_CODE_REQUIRED_PERMISSIONS);
      }
    }
    // TODO Commenting this only for now if permission is not working for other Android 11 manifacturer/devices
    // if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
    //  WifiManager wifi = (WifiManager)getSystemService( Context.WIFI_SERVICE );
    //  if (wifi != null){
    //    WifiManager.MulticastLock lock = wifi.createMulticastLock("IdpassSmartshareExample");
    //    lock.acquire();
    //  }
    // }
    // Must add this to onDestroy/onStop or disconnect to save battery
    // lock.release();

  }

  /**
   * Returns true if the app was granted all the permissions. Otherwise, returns false.
   */
  private static boolean hasPermissions(Context context, String... permissions) {
    for (String permission : permissions) {
      if (context.checkCallingOrSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
        return false;
      }
    }
    return true;
  }


    /**
   * Returns the instance of the {@link ReactActivityDelegate}. Here we use a util class {@link
   * DefaultReactActivityDelegate} which allows you to easily enable Fabric and Concurrent React
   * (aka React 18) with two boolean flags.
   */
  @Override
  protected ReactActivityDelegate createReactActivityDelegate() {
    return new ReactActivityDelegateWrapper(this, BuildConfig.IS_NEW_ARCHITECTURE_ENABLED, new DefaultReactActivityDelegate(        this,
        getMainComponentName(),
        // If you opted-in for the New Architecture, we enable the Fabric Renderer.
        DefaultNewArchitectureEntryPoint.getFabricEnabled(), // fabricEnabled
        // If you opted-in for the New Architecture, we enable Concurrent React (i.e. React 18).
        DefaultNewArchitectureEntryPoint.getConcurrentReactEnabled() // concurrentRootEnabled
    ));
  }

  /**
   * Launches IDPerú app for authentication
   * @param activity The ReactActivity instance
   * @param intent Intent configured to launch IDPerú
   * @param listener Callback listener for result handling
   */
  public static void launchIdPeru(ReactActivity activity, Intent intent, IdPeruResultListener listener) {
    if (idPeruLauncher == null) {
      listener.onError("Launcher not ready");
      return;
    }
    idPeruResultListener = listener;
    idPeruLauncher.launch(intent);
  }
}
