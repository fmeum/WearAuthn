-dontwarn android.bluetooth.BluetoothHidDeviceCallback

# Ensure the custom, fast service loader implementation is removed.
-assumevalues class kotlinx.coroutines.internal.MainDispatcherLoader {
  boolean FAST_SERVICE_LOADER_ENABLED return false;
}
-checkdiscard class kotlinx.coroutines.internal.FastServiceLoader
