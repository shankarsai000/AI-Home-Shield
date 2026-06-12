# Android Cleartext HTTP Notes

If you want to allow HTTP traffic (non-HTTPS) to your local Streamlit server, ensure your Android app permits cleartext traffic.

For a full Android project, add this to your `AndroidManifest.xml`:

```xml
<application
    android:usesCleartextTraffic="true"
    ...>
</application>
```

If you are using HTTPS, you can omit this. For production, HTTPS is recommended.
