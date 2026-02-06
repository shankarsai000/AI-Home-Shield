# AI Home Shield Mobile App (Flutter WebView)

This lightweight mobile wrapper embeds the existing Streamlit UI inside a native Flutter app using a WebView. The backend still runs `app.py` (locally on your network or hosted), while the mobile app provides a native shell for iOS/Android.

## Prerequisites
- **Flutter SDK** (3.x)
- **Android Studio** or **Xcode** for device simulators
- A reachable **Streamlit backend URL** (see below)

## 1) Run the backend
From the repo root:

```bash
pip install -r requirements.txt
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```

Find your machine's LAN IP (e.g. `192.168.1.50`). The mobile device must be on the same network.

## 2) Configure the mobile app
Edit `lib/main.dart` and set `kBackendUrl` to your Streamlit URL:

```dart
const String kBackendUrl = "http://192.168.1.50:8501";
```

## 3) Run the mobile app

```bash
cd mobile_app
flutter pub get
flutter run
```

## Notes
- For **iOS**, ensure the backend is reachable via HTTP (or use HTTPS with proper certificates). You may need to add ATS exceptions in `Info.plist` if using HTTP.
- For **Android**, cleartext HTTP is allowed in the provided manifest, but you can switch to HTTPS for production.
- This wrapper does not modify the backend—it's a native shell around the existing Streamlit UI.

## Production options
- Host the backend on a VPS or home server and point `kBackendUrl` to that URL.
- Add native features like push notifications or device health checks in Flutter as future enhancements.
