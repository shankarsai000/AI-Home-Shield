import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';

const String kBackendUrl = "http://192.168.1.50:8501"; // TODO: update to your backend

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const AiHomeShieldApp());
}

class AiHomeShieldApp extends StatelessWidget {
  const AiHomeShieldApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AI Home Shield',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const HomeShieldWebView(),
    );
  }
}

class HomeShieldWebView extends StatefulWidget {
  const HomeShieldWebView({super.key});

  @override
  State<HomeShieldWebView> createState() => _HomeShieldWebViewState();
}

class _HomeShieldWebViewState extends State<HomeShieldWebView> {
  late final WebViewController _controller;
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(
        NavigationDelegate(
          onPageFinished: (_) => setState(() => _isLoading = false),
          onWebResourceError: (error) {
            setState(() => _isLoading = false);
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('Failed to load: ${error.description}'),
              ),
            );
          },
        ),
      )
      ..loadRequest(Uri.parse(kBackendUrl));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('AI Home Shield'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () {
              setState(() => _isLoading = true);
              _controller.reload();
            },
          ),
        ],
      ),
      body: Stack(
        children: [
          WebViewWidget(controller: _controller),
          if (_isLoading)
            const Center(
              child: CircularProgressIndicator(),
            ),
        ],
      ),
    );
  }
}
