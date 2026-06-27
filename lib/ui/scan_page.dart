import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../core/otpauth_uri.dart';
import '../data/account.dart';

/// Live-camera + gallery QR scanner. Pops a validated [Account] on success.
///
/// Every decoded payload is treated as attacker-controlled and run through
/// [OtpauthUri.parseToAccount], which bounds and validates every field.
class ScanPage extends StatefulWidget {
  const ScanPage({super.key});

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> {
  final MobileScannerController _controller = MobileScannerController(
    formats: const [BarcodeFormat.qrCode],
  );
  bool _handled = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_handled) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw != null && raw.isNotEmpty) {
        _tryAccept(raw);
        return;
      }
    }
  }

  void _tryAccept(String raw) {
    try {
      final account = OtpauthUri.parseToAccount(raw);
      _handled = true;
      Navigator.of(context).pop<Account>(account);
    } on OtpauthParseException catch (e) {
      setState(() => _error = e.message);
    }
  }

  Future<void> _fromGallery() async {
    final picker = ImagePicker();
    final file = await picker.pickImage(source: ImageSource.gallery);
    if (file == null) return;
    final result = await _controller.analyzeImage(file.path);
    if (!mounted) return;
    final raw = result?.barcodes
        .map((b) => b.rawValue)
        .firstWhere((v) => v != null && v.isNotEmpty, orElse: () => null);
    if (raw == null) {
      setState(() => _error = 'No QR code found in that image.');
      return;
    }
    _tryAccept(raw);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan QR code'),
        actions: [
          IconButton(
            tooltip: 'Import from gallery',
            icon: const Icon(Icons.photo_library_outlined),
            onPressed: _fromGallery,
          ),
        ],
      ),
      body: Stack(
        children: [
          MobileScanner(controller: _controller, onDetect: _onDetect),
          if (_error != null)
            Positioned(
              left: 16,
              right: 16,
              bottom: 32,
              child: Material(
                color: Theme.of(context).colorScheme.errorContainer,
                borderRadius: BorderRadius.circular(8),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    _error!,
                    style: TextStyle(
                        color:
                            Theme.of(context).colorScheme.onErrorContainer),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
