import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// ─────────────────────────────────────────────────────────────
/// Public API (UNCHANGED)
/// ─────────────────────────────────────────────────────────────
abstract class DecryptHelpers {
  /// Stream AES-CTR decryption helper (seekable).
  static Stream<List<int>> openDecryptRead(
    File encryptedFile,
    String base64Key, [
    int? start,
    int? end,
  ]) {
    return _DecryptWorker.instance.decrypt(
      encryptedFile,
      base64Key,
      start ?? 0,
      end,
    );
  }
}

/// ─────────────────────────────────────────────────────────────
/// Internal persistent worker (NEW, PRIVATE)
/// ─────────────────────────────────────────────────────────────
class _DecryptWorker {
  _DecryptWorker._();
  static final instance = _DecryptWorker._();

  Isolate? _isolate;
  SendPort? _sendPort;
  final _ready = Completer<void>();

  File? _currentFile;
  String? _currentKey;

  Future<void> _init() async {
    if (_isolate != null) {
      return;
    }

    final receivePort = ReceivePort();
    _isolate = await Isolate.spawn(
      _decryptIsolateMain,
      receivePort.sendPort,
    );

    _sendPort = await receivePort.first as SendPort;
    _ready.complete();
  }

  Stream<List<int>> decrypt(
    File file,
    String base64Key,
    int start,
    int? end,
  ) {
    final controller = StreamController<List<int>>();

    () async {
      await _init();

      // Open file only if changed
      if (_currentFile?.path != file.path || _currentKey != base64Key) {
        _currentFile = file;
        _currentKey = base64Key;
        _sendPort!.send(_OpenFileCmd(file.path, base64Key));
      }

      final replyPort = ReceivePort();
      _sendPort!.send(
        _DecryptCmd(start, end, replyPort.sendPort),
      );

      await for (final msg in replyPort) {
        if (msg == null) {
          replyPort.close();
          await controller.close();
          break;
        }
        controller.add(msg as List<int>);
      }
    }();

    return controller.stream;
  }
}

/// ─────────────────────────────────────────────────────────────
/// Isolate main
/// ─────────────────────────────────────────────────────────────
Future<void> _decryptIsolateMain(SendPort mainPort) async {
  final commandPort = ReceivePort();
  mainPort.send(commandPort.sendPort);

  RandomAccessFile? raf;
  Uint8List? key;
  Uint8List? iv;
  int? payloadLength;

  await for (final cmd in commandPort) {
    if (cmd is _OpenFileCmd) {
      await raf?.close();

      final file = File(cmd.path);
      raf = await file.open();

      key = base64.decode(cmd.base64Key);
      if (key.length != 16 && key.length != 32) {
        throw ArgumentError('Invalid AES key length');
      }

      iv = await raf.read(16);
      payloadLength = (await raf.length()) - 16;
    }

    if (cmd is _DecryptCmd) {
      if (raf == null || iv == null || key == null) {
        cmd.reply.send(null);
        continue;
      }

      final effectiveEnd = cmd.end ?? (payloadLength! - 1);

      await _decryptRange(
        raf,
        key,
        iv,
        cmd.start,
        effectiveEnd,
        cmd.reply,
      );
    }
  }
}

/// ─────────────────────────────────────────────────────────────
/// Decryption logic (same as original, optimized placement)
/// ─────────────────────────────────────────────────────────────
Future<void> _decryptRange(
  RandomAccessFile raf,
  Uint8List key,
  Uint8List iv,
  int start,
  int end,
  SendPort out,
) async {
  const blockSize = 16;

  final blockIndex = start ~/ blockSize;
  final blockOffset = start % blockSize;

  final counter = Uint8List.fromList(iv);
  _incrementCounter(counter, blockIndex);

  final cipher = StreamCipher('AES/CTR')
    ..init(
      false,
      ParametersWithIV(KeyParameter(key), counter),
    );

  await raf.setPosition(16 + start);

  if (blockOffset > 0) {
    cipher.process(Uint8List(blockOffset));
  }

  final buffer = Uint8List(64 * 1024);
  var pos = start;

  while (pos <= end) {
    final remaining = end - pos + 1;
    final read = await raf.readInto(
      buffer,
      0,
      remaining > buffer.length ? buffer.length : remaining,
    );

    if (read == 0) {
      break;
    }

    out.send(cipher.process(buffer.sublist(0, read)));
    pos += read;
  }

  out.send(null);
}

/// CTR counter increment (big-endian)
void _incrementCounter(Uint8List counter, int blocks) {
  var carry = blocks;
  for (var i = counter.length - 1; i >= 0; i--) {
    final sum = counter[i] + (carry & 0xff);
    counter[i] = sum & 0xff;
    carry = (carry >> 8) + (sum >> 8);
    if (carry == 0) {
      break;
    }
  }
}

/// ─────────────────────────────────────────────────────────────
/// Commands (PRIVATE)
/// ─────────────────────────────────────────────────────────────
class _OpenFileCmd {
  _OpenFileCmd(this.path, this.base64Key);
  final String path;
  final String base64Key;
}

class _DecryptCmd {
  _DecryptCmd(this.start, this.end, this.reply);
  final int start;
  final int? end;
  final SendPort reply;
}
