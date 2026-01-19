import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

/// Stream AES-CTR decryption helper (seekable).
abstract class DecryptHelpers {
  /// The same Base64 key used for encryption must be provided for decryption.
  /// File must be encrypted file which is downloaded with encryption key
  static Stream<List<int>> openDecryptRead(
    File encryptedFile,
    String base64Key, [
    int? start,
    int? end,
  ]) async* {
    final key = base64.decode(base64Key);
    // Validate Key Length (AES-128 = 16, AES-256 = 32)
    if (key.length != 16 && key.length != 32) {
      throw ArgumentError('Invalid key length: ${key.length}');
    }

    final raf = await encryptedFile.open();

    try {
      final fileLength = await raf.length();

      // skip nounce iv
      if (fileLength < 16) {
        throw StateError('File too short to contain IV');
      }

      final iv = await raf.read(16);

      final effectiveStart = start ?? 0;
      final payloadLength = fileLength - 16;
      final effectiveEnd = end ?? (payloadLength - 1);

      if (effectiveStart > effectiveEnd) {
        return; // Empty range
      }

      const blockSize = 16;
      final blockIndex = effectiveStart ~/ blockSize;
      final blockOffset = effectiveStart % blockSize;

      final counter = Uint8List.fromList(iv);
      _incrementCounter(counter, blockIndex);

      final cipher = StreamCipher('AES/CTR')
        ..init(
          false, // for decrypt
          ParametersWithIV(
            KeyParameter(Uint8List.fromList(key)),
            counter,
          ),
        );

      await raf.setPosition(16 + effectiveStart);

      if (blockOffset > 0) {
        // Encrypting zeros generates the keystream.
        // We discard the result, but the cipher state advances.
        cipher.process(Uint8List(blockOffset));
      }

      final buffer = Uint8List(64 * 1024);
      var currentPosition = effectiveStart;

      while (currentPosition <= effectiveEnd) {
        final remaining = effectiveEnd - currentPosition + 1;
        final toRead = remaining > buffer.length ? buffer.length : remaining;

        final readBytes = await raf.readInto(buffer, 0, toRead);
        if (readBytes == 0) {
          break;
        }

        yield cipher.process(buffer.sublist(0, readBytes));

        currentPosition += readBytes;
      }
    } finally {
      await raf.close();
    }
  }

  /// Increments the CTR counter (treating the 16-byte array as a Big Endian integer).
  static void _incrementCounter(Uint8List counter, int blocks) {
    if (blocks == 0) {
      return;
    }

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
}
