package org.example;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

public class IPv4UniqueCounter {
    private static final int BITSET_SIZE = 1 << 26; // Размер битовой карты
    private static final long[] bitmap = new long[BITSET_SIZE]; // Хранилище для уникальных IP-адресов
    private static long uniqueCount = 0; // Счетчик уникальных IP
    private static long processedCount = 0; // Общее количество обработанных IP

    private static final long CHUNK_SIZE = 256L * 1024 * 1024; // Размер маппируемого блока файла (256MB)
    private static final byte LF = 0xA; // Символ перевода строки
    private static final byte CR = 0xD; // Символ возврата каретки

    public static void main(String[] args) throws IOException {

        String path = args[0];
        long startTime = System.currentTimeMillis();

        try (RandomAccessFile raf = new RandomAccessFile(path, "r");
             FileChannel channel = raf.getChannel()) {

            long fileSize = channel.size();
            long offset = 0;
            byte[] remainder = new byte[0];

            while (offset < fileSize) {
                long remainingFile = fileSize - offset;
                long mapSize = Math.min(CHUNK_SIZE, remainingFile);

                MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, offset, mapSize);
                int bufferLimit = buffer.limit();
                int position = 0;

                // Если осталась часть строки с прошлого чанка, обработаем её
                if (remainder.length > 0) {
                    int newLinePos = findNewLine(buffer);
                    if (newLinePos != -1) {
                        processCombined(buffer, remainder, newLinePos);
                        processedCount++;
                        remainder = new byte[0];
                        position = newLinePos + 1;
                    } else {
                        remainder = combine(remainder, buffer, 0, bufferLimit);
                        offset += mapSize;
                        continue;
                    }
                }

                buffer.position(position);
                int lineStart = position;
                while (buffer.hasRemaining()) {
                    if (buffer.get() == LF) {
                        int lineEnd = buffer.position() - 1;
                        processLine(buffer, lineStart, lineEnd);
                        processedCount++;
                        printProgress(startTime);
                        lineStart = buffer.position();
                    }
                }

                // Сохраняем остаток строки, если он есть
                if (lineStart < buffer.limit()) {
                    remainder = combine(remainder, buffer, lineStart, buffer.limit());
                }
                offset += mapSize;
            }

            // Обрабатываем последнюю оставшуюся строку
            if (remainder.length > 0) {
                processLine(remainder);
            }
        }

        printSummary(startTime);
    }

    private static void printProgress(long startTime) {
        if (processedCount % 1_000_000_000 == 0) {
            long elapsed = System.currentTimeMillis() - startTime;
            System.out.println("Обработано " + processedCount + " IP-адресов. Время: " + (elapsed / 1000.0) + " сек.");
        }
    }
    private static void printSummary(long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        System.out.println("Уникальных IP: " + uniqueCount);
        System.out.println("Общее время: " + (totalTime / 1000.0) + " сек.");
    }

    private static int findNewLine(MappedByteBuffer buffer) {
        for (int i = 0; i < buffer.limit(); i++) {
            if (buffer.get(i) == LF) {
                return i;
            }
        }
        return -1;
    }
    private static byte[] combine(byte[] prefix, MappedByteBuffer buf, int from, int to) {
        byte[] suffix = new byte[to - from];
        buf.position(from);
        buf.get(suffix);
        return combine(prefix, suffix);
    }

    private static byte[] combine(byte[] prefix, byte[] suffix) {
        byte[] combined = new byte[prefix.length + suffix.length];
        System.arraycopy(prefix, 0, combined, 0, prefix.length);
        System.arraycopy(suffix, 0, combined, prefix.length, suffix.length);
        return combined;
    }

    private static void processCombined(MappedByteBuffer buf, byte[] prefix, int newLinePos) {
        byte[] combined = new byte[prefix.length + newLinePos];
        System.arraycopy(prefix, 0, combined, 0, prefix.length);
        buf.position(0);
        buf.get(combined, prefix.length, newLinePos);
        processLine(combined);
    }

    private static void processLine(byte[] lineBytes) {
        int i = 0;
        int end = lineBytes.length;
        long ip = 0;

        ip = parseOctet(lineBytes, i, end);
        i = nextDot(lineBytes, i, end) + 1;

        ip = (ip << 8) | parseOctet(lineBytes, i, end);
        i = nextDot(lineBytes, i, end) + 1;

        ip = (ip << 8) | parseOctet(lineBytes, i, end);
        i = nextDot(lineBytes, i, end) + 1;

        ip = (ip << 8) | parseOctet(lineBytes, i, end);

        int bucket = (int) ((ip >>> 6) & 0x03FFFFFF);
        long mask = 1L << (ip & 0x3F);
        if ((bitmap[bucket] & mask) == 0) {
            bitmap[bucket] |= mask;
            uniqueCount++;
        }
    }

    private static void processLine(MappedByteBuffer buf, int start, int end) {
        int i = start;
        long ip = 0;

        ip = parseOctet(buf, i, end);
        i = nextDot(buf, i, end) + 1;

        ip = (ip << 8) | parseOctet(buf, i, end);
        i = nextDot(buf, i, end) + 1;

        ip = (ip << 8) | parseOctet(buf, i, end);
        i = nextDot(buf, i, end) + 1;

        ip = (ip << 8) | parseOctet(buf, i, end);

        int bucket = (int) ((ip >>> 6) & 0x03FFFFFF);
        long mask = 1L << (ip & 0x3F);
        if ((bitmap[bucket] & mask) == 0) {
            bitmap[bucket] |= mask;
            uniqueCount++;
        }
    }

    private static int parseOctet(byte[] bytes, int start, int end) {
        int octet = 0;
        for (int i = start; i < end; i++) {
            byte b = bytes[i];
            if (b == '.' || b == CR || b == LF) break;
            octet = octet * 10 + (b - '0');
        }
        return octet;
    }

    private static int parseOctet(MappedByteBuffer buf, int start, int end) {
        int octet = 0;
        for (int i = start; i < end; i++) {
            byte b = buf.get(i);
            if (b == '.' || b == CR || b == LF) break;
            octet = octet * 10 + (b - '0');
        }
        return octet;
    }

    private static int nextDot(byte[] bytes, int start, int end) {
        for (int i = start; i < end; i++) {
            if (bytes[i] == '.') return i;
        }
        return end;
    }

    private static int nextDot(MappedByteBuffer buf, int start, int end) {
        for (int i = start; i < end; i++) {
            if (buf.get(i) == '.') return i;
        }
        return end;
    }
}