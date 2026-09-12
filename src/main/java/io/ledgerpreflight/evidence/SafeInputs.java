package io.ledgerpreflight.evidence;

import java.io.*;
import java.nio.file.*;

/** Bounded reads, with every existing path component checked for symlinks. */
public final class SafeInputs {
    public static final int MAX_TEXT_BYTES = 8 * 1024 * 1024;
    private SafeInputs() { }
    public static void checkPath(Path path) throws IOException {
        Path absolute = path.toAbsolutePath().normalize();
        for (Path p = absolute; p != null; p = p.getParent())
            if (Files.isSymbolicLink(p)) throw new IOException("Symbolic links are not accepted as evidence");
        if (!Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Evidence must be a regular file");
    }
    public static byte[] read(Path path, int limit) throws IOException {
        checkPath(path);
        try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { return bounded(in, limit); }
    }
    public static byte[] bounded(InputStream in, int limit) throws IOException {
        byte[] bytes = in.readNBytes(limit + 1);
        if (bytes.length > limit) throw new IOException("Evidence size limit exceeded");
        return bytes;
    }
}
