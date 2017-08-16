package be.crydust.fernet;

public final class Helper {
    private Helper() {
        // NOOP
    }

    static String repeat(String s, int times) {
        final StringBuilder sb = new StringBuilder(s.length() * times);
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}
