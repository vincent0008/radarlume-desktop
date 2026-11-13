package io.radarlume.process;

public final class ProcessFixture {
    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "echo" -> System.out.print(args[1]);
            case "sleep" -> Thread.sleep(30_000);
            case "flood" -> { for (int i = 0; i < 200_000; i++) System.err.print("x"); }
            case "fail" -> { System.out.print("partial"); System.exit(7); }
            default -> throw new IllegalArgumentException();
        }
    }
}
