/**
 * Obfuscated test class simulating ProGuard output
 * This demonstrates obfuscation detection
 */
public class a {
    private String a;
    private int b;

    public a() {
        this.a = "Obfuscated message";
        this.b = 0;
    }

    public a(String paramString) {
        this.a = paramString;
        this.b = 0;
    }

    public void a() {
        System.out.println(this.a);
        this.b++;
    }

    public String b() {
        return this.a;
    }

    public void a(String paramString) {
        this.a = paramString;
    }

    public int c() {
        return this.b;
    }

    public static void main(String[] args) {
        a localA = new a();
        localA.a();

        if (args.length > 0) {
            localA.a(args[0]);
            localA.a();
        }

        System.out.println("Total calls: " + localA.c());
    }
}
