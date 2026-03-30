/**
 * Simple test class for REVENG Java bytecode analyzer
 */
public class HelloWorld {
    private String message;
    private int count;

    public HelloWorld() {
        this.message = "Hello, World!";
        this.count = 0;
    }

    public HelloWorld(String customMessage) {
        this.message = customMessage;
        this.count = 0;
    }

    public void sayHello() {
        System.out.println(this.message);
        this.count++;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getCount() {
        return this.count;
    }

    public static void main(String[] args) {
        HelloWorld hw = new HelloWorld();
        hw.sayHello();

        if (args.length > 0) {
            hw.setMessage(args[0]);
            hw.sayHello();
        }

        System.out.println("Total calls: " + hw.getCount());
    }
}
