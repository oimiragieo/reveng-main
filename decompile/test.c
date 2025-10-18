#include <stdio.h>
#include <string.h>

// Simple function to demonstrate decompilation
int add(int a, int b) {
    return a + b;
}

// Function with string manipulation
void greet(const char* name) {
    printf("Hello, %s!\n", name);
}

// Function with conditional logic
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

int main() {
    printf("REVENG Test Binary\n");
    printf("==================\n\n");

    // Test arithmetic
    int result = add(5, 3);
    printf("5 + 3 = %d\n", result);

    // Test string handling
    greet("REVENG User");

    // Test recursion
    int fact = factorial(5);
    printf("Factorial of 5 = %d\n", fact);

    return 0;
}
