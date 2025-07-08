#include <stdio.h>
#include <stdint.h>

void busy_wait(uint32_t seconds) {
    // wait for an input character
    // volatile uint32_t count = 0;
    // uint32_t end = seconds * 10000000000; // Adjust this value as needed for your platform
    int count = 0, end = 10;
    char c;
    while (count < end) {
      fflush(stdin);
      getchar();
      printf(".");
    }
}

int main()
{
  printf("hello, world!\n");
  printf("Waiting...");
  busy_wait(4);
  printf("\ngoodbye, world!\n");
  return 0;
}