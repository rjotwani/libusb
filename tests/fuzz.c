// Dummy file to figure out how to run tests

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "libusb.h"

int LLVMFuzzerTestOneInput(uint8_t* data, size_t size);

int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
  struct libusb_transfer* transfer;
  assert(data[0] != 0);
  return 0;
}

int main(int argc, char **argv) {
  printf("test\n");
  return 0;
}
