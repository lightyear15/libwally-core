#include "wally_bip32.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ext_key key;
  int res = bip32_key_unserialize(data, size, &key);
  if (res == WALLY_OK) {
    return -1;
  }

  return 0;
}
