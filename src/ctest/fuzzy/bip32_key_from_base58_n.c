#include "wally_bip32.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char *string = (const char *)data;
  struct ext_key key;
  int res = bip32_key_from_base58_n(string, size, &key);
  if (res == WALLY_OK) {
    return -1;
  }
  return 0;
}
