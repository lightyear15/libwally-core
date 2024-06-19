#include "wally_bip32.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(uint32_t) * 2) {
    return 0;
  }
  const uint8_t *ptr = data;
  size_t ptr_len = size;
  struct ext_key key;
  const uint32_t *version = (const uint32_t *)ptr;
  ptr += sizeof(uint32_t);
  ptr_len -= sizeof(uint32_t);
  const uint32_t *flags = (const uint32_t *)ptr;
  ptr += sizeof(uint32_t);
  ptr_len -= sizeof(uint32_t);
  int res = bip32_key_from_seed(ptr, ptr_len, *version, *flags, &key);
  if (res == WALLY_OK) {
    return -1;
  }
  return 0;
}
