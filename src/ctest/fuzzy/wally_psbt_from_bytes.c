#include "wally_psbt.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  struct wally_psbt *psbt = NULL;
  int result = WALLY_OK;

  result = wally_psbt_from_bytes(data, size, 0, &psbt);
  if (result == WALLY_OK) {
    wally_psbt_free(psbt);
    return -1;
  }

  result = wally_psbt_from_bytes(data, size, WALLY_PSBT_PARSE_FLAG_STRICT, &psbt);
  if (result == WALLY_OK) {
    wally_psbt_free(psbt);
    return -1;
  }

  return 0;
}
