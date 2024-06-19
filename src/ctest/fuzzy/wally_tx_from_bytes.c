#include "wally_transaction.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  struct wally_tx *tx = NULL;
  int result = WALLY_OK;

  result = wally_tx_from_bytes(data, size, WALLY_TX_FLAG_ALLOW_PARTIAL, &tx);
  if (result == WALLY_OK) {
    wally_tx_free(tx);
    return -1;
  }

  result = wally_tx_from_bytes(data, size, WALLY_TX_FLAG_PRE_BIP144, &tx);
  if (result == WALLY_OK) {
    wally_tx_free(tx);
    return -1;
  }

  result = wally_tx_from_bytes(data, size, WALLY_TX_FLAG_USE_ELEMENTS, &tx);
  if (result == WALLY_OK) {
    wally_tx_free(tx);
    return -1;
  }

  result = wally_tx_from_bytes(
      data, size, WALLY_TX_FLAG_ALLOW_PARTIAL | WALLY_TX_FLAG_PRE_BIP144, &tx);
  if (result == WALLY_OK) {
    wally_tx_free(tx);
    return -1;
  }

  result = wally_tx_from_bytes(
      data, size, WALLY_TX_FLAG_ALLOW_PARTIAL | WALLY_TX_FLAG_USE_ELEMENTS,
      &tx);
  if (result == WALLY_OK) {
    wally_tx_free(tx);
    return -1;
  }

  result = wally_tx_from_bytes(data, size,
                               WALLY_TX_FLAG_ALLOW_PARTIAL |
                                   WALLY_TX_FLAG_USE_ELEMENTS |
                                   WALLY_TX_FLAG_PRE_BIP144,
                               &tx);
  if (result == WALLY_OK) {
    wally_tx_free(tx);
    return -1;
  }

  return 0;
}
