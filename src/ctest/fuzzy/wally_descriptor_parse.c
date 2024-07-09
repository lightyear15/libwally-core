#include "wally_descriptor.h"
#include "wally_address.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *string = malloc(size + 1);
    if (string == NULL) {
        return 0;
    }
    memcpy(string, data, size);
    string[size] = '\0';

    struct wally_descriptor *output = NULL;

    wally_descriptor_parse(string, NULL, WALLY_NETWORK_NONE, WALLY_MINISCRIPT_ONLY, &output);
    wally_descriptor_free(output);
    output = NULL;

    wally_descriptor_parse(string, NULL, WALLY_NETWORK_NONE, WALLY_MINISCRIPT_TAPSCRIPT, &output);
    wally_descriptor_free(output);
    output = NULL;

    wally_descriptor_parse(string, NULL, WALLY_NETWORK_NONE, WALLY_MINISCRIPT_REQUIRE_CHECKSUM, &output);
    wally_descriptor_free(output);
    output = NULL;

    free(string);
    return 0;
}
