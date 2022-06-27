#ifndef _HMAC_SHA512_H_
#define _HMAC_SHA512_H_

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>

std::string  
hmac_sha512(
    // [in]: The key and its length.
    //      Should be at least 32 bytes long for optimal security.
    const std::string key,
    const std::string data);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // _HMAC_SHA512_H_
