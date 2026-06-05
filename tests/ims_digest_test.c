#include "../src/ims_service/ims_digest.h"

#include <assert.h>
#include <string.h>

int main(void)
{
    char md5[33];
    char resp[33];
    const char *password = "Circle Of Life";

    ims_md5_hex((const unsigned char *)"abc", 3, md5);
    assert(!strcmp(md5, "900150983cd24fb0d6963f7d28e17f72"));

    assert(ims_digest_md5_response(resp,
                                   "Mufasa",
                                   "testrealm@host.com",
                                   (const unsigned char *)password,
                                   strlen(password),
                                   "GET",
                                   "/dir/index.html",
                                   "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                                   "00000001",
                                   "0a4f113b",
                                   "auth") == 0);
    assert(!strcmp(resp, "6629fae49393a05397450978507c4ef1"));
    return 0;
}
