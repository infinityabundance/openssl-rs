/* TEST-ONLY TIMECOP control: deliberately variable-time early-exit compare. */
#include "crypto_verify.h"
int crypto_verify(const unsigned char *x,const unsigned char *y) {
  int i;
  for (i = 0;i < 16;++i) if (x[i] != y[i]) return -1;
  return 0;
}
