// Minimal test helpers: ASSERT-style checks that report over the serial channel.
#include "B:/src/Util/Ser"

I64 test_fail = 0, test_pass = 0;

U0 TestCheck(Bool ok, U8 *what)
{
  if (ok)
    test_pass++;
  else {
    test_fail++;
    SerPrint("FAIL: %s\n", what);
  }
}

U0 TestBytes(U8 *got, U8 *want, I64 n, U8 *what)
{
  TestCheck(!MemCmp(got, want, n), what);
}

U0 TestDone()
{
  SerPrint("passed %d\n", test_pass);
  SerPrint("TOS-DONE fail=%d\n", test_fail);
}
