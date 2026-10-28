// Serial channel to the test harness (COM1). Only used by tests and the lab.

U0 SerPutS(U8 *s)
{
  while (*s) {
    while (!(InU8(0x3FD) & 0x20))
      Yield;
    OutU8(0x3F8, *s++);
  }
}

U0 SerPrint(U8 *fmt, ...)
{
  U8 *s = StrPrintJoin(NULL, fmt, argc, argv);
  SerPutS(s);
  Free(s);
}
