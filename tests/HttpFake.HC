// In-memory CConn for tests: serves canned bytes (optionally in tiny fragments), records writes.
#include "B:/src/Net/Conn"

class CFake
{
  U8 *data;
  I64 len, pos, frag;
  U8 wbuf[2048];
  I64 wlen;
};

I64 FakeRead(CConn *c, U8 *buf, I64 len)
{
  CFake *f = c->priv;
  I64 n = f->len - f->pos;
  if (n <= 0)
    return 0;
  if (f->frag && n > f->frag)
    n = f->frag;
  if (n > len)
    n = len;
  MemCpy(buf, f->data + f->pos, n);
  f->pos += n;
  return n;
}

I64 FakeWrite(CConn *c, U8 *buf, I64 len)
{
  CFake *f = c->priv;
  if (f->wlen + len > 2047)
    return -1;
  MemCpy(f->wbuf + f->wlen, buf, len);
  f->wlen += len;
  f->wbuf[f->wlen] = 0;
  return len;
}

U0 FakeClose(CConn *c)
{
  Free(c->priv);
  Free(c);
}

CConn *FakeNew(U8 *data, I64 len, I64 frag)
{
  CConn *c = CAlloc(sizeof(CConn));
  CFake *f = CAlloc(sizeof(CFake));
  f->data = data;
  f->len = len;
  f->frag = frag;
  c->priv = f;
  c->read = &FakeRead;
  c->write = &FakeWrite;
  c->close = &FakeClose;
  return c;
}
