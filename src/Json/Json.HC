// Small JSON reader: parse into a tree, extract with JsonGet("data.items[0].url"), pretty-print,
// and escape strings for request bodies. Strings are decoded to UTF-8; numbers keep their source text.
// Malformed input returns NULL and sets json_err to the byte offset.
#ifndef JSON_HC
#define JSON_HC

#define JSON_NULL      0
#define JSON_BOOL      1
#define JSON_NUM       2
#define JSON_STR       3
#define JSON_ARR       4
#define JSON_OBJ       5
#define JSON_MAX_DEPTH 64

class CJson
{
  I64 type;
  I64 n;              // BOOL: 0 or 1; ARR/OBJ: number of children
  U8 *str;            // STR: decoded text; NUM: source text
  U8 *key;            // set when this node is a member of an object
  CJson *first, *last, *next;
};

class CJsonP
{
  U8 *s;
  I64 pos, err;
};

class CJsonOut
{
  U8 *p;
  I64 n, cap;
};

I64 json_err = -1;
U8 *json_hex = "0123456789abcdef";

U0 JsonFree(CJson *j)
{
  CJson *c, *nx;
  if (!j)
    return;
  for (c = j->first; c; c = nx) {
    nx = c->next;
    JsonFree(c);
  }
  Free(j->str);
  Free(j->key);
  Free(j);
}

CJson *JsonNew(I64 type)
{
  CJson *j = CAlloc(sizeof(CJson));
  j->type = type;
  return j;
}

U0 JsonAppend(CJson *parent, CJson *c)
{
  if (parent->last)
    parent->last->next = c;
  else
    parent->first = c;
  parent->last = c;
  parent->n++;
}

U0 JsonSkipWs(CJsonP *p)
{
  while (p->s[p->pos] == ' ' || p->s[p->pos] == '\t' || p->s[p->pos] == '\r' || p->s[p->pos] == '\n')
    p->pos++;
}

CJson *JsonFail(CJsonP *p, CJson *partial)
{
  if (p->err < 0)
    p->err = p->pos;
  JsonFree(partial);
  return NULL;
}

I64 JsonPutUtf8(U8 *o, I64 cp)
{
  if (cp < 0x80) {
    o[0] = cp;
    return 1;
  }
  if (cp < 0x800) {
    o[0] = 0xC0 | (cp >> 6);
    o[1] = 0x80 | (cp & 0x3F);
    return 2;
  }
  if (cp < 0x10000) {
    o[0] = 0xE0 | (cp >> 12);
    o[1] = 0x80 | ((cp >> 6) & 0x3F);
    o[2] = 0x80 | (cp & 0x3F);
    return 3;
  }
  o[0] = 0xF0 | (cp >> 18);
  o[1] = 0x80 | ((cp >> 12) & 0x3F);
  o[2] = 0x80 | ((cp >> 6) & 0x3F);
  o[3] = 0x80 | (cp & 0x3F);
  return 4;
}

// 4 hex digits at s, -1 if any is not a hex digit.
I64 JsonHex4(U8 *s)
{
  I64 i, ch, v = 0;
  for (i = 0; i < 4; i++) {
    ch = s[i];
    if (ch >= '0' && ch <= '9')
      ch -= '0';
    else if (ch >= 'a' && ch <= 'f')
      ch -= 'a' - 10;
    else if (ch >= 'A' && ch <= 'F')
      ch -= 'A' - 10;
    else
      return -1;
    v = v * 16 + ch;
  }
  return v;
}

// p->s[p->pos] is the opening quote. Returns a heap string, NULL on error.
U8 *JsonParseStr(CJsonP *p)
{
  U8 *s = p->s, *out, *o;
  I64 i = p->pos + 1, ch, cp, lo;

  while (s[i] != '"') {
    if (s[i] < 0x20) {
      p->pos = i;
      p->err = i;
      return NULL;
    }
    if (s[i] == '\\') {
      if (!s[i + 1]) {
        p->pos = i;
        p->err = i;
        return NULL;
      }
      i++;
    }
    i++;
  }
  o = out = MAlloc(i - p->pos + 1);   // decoded text is never longer than the source
  i = p->pos + 1;
  while (s[i] != '"') {
    ch = s[i++];
    if (ch != '\\')
      *o++ = ch;
    else {
      ch = s[i++];
      switch (ch) {
        case '"':
        case '\\':
        case '/':
          *o++ = ch;
          break;
        case 'b':
          *o++ = 8;
          break;
        case 'f':
          *o++ = 12;
          break;
        case 'n':
          *o++ = '\n';
          break;
        case 'r':
          *o++ = '\r';
          break;
        case 't':
          *o++ = '\t';
          break;
        case 'u':
          cp = JsonHex4(s + i);
          if (cp < 0) {
            p->pos = i;
            p->err = i;
            Free(out);
            return NULL;
          }
          i += 4;
          if (cp >= 0xD800 && cp <= 0xDBFF && s[i] == '\\' && s[i + 1] == 'u' &&
                (lo = JsonHex4(s + i + 2)) >= 0xDC00 && lo <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + lo - 0xDC00;
            i += 6;
          } else if (!cp || (cp >= 0xD800 && cp <= 0xDFFF))
            cp = 0xFFFD;   // NUL and lone surrogates
          o += JsonPutUtf8(o, cp);
          break;
        default:
          p->pos = i - 1;
          p->err = i - 1;
          Free(out);
          return NULL;
      }
    }
  }
  *o = 0;
  p->pos = i + 1;
  return out;
}

Bool JsonIsDigit(I64 ch)
{
  return ch >= '0' && ch <= '9';
}

CJson *JsonParseNum(CJsonP *p)
{
  U8 *s = p->s;
  I64 i = p->pos;
  CJson *j;

  if (s[i] == '-')
    i++;
  if (s[i] == '0')
    i++;
  else if (JsonIsDigit(s[i]))
    while (JsonIsDigit(s[i]))
      i++;
  else
    return JsonFail(p, NULL);
  if (s[i] == '.') {
    i++;
    if (!JsonIsDigit(s[i])) {
      p->pos = i;
      return JsonFail(p, NULL);
    }
    while (JsonIsDigit(s[i]))
      i++;
  }
  if (s[i] == 'e' || s[i] == 'E') {
    i++;
    if (s[i] == '+' || s[i] == '-')
      i++;
    if (!JsonIsDigit(s[i])) {
      p->pos = i;
      return JsonFail(p, NULL);
    }
    while (JsonIsDigit(s[i]))
      i++;
  }
  j = JsonNew(JSON_NUM);
  j->str = MAlloc(i - p->pos + 1);
  MemCpy(j->str, s + p->pos, i - p->pos);
  j->str[i - p->pos] = 0;
  p->pos = i;
  return j;
}

CJson *JsonParseValue(CJsonP *p, I64 depth)
{
  U8 *s = p->s;
  CJson *j, *c;
  U8 *key;
  I64 endc;

  JsonSkipWs(p);
  switch (s[p->pos]) {
    case '{':
    case '[':
      if (depth >= JSON_MAX_DEPTH)
        return JsonFail(p, NULL);
      endc = '}';
      j = JsonNew(JSON_OBJ);
      if (s[p->pos] == '[') {
        endc = ']';
        j->type = JSON_ARR;
      }
      p->pos++;
      JsonSkipWs(p);
      if (s[p->pos] == endc) {
        p->pos++;
        return j;
      }
      while (TRUE) {
        key = NULL;
        if (j->type == JSON_OBJ) {
          JsonSkipWs(p);
          if (s[p->pos] != '"')
            return JsonFail(p, j);
          key = JsonParseStr(p);
          if (!key)
            return JsonFail(p, j);
          JsonSkipWs(p);
          if (s[p->pos] != ':') {
            Free(key);
            return JsonFail(p, j);
          }
          p->pos++;
        }
        c = JsonParseValue(p, depth + 1);
        if (!c) {
          Free(key);
          return JsonFail(p, j);
        }
        c->key = key;
        JsonAppend(j, c);
        JsonSkipWs(p);
        if (s[p->pos] == endc) {
          p->pos++;
          return j;
        }
        if (s[p->pos] != ',')
          return JsonFail(p, j);
        p->pos++;
      }
    case '"':
      j = JsonNew(JSON_STR);
      j->str = JsonParseStr(p);
      if (!j->str)
        return JsonFail(p, j);
      return j;
    case 't':
      if (StrNCmp(s + p->pos, "true", 4))
        return JsonFail(p, NULL);
      p->pos += 4;
      j = JsonNew(JSON_BOOL);
      j->n = 1;
      return j;
    case 'f':
      if (StrNCmp(s + p->pos, "false", 5))
        return JsonFail(p, NULL);
      p->pos += 5;
      return JsonNew(JSON_BOOL);
    case 'n':
      if (StrNCmp(s + p->pos, "null", 4))
        return JsonFail(p, NULL);
      p->pos += 4;
      return JsonNew(JSON_NULL);
    default:
      return JsonParseNum(p);
  }
}

// Parses a whole NUL-terminated document. Caller frees with JsonFree.
CJson *JsonParse(U8 *text)
{
  CJsonP p;
  CJson *j;
  p.s = text;
  p.pos = 0;
  p.err = -1;
  j = JsonParseValue(&p, 0);
  if (j) {
    JsonSkipWs(&p);
    if (text[p.pos])
      j = JsonFail(&p, j);
  }
  json_err = p.err;
  return j;
}

CJson *JsonKey(CJson *j, U8 *key)
{
  CJson *c;
  if (j && j->type == JSON_OBJ)
    for (c = j->first; c; c = c->next)
      if (!StrCmp(c->key, key))
        return c;
  return NULL;
}

CJson *JsonIdx(CJson *j, I64 idx)
{
  CJson *c;
  if (j && j->type == JSON_ARR)
    for (c = j->first; c; c = c->next)
      if (!idx--)
        return c;
  return NULL;
}

// Path like "data.items[0].url". NULL if any step is missing.
CJson *JsonGet(CJson *j, U8 *path)
{
  U8 key[128];
  I64 i, idx;
  while (j && *path) {
    if (*path == '[') {
      path++;
      if (!JsonIsDigit(*path))
        return NULL;
      for (idx = 0; JsonIsDigit(*path); path++)
        idx = idx * 10 + *path - '0';
      if (*path++ != ']')
        return NULL;
      j = JsonIdx(j, idx);
    } else {
      if (*path == '.')
        path++;
      for (i = 0; *path && *path != '.' && *path != '['; path++) {
        if (i >= 127)
          return NULL;
        key[i++] = *path;
      }
      if (!i)
        return NULL;
      key[i] = 0;
      j = JsonKey(j, key);
    }
  }
  return j;
}

// The decoded text of a string node, NULL for anything else.
U8 *JsonStr(CJson *j)
{
  if (j && j->type == JSON_STR)
    return j->str;
  return NULL;
}

// Integer part of a number node, 0 for anything else.
I64 JsonInt(CJson *j)
{
  I64 v = 0;
  U8 *s;
  if (!j || j->type != JSON_NUM)
    return 0;
  s = j->str;
  if (*s == '-')
    s++;
  while (JsonIsDigit(*s))
    v = v * 10 + *s++ - '0';
  if (j->str[0] == '-')
    return -v;
  return v;
}

// Returns the string as a quoted JSON string literal. Caller frees.
U8 *JsonEscape(U8 *s)
{
  U8 *out = MAlloc(StrLen(s) * 6 + 3), *o = out;
  I64 ch;
  *o++ = '"';
  while (ch = *s++) {
    switch (ch) {
      case '"':
        *o++ = '\\';
        *o++ = '"';
        break;
      case '\\':
        *o++ = '\\';
        *o++ = '\\';
        break;
      case '\n':
        *o++ = '\\';
        *o++ = 'n';
        break;
      case '\r':
        *o++ = '\\';
        *o++ = 'r';
        break;
      case '\t':
        *o++ = '\\';
        *o++ = 't';
        break;
      default:
        if (ch < 0x20) {
          StrPrint(o, "\\u00%c%c", json_hex[ch >> 4], json_hex[ch & 15]);
          o += 6;
        } else
          *o++ = ch;
    }
  }
  *o++ = '"';
  *o = 0;
  return out;
}

U0 JsonOutAdd(CJsonOut *o, U8 *s, I64 len)
{
  U8 *p;
  if (o->n + len + 1 > o->cap) {
    o->cap = (o->n + len + 1) * 2;
    p = MAlloc(o->cap);
    MemCpy(p, o->p, o->n);
    Free(o->p);
    o->p = p;
  }
  MemCpy(o->p + o->n, s, len);
  o->n += len;
  o->p[o->n] = 0;
}

U0 JsonOutStr(CJsonOut *o, U8 *s)
{
  JsonOutAdd(o, s, StrLen(s));
}

U0 JsonOutIndent(CJsonOut *o, I64 depth)
{
  while (depth--)
    JsonOutAdd(o, "  ", 2);
}

U0 JsonFmtNode(CJsonOut *o, CJson *j, I64 depth)
{
  CJson *c;
  U8 *e;
  switch (j->type) {
    case JSON_NULL:
      JsonOutStr(o, "null");
      break;
    case JSON_BOOL:
      if (j->n)
        JsonOutStr(o, "true");
      else
        JsonOutStr(o, "false");
      break;
    case JSON_NUM:
      JsonOutStr(o, j->str);
      break;
    case JSON_STR:
      e = JsonEscape(j->str);
      JsonOutStr(o, e);
      Free(e);
      break;
    default:
      if (!j->n) {
        if (j->type == JSON_ARR)
          JsonOutStr(o, "[]");
        else
          JsonOutStr(o, "{}");
        break;
      }
      if (j->type == JSON_ARR)
        JsonOutStr(o, "[\n");
      else
        JsonOutStr(o, "{\n");
      for (c = j->first; c; c = c->next) {
        JsonOutIndent(o, depth + 1);
        if (c->key) {
          e = JsonEscape(c->key);
          JsonOutStr(o, e);
          Free(e);
          JsonOutStr(o, ": ");
        }
        JsonFmtNode(o, c, depth + 1);
        if (c->next)
          JsonOutStr(o, ",");
        JsonOutStr(o, "\n");
      }
      JsonOutIndent(o, depth);
      if (j->type == JSON_ARR)
        JsonOutStr(o, "]");
      else
        JsonOutStr(o, "}");
  }
}

// Pretty-printed text, 2-space indent. Caller frees.
U8 *JsonFmt(CJson *j)
{
  CJsonOut o;
  o.p = NULL;
  o.n = o.cap = 0;
  JsonOutAdd(&o, "", 0);
  JsonFmtNode(&o, j, 0);
  return o.p;
}

// Prints to the screen. The dollar sign is doubled (char 36) because Print treats it as a DolDoc escape.
U0 JsonPrint(CJson *j)
{
  U8 *s = JsonFmt(j), *p;
  for (p = s; *p; p++) {
    if (*p == 36)
      Print("%c%c", 36, 36);
    else
      Print("%c", *p);
  }
  Print("\n");
  Free(s);
}

#endif
