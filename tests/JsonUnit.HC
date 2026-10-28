#include "B:/tests/Test"
#include "B:/src/Json/Json"

U0 CheckBad(U8 *text, U8 *what)
{
  CJson *j = JsonParse(text);
  TestCheck(!j && json_err >= 0, what);
  JsonFree(j);
}

U0 CheckStr(CJson *root, U8 *path, U8 *want, U8 *what)
{
  U8 *s = JsonStr(JsonGet(root, path));
  TestCheck(s && !StrCmp(s, want), what);
}

U0 CheckEsc(U8 *in, U8 *want, U8 *what)
{
  U8 *e = JsonEscape(in);
  TestCheck(!StrCmp(e, want), what);
  Free(e);
}

U0 Main()
{
  CJson *j;
  U8 *s, *deep;
  I64 i;

  j = JsonParse(" {\"data\": {\"items\": [ {\"url\":\"https://x.y/a\",\"n\":-42,\"ok\":true,\"no\":false,\"nil\":null},"
        " {\"url\":\"b\", \"f\": 1.5e3} ], \"empty\": [], \"eo\": {}}, \"s\": \"a\\\"b\\\\c\\/d\\n\\t\\u00e9\\u20ac\\ud83d\\ude00\"} ");
  TestCheck(j && j->type == JSON_OBJ && j->n == 2, "parse object");
  CheckStr(j, "data.items[0].url", "https://x.y/a", "path string");
  CheckStr(j, "data.items[1].url", "b", "path index 1");
  TestCheck(JsonInt(JsonGet(j, "data.items[0].n")) == -42, "negative int");
  TestCheck(JsonGet(j, "data.items[0].ok")->type == JSON_BOOL && JsonGet(j, "data.items[0].ok")->n == 1, "true");
  TestCheck(JsonGet(j, "data.items[0].no")->n == 0, "false");
  TestCheck(JsonGet(j, "data.items[0].nil")->type == JSON_NULL, "null");
  TestCheck(!StrCmp(JsonGet(j, "data.items[1].f")->str, "1.5e3"), "number text kept");
  TestCheck(JsonGet(j, "data.items")->n == 2 && JsonGet(j, "data.empty")->n == 0, "counts");
  TestCheck(!JsonGet(j, "data.items[2]") && !JsonGet(j, "data.nope") && !JsonGet(j, "data.items[x]") &&
        !JsonGet(j, "data..items") && !JsonGet(j, "s.x") && !JsonStr(JsonGet(j, "data")), "missing paths");
  TestCheck(JsonGet(j, "") == j, "empty path is root");
  CheckStr(j, "s", "a\"b\\c/d\n\t\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80", "escapes and unicode");
  s = JsonFmt(JsonGet(j, "data.items[1]"));
  TestCheck(!StrCmp(s, "{\n  \"url\": \"b\",\n  \"f\": 1.5e3\n}"), "fmt object");
  Free(s);
  s = JsonFmt(JsonGet(j, "data"));
  TestCheck(!StrCmp(s, "{\n  \"items\": [\n    {\n      \"url\": \"https://x.y/a\",\n      \"n\": -42,\n      \"ok\": true,\n"
        "      \"no\": false,\n      \"nil\": null\n    },\n    {\n      \"url\": \"b\",\n      \"f\": 1.5e3\n    }\n  ],\n"
        "  \"empty\": [],\n  \"eo\": {}\n}"), "fmt nested");
  Free(s);
  JsonFree(j);

  j = JsonParse("[1,[2,[3]],\"x\"]");
  TestCheck(j && JsonInt(JsonGet(j, "[1][1][0]")) == 3 && !StrCmp(JsonStr(JsonGet(j, "[2]")), "x"), "array paths");
  JsonFree(j);
  j = JsonParse("\"\\ud800x\\udc00\\u0000\"");
  TestCheck(j && !StrCmp(j->str, "\xEF\xBF\xBDx\xEF\xBF\xBD\xEF\xBF\xBD"), "lone surrogates and NUL become U+FFFD");
  JsonFree(j);
  j = JsonParse("0");
  TestCheck(j && j->type == JSON_NUM, "bare number");
  JsonFree(j);
  j = JsonParse("{\"a\":1,\"a\":2}");
  TestCheck(j && JsonInt(JsonGet(j, "a")) == 1, "duplicate key: first wins");
  JsonFree(j);

  CheckBad("", "empty");
  CheckBad("   ", "blank");
  CheckBad("{", "open object");
  CheckBad("[1,", "open array");
  CheckBad("[1,]", "trailing comma array");
  CheckBad("{\"a\":1,}", "trailing comma object");
  CheckBad("{\"a\":}", "missing value");
  CheckBad("{\"a\" 1}", "missing colon");
  CheckBad("{a:1}", "unquoted key");
  CheckBad("{'a':1}", "single quotes");
  CheckBad("tru", "short literal");
  CheckBad("nulL", "bad literal");
  CheckBad("01", "leading zero");
  CheckBad("1.", "dangling dot");
  CheckBad("-", "lone minus");
  CheckBad("1e", "dangling exponent");
  CheckBad("+1", "plus sign");
  CheckBad("\"abc", "unterminated string");
  CheckBad("\"a\\", "backslash at end");
  CheckBad("\"\\x\"", "bad escape");
  CheckBad("\"\\u12g4\"", "bad hex");
  CheckBad("\"\\u12\"", "short hex");
  CheckBad("\"a\nb\"", "raw newline in string");
  CheckBad("[1] x", "trailing garbage");
  CheckBad("[1][2]", "two documents");
  CheckBad("]", "stray close");
  CheckBad("[1 2]", "missing comma");

  for (i = 0, deep = MAlloc(300); i < 64; i++)
    deep[i] = '[';
  StrCpy(deep + 64, "1");
  for (i = 0; i < 64; i++)
    deep[65 + i] = ']';
  deep[129] = 0;
  j = JsonParse(deep);
  TestCheck(j != NULL, "depth 64 ok");
  JsonFree(j);
  for (i = 0; i < 65; i++)
    deep[i] = '[';
  StrCpy(deep + 65, "1");
  for (i = 0; i < 65; i++)
    deep[66 + i] = ']';
  deep[131] = 0;
  CheckBad(deep, "depth 65 refused");
  for (i = 0; i < 200; i++)
    deep[i] = '{';
  deep[200] = 0;
  CheckBad(deep, "deep unterminated refused");
  Free(deep);

  CheckEsc("plain", "\"plain\"", "escape plain");
  CheckEsc("a\"b\\c\n\r\t", "\"a\\\"b\\\\c\\n\\r\\t\"", "escape specials");
  CheckEsc("\x01\x1F", "\"\\u0001\\u001f\"", "escape control chars");
  CheckEsc("\xC3\xA9", "\"\xC3\xA9\"", "utf-8 passes through");
  CheckEsc("", "\"\"", "escape empty");
  s = JsonEscape("q\"\\\n\x02\xE2\x82\xAC");
  j = JsonParse(s);
  TestCheck(j && !StrCmp(j->str, "q\"\\\n\x02\xE2\x82\xAC"), "escape roundtrip");
  JsonFree(j);
  Free(s);

  TestDone();
}
Main;
