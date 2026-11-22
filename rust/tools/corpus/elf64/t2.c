#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
static jmp_buf jb;
typedef struct { const char *name; int (*fn)(int, int); } op_t;
static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }
static int mul(int a, int b) { return a * b; }
static int dv(int a, int b) { if (!b) longjmp(jb, 1); return a / b; }
static const op_t ops[] = { {"add", add}, {"sub", sub}, {"mul", mul}, {"div", dv} };
__attribute__((noinline)) int run(int i, int a, int b) { return ops[i & 3].fn(a, b); }
__attribute__((noinline)) int classify(unsigned c) {
  switch (c) { case 'a': case 'e': case 'i': case 'o': case 'u': return 1; case '0'...'9': return 2;
  case ' ': return 3; case '\n': return 4; case '(': case ')': return 5; case '+': case '-': return 6; default: return 0; }
}
int main(int argc, char **argv) {
  if (setjmp(jb)) { puts("div0"); return 1; }
  int t = 0;
  for (int i = 1; i < argc; i++) t += run(i, atoi(argv[i]), argc) + classify(argv[i][0]);
  if (t < 0) abort();
  printf("%d\n", t);
  exit(t & 1);
}
