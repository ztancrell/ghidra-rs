#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct node { struct node *next; int v; };
static int __attribute__((noinline)) sw(int x) {
  switch (x) { case 0: return puts("a"); case 1: return 7*x; case 2: return strlen("bb");
  case 3: return x<<3; case 4: return x^99; case 5: return x+11; case 6: return abs(x-50); default: return -1; }
}
static void __attribute__((noinline,noreturn)) die(const char *m) { fprintf(stderr, "%s\n", m); exit(3); }
int (*fp)(int) = sw;
int sum(struct node *n) { int s = 0; for (; n; n = n->next) s += n->v; return s; }
double avg(double *a, int n) { double s = 0; for (int i = 0; i < n; i++) s += a[i]; return n ? s / n : 0; }
long many(long a, long b, long c, long d, long e, long f, long g, long h) { return a+b*c-d+e*f-g+h; }
int main(int argc, char **argv) {
  if (argc > 5) die("too many");
  struct node *h = 0;
  for (int i = 0; i < argc; i++) { struct node *n = malloc(sizeof *n); if (!n) abort(); n->v = fp(i); n->next = h; h = n; }
  double d[3] = {1, 2, argc};
  printf("%d %f %ld\n", sum(h), avg(d, 3), many(argc, 2, 3, 4, 5, 6, 7, 8));
  return 0;
}
