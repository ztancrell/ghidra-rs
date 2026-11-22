/* DWARF test corpus (C): structs, unions, enums, bitfields, anonymous types, typedefs,
   function pointers, arrays, varargs. Built by tools/dwarf-diff.sh. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

typedef unsigned int u32;
typedef struct point { int x, y; } point_t;
struct flags { unsigned a : 1, b : 3; signed c : 5; unsigned : 0; unsigned d : 7; char e; };
union value { int i; float f; double d; char bytes[8]; struct { short lo, hi; } parts; };
enum color { RED, GREEN = 5, BLUE = -1 };
typedef enum { ANON_A = 1, ANON_B = 2 } anon_enum_t;
typedef int (*binop)(int, int);
struct node { struct node *next; void *data; binop op; int grid[3][4]; char name[]; };
struct opaque;
struct holder { struct opaque *p; struct { int k; long v; } inner; union { int a; char b; } u; };
struct packed_s { char c; int i; } __attribute__((packed));
struct big { long double ld; __int128 w; uint8_t b8; int64_t i64; wchar_t wc; _Bool ok; };
typedef struct point point_t2;
const volatile int cv_global = 3;

static int add(int a, int b) { return a + b; }
int sum(int n, ...) {
    va_list ap;
    va_start(ap, n);
    int s = 0;
    for (int i = 0; i < n; i++) s += va_arg(ap, int);
    va_end(ap);
    return s;
}
u32 use_all(point_t *p, struct flags f, union value v, enum color c, anon_enum_t ae, struct node *n,
            struct holder *h, struct packed_s ps, struct big *b, point_t2 q) {
    binop op = add;
    return (u32)(p->x + f.b + v.i + c + ae + n->grid[1][2] + h->inner.k + ps.i + (int)b->b8 + q.y +
                 op(1, 2));
}
__attribute__((noreturn)) void die(const char *msg) {
    (void)msg;
    for (;;) {
    }
}
int main(void) {
    return sum(2, 1, 2) + (int)use_all(0, (struct flags){0}, (union value){0}, RED, ANON_A, 0, 0,
                                       (struct packed_s){0}, 0, (point_t2){0});
}
