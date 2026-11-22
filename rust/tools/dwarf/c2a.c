/* DWARF test corpus (C, two units with c2b.c): the same names with different layouts
   (.conflict types), a declared-only struct completed in the other unit, enums merged by name,
   bitfields across storage units, -O2 inlining. Built by tools/dwarf-diff.sh. */
struct conf { int a; int b; };
struct later;
struct later *get_later(void);
enum shared { S_A, S_B };
struct bits { unsigned long long x : 40, y : 30; unsigned char z : 3; short w : 9, v : 9; };
typedef struct { int only_a; } anon_a_t;
static inline int helper(struct conf *c) { return c->a * 3 + c->b; }
int use_a(struct conf *c, struct bits *b, anon_a_t *t, enum shared s) {
    return helper(c) + (int)b->y + b->v + t->only_a + s + (get_later() != 0);
}
