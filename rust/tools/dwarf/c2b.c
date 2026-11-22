/* Second unit of c2a.c. */
struct conf { long a; char b[3]; };
struct later { int x; struct later *next; };
enum shared { S_A, S_B, S_C };
typedef struct { int only_b; } anon_b_t;
static struct later the_later;
struct later *get_later(void) { return &the_later; }
int use_b(struct conf *c, anon_b_t *t, enum shared s) { return (int)c->a + c->b[1] + t->only_b + s; }
int use_a(struct conf *, void *, void *, int);
int main(void) {
    struct conf c = {1, {2, 3, 4}};
    anon_b_t t = {5};
    return use_b(&c, &t, S_C) + use_a(0, 0, 0, 0);
}
