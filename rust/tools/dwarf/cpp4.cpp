// Returns and parameters by the x86-64 System V rules (x86-64-gcc.cspec): a 24-byte struct
// returned by a method with an unnamed parameter (hidden return pointer), returns of up to 16
// bytes that bind to registers (join_dual_class) or not (x87 long double), register-passed
// parameters.
struct Big { long a, b, c; };
struct LD { long double x; };
struct FI { float f; int i; };
struct DD { double a, b; };
struct CD { char c; double d; };
union U { long double x; long l; };
union V { double d; long l; };

class K {
public:
    int base;
    __attribute__((noinline)) Big make(int, long n, double d, char c);
    __attribute__((noinline)) long double ld(int x);
};

Big K::make(int, long n, double d, char c) { return Big{n + base, (long)d, c}; }
long double K::ld(int x) { return x * 1.5L + base; }
__attribute__((noinline)) LD mk_ld(long double v) { return LD{v}; }
__attribute__((noinline)) FI mk_fi(float f, int i) { return FI{f, i}; }
__attribute__((noinline)) DD mk_dd(double a, double b) { return DD{a, b}; }
__attribute__((noinline)) CD mk_cd(char c, double d) { return CD{c, d}; }
__attribute__((noinline)) U mk_u(long l) { U u; u.l = l; return u; }
__attribute__((noinline)) V mk_v(long l) { V v; v.l = l; return v; }

int main(int argc, char **) {
    K k{argc};
    volatile long s = k.make(1, argc, 2.0, 'c').b + (long)k.ld(argc) + (long)mk_ld(argc).x;
    s = s + mk_fi(1.0f, argc).i + (long)mk_dd(argc, 2).b + (long)mk_cd('a', argc).d;
    s = s + mk_u(argc).l + mk_v(argc).l;
    return (int)s;
}
