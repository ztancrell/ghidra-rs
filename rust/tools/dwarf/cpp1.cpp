// DWARF test corpus (C++): classes, inheritance, virtual methods, templates, namespaces,
// references, pointers to members, nested and anonymous types, static members.
// Built by tools/dwarf-diff.sh.
namespace geo {
struct Shape {
    virtual ~Shape() {}
    virtual double area() const = 0;
    int id;
    static int count;
};
int Shape::count = 0;
class Circle : public Shape {
  public:
    explicit Circle(double r) : r_(r) {}
    double area() const override { return 3.14 * r_ * r_; }
    double radius() const { return r_; }

  private:
    double r_;
};
struct Rect : Shape {
    double w, h;
    double area() const override { return w * h; }
};
struct Multi : Circle, Rect {
    Multi() : Circle(1.0) {}
    double area() const override { return 0; }
};
} // namespace geo
template <typename T, int N> struct Array {
    T items[N];
    int size() const { return N; }
    T &at(int i) { return items[i]; }
};
template <typename T> T maxof(T a, T b) { return a > b ? a : b; }
struct Outer {
    struct Inner {
        int v;
    } in;
    enum Mode { A, B } mode;
    union {
        int i;
        float fl;
    };
    int Outer::*pm;
    int (Outer::*pmf)(int);
    int f(int x) { return x; }
};
class Base {
  public:
    virtual void hello(int &ref, const char *s) = 0;
    virtual ~Base();
};
Base::~Base() {}
class Derived : public virtual Base {
  public:
    void hello(int &ref, const char *s) override { ref += *s; }
    int &&rv(int &&x) { return static_cast<int &&>(x); }
};
namespace {
struct Hidden {
    int h;
};
int hidden_fn(Hidden *h) { return h->h; }
} // namespace
int main() {
    geo::Circle c(2.0);
    geo::Rect r;
    r.w = 1;
    r.h = 2;
    geo::Multi m;
    Array<int, 4> ai;
    Array<double, 2> ad;
    ai.at(0) = 1;
    ad.at(1) = 2.0;
    Outer o;
    o.pm = nullptr;
    o.pmf = &Outer::f;
    Derived d;
    int x = 0;
    d.hello(x, "a");
    Hidden h{1};
    return (int)(c.area() + r.area() + m.area() + ai.size() + ad.size() + maxof(1, 2) +
                 maxof(1.0, 2.0) + (o.*o.pmf)(1) + x + hidden_fn(&h) + d.rv(3));
}
