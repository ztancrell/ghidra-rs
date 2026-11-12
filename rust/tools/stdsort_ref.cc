// Reference for decomp/stdsort.rs: libstdc++ std::sort and the heapsort it falls back to
// (std::partial_sort(first, last, last)) on seeded inputs with many tied keys. Output:
// ghidra-rs/tests/data/stdsort-gxx.txt (g++ -O1 -o t stdsort_ref.cc && ./t > ...).
#include <algorithm>
#include <cstdio>
#include <vector>
#include <utility>
typedef std::pair<unsigned,unsigned> P;
static std::vector<P> gen(unsigned n,unsigned keys){unsigned seed=12345;std::vector<P> v;for(unsigned i=0;i<n;i++){seed=seed*1103515245u+12345u;v.push_back(P((seed>>16)%keys,i));}return v;}
static bool lt(const P&a,const P&b){return a.first<b.first;}
static void out(const char*name,const std::vector<P>&v){printf("%s:",name);for(size_t i=0;i<v.size();i++)printf(" %u",v[i].second);printf("\n");}
int main(){std::vector<P> a=gen(1000,50);std::sort(a.begin(),a.end(),lt);out("sort1000_50",a);std::vector<P> b=gen(40,3);std::sort(b.begin(),b.end(),lt);out("sort40_3",b);std::vector<P> c=gen(40,3);std::partial_sort(c.begin(),c.end(),c.end(),lt);out("heap40_3",c);return 0;}
