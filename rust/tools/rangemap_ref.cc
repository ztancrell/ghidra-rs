// Reference for decomp/rangemap.rs: the C++ rangemap template on the data of its unit tests
// (the multiset order, the record list order and find). Build and run from rust/:
//   g++ -std=c++11 -I../Ghidra/Features/Decompiler/src/decompile/cpp tools/rangemap_ref.cc -o target/rangemap_ref && target/rangemap_ref
#include <cstdio>
#include <utility>
#include "rangemap.hh"
using namespace ghidra;
struct Sub { unsigned s; unsigned long o; Sub(bool v):s(v?0xffff:0),o(0){} Sub(unsigned a,unsigned long b):s(a),o(b){} bool operator<(const Sub&x)const{return s!=x.s? s<x.s : o<x.o;} };
struct Rec { typedef unsigned long linetype; typedef Sub subsorttype; typedef std::pair<int,Sub> inittype;
  int id; unsigned long a,b; Sub sub; Rec(const inittype&d,unsigned long a_,unsigned long b_):id(d.first),a(a_),b(b_),sub(d.second){}
  unsigned long getFirst()const{return a;} unsigned long getLast()const{return b;} Sub getSubsort()const{return sub;} };
typedef rangemap<Rec> M;
static void dump(const char*n,M&m){printf("%s tree:",n);for(M::const_iterator i=m.begin();i!=m.end();++i)printf(" %d",(*i).id);printf(" | list:");for(std::list<Rec>::const_iterator i=m.begin_list();i!=m.end_list();++i)printf(" %d",i->id);printf("\n");}
static void find(const char*n,M&m,unsigned long p,Sub s1,Sub s2){std::pair<M::const_iterator,M::const_iterator> r=m.find(p,s1,s2);printf("%s find:",n);for(M::const_iterator i=r.first;i!=r.second;++i)printf(" %d",(*i).id);printf("\n");}
int main(){
  M m; m.insert(std::make_pair(1,Sub(2,0x10)),0,3); dump("a",m); m.insert(std::make_pair(2,Sub(2,0x30)),0,3); dump("b",m); m.insert(std::make_pair(3,Sub(2,0x10)),0,3); dump("c",m);
  find("all",m,1,Sub(false),Sub(true)); find("lim",m,1,Sub(false),Sub(2,0x20));
  m.insert(std::make_pair(4,Sub(false)),8,11); dump("d",m);
  M g; g.insert(std::make_pair(7,Sub(false)),0,7); g.insert(std::make_pair(9,Sub(false)),4,5); dump("inner",g); find("inner4",g,4,Sub(false),Sub(true));
  g.erase(++g.begin_list()==g.end_list()?g.begin_list():g.begin_list()); dump("erased-first",g);
  return 0; }
