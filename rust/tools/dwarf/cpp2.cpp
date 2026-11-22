// DWARF test corpus (C++): the standard library's templates (string, vector, map,
// unique_ptr, function), a class hierarchy with virtual bases and bitfields, -O2 inlining.
// Built by tools/dwarf-diff.sh.
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

struct Flags {
    unsigned a : 3;
    bool b : 1;
    int c : 12;
};
class Animal {
  public:
    virtual ~Animal() = default;
    virtual std::string speak() const = 0;
    Flags flags{};
};
class Dog : public Animal {
  public:
    std::string speak() const override { return "woof " + name; }
    std::string name = "rex";
};
class Robot : public virtual Animal {
  public:
    std::string speak() const override { return "beep"; }
    std::vector<int> parts;
};
int run(std::map<std::string, std::unique_ptr<Animal>> &zoo, const std::function<int(const Animal &)> &f) {
    int n = 0;
    for (auto &kv : zoo)
        n += f(*kv.second) + (int)kv.first.size();
    return n;
}
int main(int argc, char **argv) {
    std::map<std::string, std::unique_ptr<Animal>> zoo;
    zoo["d"] = std::make_unique<Dog>();
    zoo["r"] = std::make_unique<Robot>();
    std::vector<std::string> args(argv, argv + argc);
    return run(zoo, [](const Animal &a) { return (int)a.speak().size() + a.flags.c; }) + (int)args.size();
}
