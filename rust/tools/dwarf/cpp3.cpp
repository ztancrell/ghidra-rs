// DWARF test corpus (C++): breadth of the standard library's types (streams, regex, threads,
// hash maps, variants, tuples, chrono), -O2. Built by tools/dwarf-diff.sh.
#include <chrono>
#include <deque>
#include <iostream>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <variant>

struct Point3 {
    double x, y, z;
    bool operator<(const Point3 &o) const { return std::tie(x, y, z) < std::tie(o.x, o.y, o.z); }
};
using Value = std::variant<int, double, std::string, Point3>;

int main(int argc, char **argv) {
    std::unordered_map<std::string, Value> vals;
    std::set<Point3> pts{{1, 2, 3}, {0, 0, 1}};
    std::deque<std::tuple<int, std::string, std::optional<double>>> q;
    std::mutex m;
    std::ostringstream os;
    std::regex re("[a-z]+([0-9]*)");
    for (int i = 0; i < argc; i++) {
        std::smatch sm;
        std::string a = argv[i];
        if (std::regex_match(a, sm, re))
            vals[sm[1]] = (int)sm.size();
        q.emplace_back(i, a, i ? std::optional<double>(i * 0.5) : std::nullopt);
    }
    auto t0 = std::chrono::steady_clock::now();
    std::thread th([&] {
        std::lock_guard<std::mutex> g(m);
        os << vals.size() << pts.size() << q.size();
    });
    th.join();
    std::cout << os.str() << (std::chrono::steady_clock::now() - t0).count() << std::endl;
    return (int)std::get<0>(q.front());
}
