// A C++ global with a constructor and a destructor. The constructor runs from .init_array before
// main; the destructor is registered through __cxa_atexit and runs after main returns.
//
// No standard headers: there is no C++ standard library (build.sh passes -nostdinc++), and
// `unsigned long` is `size_t` on RV64.

extern "C" void write_output(const unsigned char *output, unsigned long size);

namespace {

struct Global {
    int value;
    Global() : value(42) {}
    ~Global() {
        static const unsigned char bye[] = {'b', 'y', 'e'};
        write_output(bye, sizeof bye);
    }
};

Global global;

} // namespace

extern "C" int cxx_global_constructed(void) { return global.value == 42; }
