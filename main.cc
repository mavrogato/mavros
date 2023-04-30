#include <iostream>
#include <concepts>
#include <tuple>
#include <stdexcept>
#include <source_location>
#include <string_view>
#include <array>
#include <memory>
#include <filesystem>
#include <map>
#include <complex>
#include <numbers>
#include <coroutine>
#include <ranges>
#include <variant>

#include <cstring>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <wayland-client.h>
#include "xdg-shell-v6-client.h"
#include "zwp-tablet-v2-client.h"

#pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
# pragma GCC diagnostic ignored "-Wreturn-type"
# include <sycl/sycl.hpp>
#pragma GCC diagnostic pop

namespace std
{
    template <class T, size_t I>
    concept has_tuple_element = requires(T t) {
        typename std::tuple_element_t<I, std::remove_const_t<T>>;
        { get<I>(t) } -> std::convertible_to<std::tuple_element_t<I, T> const&>;
    };
    template <class T>
    concept tuple_like = !std::is_reference_v<T> && requires(T) {
        std::tuple_size<T>::value;
        requires std::derived_from<std::tuple_size<T>, std::integral_constant<size_t, std::tuple_size_v<T>>>;
    } && []<size_t... I>(std::index_sequence<I...>) noexcept {
        return (has_tuple_element<T, I>&& ...);
    }(std::make_index_sequence<std::tuple_size_v<T>>());

    template <class Ch, tuple_like T>
    auto& operator<<(std::basic_ostream<Ch>& output, T const& t) noexcept {
        output.put('(');
        [&]<size_t ...I>(std::index_sequence<I...>) noexcept {
            (void) (int[]) {(output << (I==0 ? "" : " ") << get<I>(t), 0)...};
        }(std::make_index_sequence<std::tuple_size<T>::value>());
        return output.put(')');
    }

    template <class Ch>
    auto& operator<<(std::basic_ostream<Ch>& output, std::source_location const& loc) noexcept {
        return output << loc.file_name() << ':'
                      << loc.line()      << ':'
                      << loc.column()    << ':'
                      << loc.function_name();
    }
} // ::std

namespace aux
{
    using sloc = std::source_location;

    inline auto lamed() noexcept {
        return [](auto...) noexcept { };
    }
    inline auto lamed(auto&& closure) noexcept {
        static auto cache = closure;
        return [](auto... args) {
            return cache(args...);
        };
    }

    struct application_error : std::runtime_error {
        sloc loc;
        application_error(std::string_view msg, sloc loc = sloc::current()) noexcept
            : std::runtime_error(msg.data())
            , loc(loc)
            {
            }
        template <class Ch>
        friend auto& operator<<(std::basic_ostream<Ch>& output, application_error const& ex) {
            return output << ex.loc << ": " << ex.what();
        }
    };

    template <class T, class D>
    auto make_unique(T* ptr, D del, auto&& loc = sloc::current()) {
        if (ptr == nullptr) {
            throw application_error("nullptr detected.", loc);
        }
        return std::unique_ptr<T, D>(ptr, del);
    }

    template <class> struct function;
    template <class T, class... Args> struct function<T(*)(Args...)> {
        using result_type = T;
        using arguments_type = std::tuple<Args...>;
    };
    template <class T, class... Args> struct function<T(Args...)> {
        using result_type = T;
        using arguments_type = std::tuple<Args...>;
    };
    template <class F> using arguments_of = typename function<F>::arguments_type;
#   define ARGUMENTS_OF(T,m) aux::arguments_of<decltype (std::declval<T>().m)>

} // ::aux

namespace aux::inline wayland
{
    template <class> constexpr wl_interface const *const interface_ptr = nullptr;
    template <class> constexpr std::string_view interface_name = "";
    template <class T> concept as_client = (interface_ptr<T> != nullptr);
    template <as_client> constexpr void (*client_deleter)(void*) = nullptr;
    enum class null_listener_type { nil };
    template <as_client> struct listener_meta_type { using type = null_listener_type; };
    template <as_client T> using listener_type = typename listener_meta_type<T>::type;
    template <class T> concept as_client_without_listener = (std::is_same_v<listener_type<T>, null_listener_type>);
    template <class T> concept as_client_with_listener = !as_client_without_listener<T>;

#   define INTERN_AS_CLIENT_CONCEPT(AS_CLIENT, DELETER, LISTENER)         \
    template <> constexpr wl_interface const *const interface_ptr<AS_CLIENT> = &AS_CLIENT##_interface; \
    template <> constexpr std::string_view interface_name<AS_CLIENT> = #AS_CLIENT; \
    template <> constexpr void (*client_deleter<AS_CLIENT>)(AS_CLIENT*) = DELETER;     \
    template <> struct listener_meta_type<AS_CLIENT> { using type = LISTENER; };
    INTERN_AS_CLIENT_CONCEPT(wl_display,            wl_display_disconnect,         wl_display_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_registry,           wl_registry_destroy,           wl_registry_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_compositor,         wl_compositor_destroy,         null_listener_type)
    INTERN_AS_CLIENT_CONCEPT(wl_output,             wl_output_destroy,             wl_output_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_shm,                wl_shm_destroy,                wl_shm_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_seat,               wl_seat_destroy,               wl_seat_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_surface,            wl_surface_destroy,            wl_surface_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_shm_pool,           wl_shm_pool_destroy,           null_listener_type)
    INTERN_AS_CLIENT_CONCEPT(wl_buffer,             wl_buffer_destroy,             wl_buffer_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_keyboard,           wl_keyboard_destroy,           wl_keyboard_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_pointer,            wl_pointer_destroy,            wl_pointer_listener)
    INTERN_AS_CLIENT_CONCEPT(wl_touch,              wl_touch_destroy,              wl_touch_listener)
    INTERN_AS_CLIENT_CONCEPT(zxdg_shell_v6,         zxdg_shell_v6_destroy,         zxdg_shell_v6_listener)
    INTERN_AS_CLIENT_CONCEPT(zxdg_surface_v6,       zxdg_surface_v6_destroy,       zxdg_surface_v6_listener)
    INTERN_AS_CLIENT_CONCEPT(zxdg_toplevel_v6,      zxdg_toplevel_v6_destroy,      zxdg_toplevel_v6_listener)
    INTERN_AS_CLIENT_CONCEPT(zwp_tablet_manager_v2, zwp_tablet_manager_v2_destroy, null_listener_type)
#   undef  INTERN_AS_CLIENT_CONCEPT

    template <as_client T>
    auto make_unique(T* ptr, sloc loc = sloc::current()) {
        return aux::make_unique(ptr, client_deleter<T>, loc);
    }

    template <as_client_with_listener T>
    auto add_listener(T* ptr, listener_type<T>&& listener, void* data = nullptr, sloc loc = sloc::current())
    { 
        if (0 != wl_proxy_add_listener(reinterpret_cast<wl_proxy*>(ptr),
                                       reinterpret_cast<void(**)(void)>(&listener),
                                       data)) {
            throw application_error("wl_proxy_add_listener failed.", loc);
        }
        return listener;
    }

    template <as_client T>
    using unique_type = decltype (make_unique(std::declval<T*>()));

    //template <class T> class wrapper;

    template <as_client T>
    class wrapper {
    public:
        wrapper() noexcept
            : ptr{nullptr, client_deleter<T>}
            , listener{}
            { }

        explicit wrapper(T* raw)
            : ptr{make_unique(raw)}
            , listener{}
            {
            }
        wrapper(T* raw, listener_type<T>&& listener, void* data = nullptr)
            : ptr{make_unique(raw)}
            , listener{add(std::move(listener), data)}
            {
            }
        wrapper(wrapper&& other) noexcept
            : ptr{std::exchange(other.ptr, nullptr)}
            , listener{std::exchange(other.listener, listener_type<T>{})}
            {
            }
        auto& operator=(wrapper&& other) noexcept {
            if (this != &other) {
                this->ptr = std::exchange(other.ptr, nullptr);
                this->listener = std::exchange(other.listener, listener_type<T>{});
            }
            return *this;
        }

        //auto reset(T* raw) { return ptr.reset(raw); }

        auto get() const noexcept { return this->ptr.get(); }
        operator T*() const noexcept { return this->get(); }

        auto add(listener_type<T>&& listener, void* data = nullptr) {
            return this->listener = add_listener(this->get(), std::move(listener), data);
        }

    private:
        unique_type<T> ptr;
        listener_type<T> listener;
    };

    // template <as_client T>
    // [[deprecated]]
    // auto wrap(T* raw) {
    //     return wrapper(raw);
    // }
    // template <as_client T>
    // [[deprecated]]
    // auto wrap(T* raw, listener_type<T>&& listener, void* data = nullptr) {
    //     return wrapper(raw, std::move(listener), data);
    // }

    template <as_client T>
    auto wl_registry_bind(wl_registry* registry, uint32_t name, uint32_t version) noexcept {
        return static_cast<T*>(::wl_registry_bind(registry, name, interface_ptr<T>, version));
    }

    struct color_type {
        uint8_t b;
        uint8_t g;
        uint8_t r;
        uint8_t a;
    };

    template <class T = color_type, wl_shm_format format = WL_SHM_FORMAT_XRGB8888, size_t bypp = 4>
    inline auto allocate_buffer(wl_shm* shm, size_t cx, size_t cy) {
        std::string_view xdg_runtime_dir = std::getenv("XDG_RUNTIME_DIR");
        if (xdg_runtime_dir.empty() || !std::filesystem::exists(xdg_runtime_dir)) {
            throw application_error("No XDG_RUNTIME_DIR settings...");
        }
        std::string_view tmp_file_title = "/weston-shared-XXXXXX";
        if (4096 <= xdg_runtime_dir.size() + tmp_file_title.size()) {
            throw application_error("The path of XDG_RUNTIME_DIR is too long...");
        }
        char tmp_path[4096] = { };
        auto p = std::strcat(tmp_path, xdg_runtime_dir.data());
        std::strcat(p, tmp_file_title.data());
        int fd = mkostemp(tmp_path, O_CLOEXEC);
        if (fd >= 0) {
            unlink(tmp_path);
        }
        else {
            throw application_error("mkostemp failed...");
        }
        if (ftruncate(fd, bypp*cx*cy) < 0) {
            close(fd);
            throw application_error("ftruncate failed...");
        }
        auto data = mmap(nullptr, bypp*cx*cy, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED) {
            close(fd);
            throw application_error("mmap failed...");
        }
        return std::tuple{
            wrapper(wl_shm_pool_create_buffer(wrapper(wl_shm_create_pool(shm, fd, bypp*cx*cy)),
                                           0, cx, cy, bypp * cx, format)),
            static_cast<T*>(data),
        };
    }

    using resource = std::variant<
        wl_display,
        wl_registry,
        wl_compositor,
        wl_output,
        wl_shm,
        wl_seat,
        wl_surface,
        wl_shm_pool,
        wl_buffer,
        wl_keyboard,
        wl_pointer,
        wl_touch,
        zxdg_shell_v6,
        zxdg_surface_v6,
        zxdg_toplevel_v6,
        zwp_tablet_manager_v2>;
    using wrapped_resource = std::variant<
        wrapper<wl_display>,
        wrapper<wl_registry>,
        wrapper<wl_compositor>,
        wrapper<wl_output>,
        wrapper<wl_shm>,
        wrapper<wl_seat>,
        wrapper<wl_surface>,
        wrapper<wl_shm_pool>,
        wrapper<wl_buffer>,
        wrapper<wl_keyboard>,
        wrapper<wl_pointer>,
        wrapper<wl_touch>,
        wrapper<zxdg_shell_v6>,
        wrapper<zxdg_surface_v6>,
        wrapper<zxdg_toplevel_v6>,
        wrapper<zwp_tablet_manager_v2>>;

    struct node : std::map<resource, node> {
        wrapped_resource wrapped;
    };

} // ::aux::wayland

int main() {
    using namespace aux;
    try {
        size_t cx = 3840;//0;
        size_t cy = 1080;//std::numeric_limits<size_t>::max();

        auto display = wrapper(wl_display_connect(nullptr));
        wrapper<wl_compositor> compositor;
        std::vector<wrapper<wl_output>> outputs;
        wrapper<wl_shm> shm;
        wrapper<wl_seat> seat;
        wrapper<zxdg_shell_v6> shell;
        wrapper<zwp_tablet_manager_v2> tablet_manager;
        auto registry = wrapper(wl_display_get_registry(display), {
                .global = lamed([&](auto, wl_registry* registry,
                                    uint32_t name,
                                    std::string_view interface,
                                    uint32_t version) noexcept {
                    std::cout << "global added: " << std::tuple{registry, name, interface, version} << std::endl;
                    if (interface == interface_name<wl_compositor>) {
                        compositor = wrapper(wl_registry_bind<wl_compositor>(registry, name, version));
                    }
                    else if (interface == interface_name<wl_output>) {
                        outputs.emplace_back(wl_registry_bind<wl_output>(registry, name, version));
                    }
                    else if (interface == interface_name<wl_shm>) {
                        shm = wrapper(wl_registry_bind<wl_shm>(registry, name, version), {
                            .format = lamed([&](auto, auto, uint32_t format) {
                                if (format == WL_SHM_FORMAT_XRGB8888) {
                                    std::cout << "OK" << std::endl;
                                }
                            })});
                    }
                    else if (interface == interface_name<zxdg_shell_v6>) {
                        shell = wrapper(wl_registry_bind<zxdg_shell_v6>(registry, name, version));
                    }
                    else if (interface == interface_name<wl_seat>) {
                        seat = wrapper(wl_registry_bind<wl_seat>(registry, name, version));
                    }
                    else if (interface == interface_name<zwp_tablet_manager_v2>) {
                        tablet_manager = wrapper(wl_registry_bind<zwp_tablet_manager_v2>(registry, name, version));
                    }
                }),
                .global_remove = lamed([&](auto... args) {
                    std::cout << "global removed: " << std::tuple{args...} << std::endl;
                    //throw application_error("Lost required objects...", sloc());
                }),
            });

        wl_display_roundtrip(display);

        if (!compositor || !shm) throw application_error("Missed required object...");

        for (auto& output : outputs) {
            output.add({
                    .geometry = lamed([](auto... args) {
                        std::cout << "output geometry: " << std::tuple{args...} << std::endl;
                    }),
                    .mode = lamed([&](auto... args) {
                        std::cout << "output mode: " << std::tuple{args...} << std::endl;
                        auto [data, output, flags, width, height, refresh] = std::tuple{args...};
                        cx = std::max<size_t>(cx, width);
                        cy = std::min<size_t>(cy, height);
                    }),
                    .done = lamed([](auto... args) {
                        std::cout << "output done: " << std::tuple{args...} << std::endl;
                    }),
                    .scale = lamed([](auto... args) {
                        std::cout << "output scale: " << std::tuple{args...} << std::endl;
                    }),
                    .name = lamed([](auto... args) {
                        std::cout << "output name: " << std::tuple{args...} << std::endl;
                    }),
                    .description = lamed([](auto... args) {
                        std::cout << "output description: " << std::tuple{args...} << std::endl;
                    })});
        }

        auto surface = wrapper(wl_compositor_create_surface(compositor));

        std::map<int32_t, std::vector<std::complex<double>>> strokes;
        wrapper<wl_pointer> pointer;
        wrapper<wl_keyboard> keyboard;
        wrapper<wl_touch> touch;
        seat.add({
                .capabilities = lamed([&](auto, wl_seat* seat, uint32_t capabilities) noexcept {
                    if (capabilities & WL_SEAT_CAPABILITY_POINTER) {
                        pointer = wrapper(wl_seat_get_pointer(seat));
                    }
                    if (capabilities & WL_SEAT_CAPABILITY_KEYBOARD) {
                        keyboard = wrapper(wl_seat_get_keyboard(seat));
                    }
                    if (capabilities & WL_SEAT_CAPABILITY_TOUCH) {
                        touch = wrapper(wl_seat_get_touch(seat));
                    }
                }),
                .name = lamed(),
            });

        wl_display_roundtrip(display);

        std::cout << "(cx,cy) = " << std::tuple{cx, cy} << std::endl;
        auto [buffer, pixels] = allocate_buffer(shm, cx, cy);
        strokes[-1].emplace_back(1*cx/4.0, cy/2.0);
        strokes[-1].emplace_back(3*cx/4.0, cy/2.0);

        pointer.add({
                .enter = lamed(),
                .leave = lamed(),
                .motion = lamed([&](auto, auto, auto, auto x, auto y) noexcept {
                    // strokes[-1].emplace_back(wl_fixed_to_double(x), wl_fixed_to_double(y));
                    std::cout << std::tuple{wl_fixed_to_double(x), wl_fixed_to_double(y)} << std::endl;
                }),
                .button = lamed([&](auto, auto, auto x, auto y, auto button, auto state) noexcept {
                    // if (state) {
                    //     //strokes[-1].emplace_back(wl_fixed_to_double(x), wl_fixed_to_double(y));
                    // }
                    // else {
                    //     strokes.erase(-1);
                    // }
                }),
                .axis = lamed(),
                .frame = lamed(),
                .axis_source = lamed(),
                .axis_stop = lamed(),
                .axis_discrete = lamed(),
            });
        keyboard.add({
                .keymap = lamed(),
                .enter = lamed(),
                .leave = lamed(),
                .key = lamed([&](auto, auto, auto, auto, auto k, auto s) /*noexcept*/ {
                    std::cout << k << ':' << s << std::endl; //!!!
                    if ((k == 1 || k == 16) && s == 0) {
                        throw application_error("quit.");
                    }
                }),
                .modifiers = lamed(),
                .repeat_info = lamed(),
            });

        touch.add({
                .down = lamed([&](auto, auto, auto, auto, auto, int32_t id, wl_fixed_t x, wl_fixed_t y) {
                    strokes[id].emplace_back(wl_fixed_to_double(x), wl_fixed_to_double(y));
                }),
                .up = lamed([&](auto, auto, auto, auto, int32_t id) noexcept {
                    strokes.erase(id);
                }),
                .motion = lamed([&](auto, auto, auto, int32_t id, wl_fixed_t x, wl_fixed_t y) {
                    strokes[id].emplace_back(wl_fixed_to_double(x), wl_fixed_to_double(y));
                }),
                .frame = lamed([&](auto...) {
                    // for (auto const [id, stroke] : strokes) {
                    //     for (auto vertex : stroke) {
                    //         std::cout << vertex << ' ';
                    //     }
                    //     std::cout << std::endl;
                    // }
                    // std::cout << strokes.size() << std::endl;
                }),
                .cancel = lamed([&](auto...) noexcept {
                    strokes.clear();
                }),
                .shape = lamed(),
                .orientation = lamed(),
            });

        shell.add({
                .ping = lamed([](auto, auto shell, uint32_t serial) noexcept {
                    zxdg_shell_v6_pong(shell, serial);
                })});

        auto xsurface = wrapper(zxdg_shell_v6_get_xdg_surface(shell, surface), {
                .configure = [](auto, auto xsurface, auto serial) noexcept {
                    zxdg_surface_v6_ack_configure(xsurface, serial);
                },
            });

        auto toplevel = wrapper(zxdg_surface_v6_get_toplevel(xsurface), {
                .configure = lamed([&](auto, auto, auto w, auto h, auto) {
                    cx = w;
                    cy = h;
                    if (cx && cy) {
                        auto [b, p] = allocate_buffer(shm, cx, cy);
                        buffer = std::move(b);
                        pixels = p;
                    }
                }),
                .close = lamed(),
            });

        wl_surface_commit(surface);

        auto que = sycl::queue();
        std::cout << que.get_device().get_info<sycl::info::device::name>() << std::endl;
        std::cout << que.get_device().get_info<sycl::info::device::vendor>() << std::endl;

        static constexpr size_t N = 256;// * 256 * 3 * 3;
        static constexpr double PI = std::numbers::pi;
        static constexpr double TAU = PI * 2.0;
        static constexpr double PHI = std::numbers::phi;

        // static constexpr auto segment = []{
        //     std::array<double, N*N> buf{};
        //     for (size_t i = 0; i < buf.size(); ++i) {
        //         double tmp = PHI * i;
        //         buf[i] = tmp - static_cast<size_t>(tmp);
        //     }
        //     return buf;
        // }();

        while (wl_display_dispatch(display) != -1) {
            if (cx && cy) {

                    auto pv = sycl::buffer<color_type, 2>{pixels, {cy, cx}};
                    que.submit([&](auto& h) noexcept {
                        auto apv = pv.get_access<sycl::access::mode::write>(h);
                        h.parallel_for({cy, cx}, [=](auto idx) noexcept {
                            apv[idx] = { 0, 0, 0, 0 };
                        });
                    });
                    for (auto const& stroke : strokes) {
                        if (auto const& vertices = stroke.second; !vertices.empty()) {
                            auto vv = sycl::buffer<std::complex<double>, 1>{vertices.data(), vertices.size()};
                            que.submit([&](auto& h) noexcept {
                                auto apv = pv.get_access<sycl::access::mode::read_write>(h);
                                auto avv = vv.get_access<sycl::access::mode::read>(h);
                                h.parallel_for({vertices.size(), N}, [=](auto idx) noexcept {
                                    auto n = idx[1];
                                    auto pt = avv[idx[0]] + std::polar(sqrt(n)/3, n*TAU*PHI);
                                    auto d = 255*(1.0 - ((double)n/N));
                                    //auto d = 255.0 * (N/1024.0 / (N/1024.0+n));
                                    //auto d = 255.0 / n;
                                    auto y = pt.imag();
                                    auto x = pt.real();
                                    if (0 <= x && x < cx && 0 <= y && y < cy) {
                                        uint8_t b = d;
                                        // auto v = reinterpret_cast<uint8_t*>(&apv[{(size_t) y, (size_t) x}]);
                                        // // v[0] = std::max(v[0], b);
                                        // // v[1] = std::max(v[1], b);
                                        // // v[2] = std::max(v[2], b);
                                        // // v[3] = std::max(v[3], b);
                                        // v[0] = std::min(v[0] + b, 255);
                                        // v[1] = std::min(v[1] + b, 255);
                                        // v[2] = std::min(v[2] + b, 255);
                                        // v[3] = std::min(v[3] + b, 255);
                                        auto& c = apv[{(size_t) y, (size_t) x}];
                                        c.a = std::min(c.a + b, 255);
                                        c.b = std::min(c.b + b, 255);
                                        c.g = std::min(c.g + b, 255);
                                        c.r = std::min(c.r + b, 255);
                                    }
                                });
                            });
                        }
                    }

            }
            wl_surface_damage(surface, 0, 0, cx, cy);
            wl_surface_attach(surface, buffer, 0, 0);
            wl_surface_commit(surface);
            wl_display_flush(display);
        }
    }
    catch (application_error& ex) {
        std::cout << ex << std::endl;
    }
    return 0;
}
