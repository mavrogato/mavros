
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
    auto safe_ptr(T* ptr, D del, auto&& loc = sloc::current()) {
        if (ptr == nullptr) {
            throw application_error("nullptr detected.", loc);
        }
        return std::unique_ptr<T, D>(ptr, del);
    }

} // ::aux

namespace aux::inline wayland_client_helper
{
    template <class> constexpr wl_interface const *const wl_interface_ptr = nullptr;
    template <class> constexpr std::string_view wl_interface_name = "";
    template <class T> concept wl_client = (wl_interface_ptr<T> != nullptr);
    template <wl_client> constexpr void (*wl_deleter)(void*) = nullptr;
    template <wl_client> struct wl_listener { using type = void; };
    template <wl_client T> using wl_listener_type = typename wl_listener<T>::type;
    template <class T> concept wl_client_with_listener = !(std::is_same_v<wl_listener_type<T>, void>);

# define INTERN_WL_CLIENT_CONCEPT(WL_CLIENT, DELETER, LISTENER)         \
    template <> constexpr wl_interface const *const wl_interface_ptr<WL_CLIENT> = &WL_CLIENT##_interface; \
    template <> constexpr std::string_view wl_interface_name<WL_CLIENT> = #WL_CLIENT; \
    template <> constexpr void (*wl_deleter<WL_CLIENT>)(WL_CLIENT*) = DELETER;     \
    template <> struct wl_listener<WL_CLIENT> { using type = LISTENER; };
    INTERN_WL_CLIENT_CONCEPT(wl_display,            wl_display_disconnect,         wl_display_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_registry,           wl_registry_destroy,           wl_registry_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_compositor,         wl_compositor_destroy,         void)
    INTERN_WL_CLIENT_CONCEPT(wl_output,             wl_output_destroy,             wl_output_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_shm,                wl_shm_destroy,                wl_shm_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_seat,               wl_seat_destroy,               wl_seat_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_surface,            wl_surface_destroy,            wl_surface_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_shm_pool,           wl_shm_pool_destroy,           void)
    INTERN_WL_CLIENT_CONCEPT(wl_buffer,             wl_buffer_destroy,             wl_buffer_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_keyboard,           wl_keyboard_destroy,           wl_keyboard_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_pointer,            wl_pointer_destroy,            wl_pointer_listener)
    INTERN_WL_CLIENT_CONCEPT(wl_touch,              wl_touch_destroy,              wl_touch_listener)
    INTERN_WL_CLIENT_CONCEPT(zxdg_shell_v6,         zxdg_shell_v6_destroy,         zxdg_shell_v6_listener)
    INTERN_WL_CLIENT_CONCEPT(zxdg_surface_v6,       zxdg_surface_v6_destroy,       zxdg_surface_v6_listener)
    INTERN_WL_CLIENT_CONCEPT(zxdg_toplevel_v6,      zxdg_toplevel_v6_destroy,      zxdg_toplevel_v6_listener)
    INTERN_WL_CLIENT_CONCEPT(zwp_tablet_manager_v2, zwp_tablet_manager_v2_destroy, void)
# undef  INTERN_WL_CLIENT_CONCEPT

    template <wl_client T>
    auto safe_ptr(T* ptr, sloc loc = sloc::current()) {
        return aux::safe_ptr(ptr, wl_deleter<T>, loc);
    }
    template <wl_client_with_listener T>
    auto safe_ptr(T* ptr,
                  wl_listener_type<T>&& listener,
                  void* data = nullptr,
                  sloc loc = sloc::current()) {
        auto ret = safe_ptr(ptr, loc);
        if (0 != wl_proxy_add_listener(reinterpret_cast<wl_proxy*>(ptr),
                                       reinterpret_cast<void(**)(void)>(&listener),
                                       data)) {
            throw application_error("wl_proxy_add_listener failed.", loc);
        }
        return std::tuple{std::move(ret), std::move(listener)};
    }

    template <wl_client T>
    auto wl_registry_bind(wl_registry* registry, uint32_t name, uint32_t version) noexcept {
        return static_cast<T*>(::wl_registry_bind(registry, name, wl_interface_ptr<T>, version));
    }

    template <class T = uint32_t, wl_shm_format format = WL_SHM_FORMAT_XRGB8888, size_t bypp = 4>
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
            application_error("ftruncate failed...");
            close(fd);
        }
        auto data = mmap(nullptr, bypp*cx*cy, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED) {
            application_error("mmap failed...");
            close(fd);
        }
        return std::tuple{
            safe_ptr(wl_shm_pool_create_buffer(safe_ptr(wl_shm_create_pool(shm, fd, bypp*cx*cy)).get(),
                                               0, cx, cy, bypp * cx, format)),
            static_cast<T*>(data),
        };
    }

} // ::aux::wayland_client_helper

int main() {
    using namespace aux;
    try {
        auto display = safe_ptr(wl_display_connect(nullptr));
        wl_compositor* compositor_raw;
        std::vector<wl_output*> output_raw_list;
        wl_shm* shm_raw = nullptr;
        wl_seat* seat_raw = nullptr;
        zxdg_shell_v6* shell_raw = nullptr;
        zwp_tablet_manager_v2* table_raw = nullptr;
        auto [registry, registry_listener] = safe_ptr(wl_display_get_registry(display.get()), {
                .global = lamed([&](auto, wl_registry* registry,
                                    uint32_t name,
                                    std::string_view interface,
                                    uint32_t version) noexcept {
                    if (interface == wl_interface_name<wl_compositor>) {
                        compositor_raw = wl_registry_bind<wl_compositor>(registry, name, version);
                    }
                    else if (interface == wl_interface_name<wl_output>) {
                        output_raw_list.emplace_back(wl_registry_bind<wl_output>(registry, name, version));
                    }
                    else if (interface == wl_interface_name<wl_shm>) {
                        shm_raw = wl_registry_bind<wl_shm>(registry, name, version);
                    }
                    else if (interface == wl_interface_name<zxdg_shell_v6>) {
                        shell_raw = wl_registry_bind<zxdg_shell_v6>(registry, name, version);
                    }
                    else if (interface == wl_interface_name<wl_seat>) {
                        seat_raw = wl_registry_bind<wl_seat>(registry, name, version);
                    }
                    else if (interface == wl_interface_name<zwp_tablet_manager_v2>) {
                        table_raw = wl_registry_bind<zwp_tablet_manager_v2>(registry, name, version);
                    }
                }),
                .global_remove = lamed([&](auto...) {
                    throw application_error("Lost required objects...", sloc());
                }),
            });
        wl_display_roundtrip(display.get());

        auto compositor = safe_ptr(compositor_raw);

        auto output_list_view = std::views::transform(output_raw_list, [](auto ptr) {
            std::cout << "do transform!" << std::endl;
            return safe_ptr(ptr, {
                    .geometry = lamed([](auto... args) {
                        std::cout << "output geometry: " << std::tuple{args...} << std::endl;
                    }),
                    .mode = lamed([](auto... args) {
                        std::cout << "output mode: " << std::tuple{args...} << std::endl;
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
                    }),
                });
        });
        for (auto item : output_list_view) {
            auto& [output, listener] = item;
            std::cout << wl_output_get_version(output.get()) << std::endl;
        }

        auto surface = safe_ptr(wl_compositor_create_surface(compositor.get()));

        auto [shm, shm_listener] = safe_ptr(shm_raw, {
                .format = lamed([&](auto, wl_shm* shm, uint32_t format) {
                    if (format == WL_SHM_FORMAT_XRGB8888) {
                        std::cout << "OK" << std::endl;
                    }
                }),
            });

        wl_pointer* pointer_raw = nullptr;
        wl_keyboard* keyboard_raw = nullptr;
        wl_touch* touch_raw = nullptr;
        auto [seat, seat_listener] = safe_ptr(seat_raw, {
                .capabilities = lamed([&](auto, wl_seat* seat, uint32_t capabilities) noexcept {
                    if (capabilities & WL_SEAT_CAPABILITY_POINTER) {
                        pointer_raw = wl_seat_get_pointer(seat);
                    }
                    if (capabilities & WL_SEAT_CAPABILITY_KEYBOARD) {
                        keyboard_raw = wl_seat_get_keyboard(seat);
                    }
                    if (capabilities & WL_SEAT_CAPABILITY_TOUCH) {
                        touch_raw = wl_seat_get_touch(seat);
                    }
                }),
                .name = lamed(),
            });

        wl_display_roundtrip(display.get());

        size_t cx = 640;
        size_t cy = 480;
        auto [buffer, pixels] = allocate_buffer(shm.get(), cx, cy);

        auto [pointer, pointer_listener] = safe_ptr(pointer_raw, {
                .enter = lamed(),
                .leave = lamed(),
                .motion = lamed([&](auto, auto, auto, auto x, auto y) noexcept {
                    // !!!
                }),
                .button = lamed([&](auto, auto, auto, auto, auto button, auto state) noexcept {
                    // !!!
                }),
                .axis = lamed(),
                .frame = lamed(),
                .axis_source = lamed(),
                .axis_stop = lamed(),
                .axis_discrete = lamed(),
            });
        auto [keyboard, keyboard_listener] = safe_ptr(keyboard_raw, {
                .keymap = lamed(),
                .enter = lamed(),
                .leave = lamed(),
                .key = lamed([&](auto, auto, auto, auto, auto k, auto s) /*noexcept*/ {
                    std::cout << k << ':' << s << std::endl; //!!!
                    if (k == 16 && s == 0) {
                        throw application_error("quit.");
                    }
                }),
                .modifiers = lamed(),
                .repeat_info = lamed(),
            });

        std::map<int32_t, std::vector<std::complex<double>>> strokes;
        auto [touch, touch_listener] = safe_ptr(touch_raw, {
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

        auto [shell, shell_listener] = safe_ptr(shell_raw, {
                .ping = [](auto, auto shell, uint32_t serial) noexcept {
                    zxdg_shell_v6_pong(shell, serial);
                },
            });

        auto [xsurface, xsurface_listener] = safe_ptr(zxdg_shell_v6_get_xdg_surface(shell.get(), surface.get()), {
                .configure = [](auto, auto xsurface, auto serial) noexcept {
                    zxdg_surface_v6_ack_configure(xsurface, serial);
                },
            });

        auto [toplevel, toplevel_listener] = safe_ptr(zxdg_surface_v6_get_toplevel(xsurface.get()), {
                .configure = lamed([&](auto, auto, auto w, auto h, auto) {
                    cx = w;
                    cy = h;
                    if (cx && cy) {
                        auto [b, p] = allocate_buffer(shm.get(), cx, cy);
                        buffer = std::move(b);
                        pixels = p;
                    }
                }),
                .close = lamed(),
            });

        wl_surface_commit(surface.get());

        auto que = sycl::queue();
        std::cout << que.get_device().get_info<sycl::info::device::name>() << std::endl;
        std::cout << que.get_device().get_info<sycl::info::device::vendor>() << std::endl;

        while (wl_display_dispatch(display.get()) != -1) {
            if (cx && cy) {
                static constexpr size_t N = 256*256;
                static constexpr double PI = std::numbers::pi;
                static constexpr double TAU = PI * 2.0;
                static constexpr double PHI = std::numbers::phi;

                auto pv = sycl::buffer<uint32_t, 2>{pixels, {cy, cx}};
                que.submit([&](auto& h) noexcept {
                    auto apv = pv.get_access<sycl::access::mode::write>(h);
                    h.parallel_for({cy, cx}, [=](auto idx) noexcept {
                        apv[idx] = 0x00000000;
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
                                auto d = 1.0 - ((double)n/N);
                                auto y = pt.imag();
                                auto x = pt.real();
                                if (0 <= x && x < cx && 0 <= y && y < cy) {
                                    uint8_t b = d * 255;
                                    auto v = reinterpret_cast<uint8_t*>(&apv[{(size_t) y, (size_t) x}]);
                                    v[0] = std::max(v[0], b);
                                    v[1] = std::max(v[1], b);
                                    v[2] = std::max(v[2], b);
                                    v[3] = std::max(v[3], b);
                                }
                            });
                        });
                    }
                }
            }
            wl_surface_damage(surface.get(), 0, 0, cx, cy);
            wl_surface_attach(surface.get(), buffer.get(), 0, 0);
            wl_surface_commit(surface.get());
            wl_display_flush(display.get());
        }
    }
    catch (application_error& ex) {
        std::cout << ex << std::endl;
    }
    return 0;
}
