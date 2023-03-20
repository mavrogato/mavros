
#include <iostream>
#include <tuple>
#include <stdexcept>
#include <source_location>
#include <filesystem>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <wayland-client.hpp>
#include <wayland-client-protocol-extra.hpp>
// #include "xdg-shell-v6-client.h"
// #include "zwp-tablet-v2-client.h"

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
        //requires std::derived_from<std::tuple_size<T>, std::integral_constant<size_t, std::tuple_size_v<T>>>;
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
} // ::std

namespace aux
{
    class safe_fd final {
    public:
        safe_fd(safe_fd const&) = delete;
        auto& operator=(safe_fd const&) = delete;

        explicit safe_fd(int fd, auto&& loc = std::source_location::current()) : fd(fd) {
            if (fd == -1) {
                throw application_error(std::move(loc));
            }
        }

        safe_fd(safe_fd&& other) noexcept : fd(std::exchange(other.fd, -1)) { }
        safe_fd& operator=(safe_fd&& other) noexcept {
            this->fd = std::exchange(other.fd, this->fd);
            return *this;
        }

        ~safe_fd() noexcept {
            if (this->fd != -1) {
                close(fd);
                this->fd = -1;
            }
        }

    public:
        operator int() const noexcept { return fd; }

    private:
        int fd;
    };
}

int main() {
    wayland::display_t display;
    if (false == display) {
        return -1;
    }
    wayland::registry_t registry = display.get_registry();
    wayland::compositor_t compositor;
    wayland::xdg_wm_base_t shell;
    wayland::seat_t seat;
    wayland::shm_t shm;
    registry.on_global() = [&](uint32_t name, std::string_view interface, uint32_t version) {
        if (interface == wayland::compositor_t::interface_name) {
            registry.bind(name, compositor, version);
        }
        else if (interface == wayland::xdg_wm_base_t::interface_name) {
            registry.bind(name, shell, version);
        }
        else if (interface == wayland::seat_t::interface_name) {
            registry.bind(name, seat, version);
        }
        else if (interface == wayland::shm_t::interface_name) {
            registry.bind(name, shm, version);
        }
    };
    display.roundtrip();
    if (false == compositor && shell && seat && shm) {
        return -1;
    }

    auto surface = compositor.create_surface();
    shell.on_ping() = [&](uint32_t serial) noexcept { shell.pong(serial); };
    auto xsurface = shell.get_xdg_surface(surface);
    xsurface.on_configure() = [&](uint32_t serial) noexcept { xsurface.ack_configure(serial); };
    auto toplevel = xsurface.get_toplevel();
    toplevel.set_title("default caption");
    bool running = true;
    toplevel.on_close() = [&]() noexcept { running = false; };

    bool has_keyboard = false;
    bool has_pointer = false;
    bool has_touch = false;
    seat.on_capabilities() = [&](auto capability) {
        has_keyboard = capability & wayland::seat_capability::keyboard;
        has_pointer = capability & wayland::seat_capability::pointer;
        has_touch = capability & wayland::seat_capability::touch;
    };
    display.roundtrip();
    if (false == has_keyboard && has_pointer && has_touch) {
        return -1;
    }
    auto keyboard = seat.get_keyboard();
    auto pointer = seat.get_pointer();
    auto touch = seat.get_touch();

    std::string_view xdg_runtime_dir = std::getenv("XDG_RUNTIME_DIR");
    if (xdg_runtime_dir.empty() || !std::filesystem::exists(xdg_runtime_dir)) {
        return -1;
    }
    std::string_view tmp_file_title = "/weston-shared-XXXXXX";
    if (1024 <= xdg_runtime_dir.size() + tmp_file_title.size()) {
        return -1;
    }
    char tmp_path[1024] = { };
    auto p = std::strcat(tmp_path, xdg_runtime_dir.data());
    std::strcat(p, tmp_file_title.data());
    int fd = mkostemp(tmp_path, O_CLOEXEC);
    if (fd >= 0) {
        unlink(tmp_path);
    }
    else {
        std::cerr << "Failed to mkostemp..." << std::endl;
        return -1;
    }
    constexpr int cx = 640;
    constexpr int cy = 480;
    if (ftruncate(fd, 4*cx*cy) < 0) {
        std::cerr << "Failed to ftruncate..." << std::endl;
        close(fd);
        return -1;
    }
    auto data = mmap(nullptr, 4*cx*cy, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) {
        std::cerr << "Failed to mmap..." << std::endl;
        close(fd);
        return -1;
    }
    auto buffer = shm.create_pool(fd, 4*cx*cy).create_buffer(0, cx, cy, cx*4, wayland::shm_format::xrgb8888);

    surface.attach(buffer, 0, 0);
    surface.damage(0, 0, cx, cy);
    surface.commit();

    while (running) {
        display.dispatch();
    }
    return 0;
}
