
#include <iostream>
#include <tuple>
#include <stdexcept>
#include <source_location>
#include <memory>
#include <coroutine>

#include <unistd.h>

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
    inline auto lamed(auto&& closure) noexcept {
        static auto cache = closure;
        return [](auto... args) {
            return cache(args...);
        };
    }

    struct application_error : std::runtime_error {
        std::source_location loc;
        application_error(std::source_location&& loc) noexcept
            : std::runtime_error("application error")
            , loc(loc)
            {            
            }
        template <class Ch>
        friend auto& operator<<(std::basic_ostream<Ch>& output, application_error const& ex) {
            return output << ex.loc.file_name() << ':'
                          << ex.loc.line() << ':'
                          << ex.loc.column() << ':'
                          << ex.loc.function_name();
        }
    };

    template <class T, class D>
    auto safe_ptr(T* ptr, D del, auto&& loc = std::source_location::current()) {
        if (ptr == nullptr) {
            throw application_error(std::move(loc));
        }
        return std::unique_ptr<T, D>(ptr, del);
    }

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

} // ::aux

namespace aux::inline wayland_client_helper
{
    inline auto safe_ptr(wl_display* ptr, std::source_location&& loc = std::source_location::current()) {
        return aux::safe_ptr(ptr, wl_display_disconnect, std::move(loc));
    }
#  define INTERN_SAFE_PTR(WL_CLIENT) \
    inline auto safe_ptr(WL_CLIENT* ptr, std::source_location&& loc = std::source_location::current()) {  \
        return aux::safe_ptr(ptr, WL_CLIENT##_destroy, std::move(loc)); \
    }
    INTERN_SAFE_PTR(wl_registry)
    INTERN_SAFE_PTR(wl_compositor)
    INTERN_SAFE_PTR(wl_shm)
    INTERN_SAFE_PTR(wl_seat)
    INTERN_SAFE_PTR(wl_surface)
    INTERN_SAFE_PTR(wl_keyboard)
    INTERN_SAFE_PTR(wl_pointer)
    INTERN_SAFE_PTR(wl_touch)
    INTERN_SAFE_PTR(zxdg_shell_v6)
    INTERN_SAFE_PTR(zxdg_surface_v6)
    INTERN_SAFE_PTR(zwp_tablet_manager_v2)
#  undef INTERN_SAFE_PTR

    template <class WL_CLIENT> struct wl_listener { using type = void; };
#  define INTERN_LISTENER(WL_CLIENT)                                      \
    template <> struct wl_listener<WL_CLIENT> { using type = WL_CLIENT##_listener; };
    INTERN_LISTENER(wl_registry)
    INTERN_LISTENER(wl_seat)
    INTERN_LISTENER(zxdg_shell_v6)
    INTERN_LISTENER(zxdg_surface_v6)
    INTERN_LISTENER(wl_pointer)
    INTERN_LISTENER(wl_keyboard)
    INTERN_LISTENER(wl_touch)
#  undef INTERN_LISTENER

    template <class WL_CLIENT>
    auto add_listener(WL_CLIENT* client,
                      typename wl_listener<WL_CLIENT>::type&& listener,
                      void* data = nullptr,
                      std::source_location&& loc = std::source_location::current()) {
        if (0 != wl_proxy_add_listener(reinterpret_cast<wl_proxy*>(client),
                                       reinterpret_cast<void(**)(void)>(&listener),
                                       data)) {
            throw loc;
        }
        return listener;
    }

    template <class> constexpr wl_interface const *const interface_pointer = nullptr;
#  define INTERN_INTERFACE(WL_CLIENT)                                     \
    template <> constexpr wl_interface const *const interface_pointer<WL_CLIENT> = &WL_CLIENT##_interface;
    INTERN_INTERFACE(wl_compositor)
    INTERN_INTERFACE(wl_shm)
    INTERN_INTERFACE(wl_seat)
    INTERN_INTERFACE(zxdg_shell_v6)
    INTERN_INTERFACE(zwp_tablet_manager_v2)
#  undef INTERN_INTERFACE

} // ::aux::wayland_client_helper

int main() {
    try {
        auto display = aux::safe_ptr(wl_display_connect(nullptr));
        auto registry = aux::safe_ptr(wl_display_get_registry(display.get()));

        auto registry_listener = aux::add_listener(registry.get(), {
                .global = aux::lamed([&](auto...) {
                }),
                .global_remove = aux::lamed([&](auto...) {
                    throw aux::application_error(std::source_location());
                }),
            });
    }
    catch (aux::application_error& ex) {
        std::cout << ex << std::endl;
    }
    return 0;
}
