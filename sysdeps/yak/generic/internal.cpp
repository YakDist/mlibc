#include <abi-bits/ioctls.h>
#include <abi-bits/mode_t.h>
#include <abi-bits/vm-flags.h>
#include <bits/ansi/timespec.h>
#include <bits/ensure.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/fsfd_target.hpp>
#include <mlibc/sysdeps.hpp>
#include <stddef.h>
#include <stdlib.h>
#include <yak/arch-syscall.h>
#include <yak/syscall.h>

namespace mlibc {
void Sysdeps<LibcLog>::operator()(const char *message) { syscall(SYS_DEBUG_LOG, message); }

#define STUB                                                                                       \
	do {                                                                                           \
		sys_libc_log("STUB:");                                                                     \
		sys_libc_log(__func__);                                                                    \
		__ensure(!"STUB CALLED");                                                                  \
		__builtin_unreachable();                                                                   \
	} while (0)

int Sysdeps<TcbSet>::operator()(void *pointer) {
#if defined(__x86_64__)
	syscall(SYS_ARCHCTL, ARCHCTL_SET_FSBASE, pointer);
#else
#error "Arch unsupported"
#endif
	return 0;
}

int Sysdeps<VmMap>::operator()(
    void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window
) {
	auto rv = syscall(SYS_MMAP, hint, size, prot, flags, fd, offset);
	*window = (void *)rv.retval;
	return rv.err;
}

int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
	return syscall_err(SYS_MUNMAP, pointer, size);
}

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
	__ensure(pointer);
	__ensure(size > 0);
	return sysdep<VmMap>(
	    NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, pointer
	);
}

int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
	return sysdep<VmUnmap>(pointer, size);
}

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
	auto rv = syscall(SYS_SEEK, fd, offset, whence);
	*new_offset = rv.retval;
	return rv.err;
}

int Sysdeps<Read>::operator()(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	auto rv = syscall(SYS_READ, fd, buf, count);
	*bytes_read = rv.retval;
	return rv.err;
}

int Sysdeps<Close>::operator()(int fd) { return syscall_err(SYS_CLOSE, fd); }

int Sysdeps<Openat>::operator()(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	auto rv = syscall(SYS_OPENAT, dirfd, path, flags, mode);
	*fd = rv.retval;
	return rv.err;
}

int Sysdeps<Stat>::operator()(
    fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf
) {
	if (fsfdt == fsfd_target::path)
		fd = AT_FDCWD;
	else if (fsfdt == fsfd_target::fd)
		flags |= AT_EMPTY_PATH;
	else
		__ensure(fsfdt == fsfd_target::fd_path);

	return syscall_err(SYS_FSTATAT, fd, path, statbuf, flags);
}

int Sysdeps<Open>::operator()(const char *pathname, int flags, mode_t mode, int *fd) {
	return sysdep<Openat>(AT_FDCWD, pathname, flags, mode, fd);
}

int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const timespec *time) {
	sysdep<LibcLog>("sys_futex_wait is a stub!");
	return 0;
}

int Sysdeps<FutexWake>::operator()(int *pointer, bool all) {
	sysdep<LibcLog>("sys_futex_wake is a stub!");
	return 0;
}

int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
	struct timespec ts;
	auto rv = syscall(SYS_CLOCK_GET, clock, &ts);
	*secs = ts.tv_sec;
	*nanos = ts.tv_nsec;
	return rv.err;
}

[[noreturn]] void Sysdeps<Exit>::operator()(int status) {
	syscall(SYS_EXIT, status);
	__builtin_unreachable();
}

void Sysdeps<LibcPanic>::operator()() {
	sysdep<LibcLog>("unrecoverable MLIBC PANIC :(\n");
	sysdep<Exit>(-1);
	__builtin_unreachable();
}

int Sysdeps<Write>::operator()(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
	auto rv = syscall(SYS_WRITE, fd, buf, count);
	*bytes_written = rv.retval;
	return rv.err;
}

int Sysdeps<VmProtect>::operator()(void *pointer, size_t size, int prot) {

	return syscall_err(SYS_MPROTECT, pointer, size, prot);
}

} // namespace mlibc
