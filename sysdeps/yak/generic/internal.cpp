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
#include <stddef.h>
#include <stdlib.h>
#include <yak/arch-syscall.h>
#include <yak/syscall.h>

namespace mlibc {
void sys_libc_log(const char *message) { syscall(SYS_DEBUG_LOG, message); }

#define STUB                                                                                       \
	do {                                                                                           \
		sys_libc_log("STUB:");                                                                     \
		sys_libc_log(__func__);                                                                    \
		__ensure(!"STUB CALLED");                                                                  \
		__builtin_unreachable();                                                                   \
	} while (0)

int sys_tcb_set(void *pointer) {
#if defined(__x86_64__)
	syscall(SYS_ARCHCTL, ARCHCTL_SET_FSBASE, pointer);
#else
#error "Arch unsupported"
#endif
	return 0;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	auto rv = syscall(SYS_MMAP, hint, size, prot, flags, fd, offset);
	*window = (void *)rv.retval;
	return rv.err;
}

int sys_vm_unmap(void *pointer, size_t size) { return syscall_err(SYS_MUNMAP, pointer, size); }

int sys_anon_allocate(size_t size, void **pointer) {
	__ensure(pointer);
	__ensure(size > 0);
	return sys_vm_map(
	    NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, pointer
	);
}

int sys_anon_free(void *pointer, size_t size) { return sys_vm_unmap(pointer, size); }

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	auto rv = syscall(SYS_SEEK, fd, offset, whence);
	*new_offset = rv.retval;
	return rv.err;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	auto rv = syscall(SYS_READ, fd, buf, count);
	*bytes_read = rv.retval;
	return rv.err;
}

int sys_close(int fd) { return syscall_err(SYS_CLOSE, fd); }

int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	auto rv = syscall(SYS_OPENAT, dirfd, path, flags, mode);
	*fd = rv.retval;
	return rv.err;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
	if (fsfdt == fsfd_target::path)
		fd = AT_FDCWD;
	else if (fsfdt == fsfd_target::fd)
		flags |= AT_EMPTY_PATH;
	else
		__ensure(fsfdt == fsfd_target::fd_path);

	return syscall_err(SYS_FSTATAT, fd, path, statbuf, flags);
}

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
	return sys_openat(AT_FDCWD, pathname, flags, mode, fd);
}

int sys_futex_wait(int *pointer, int expected, const timespec *time) {
	sys_libc_log("sys_futex_wait is a stub!");
	return 0;
}

int sys_futex_wake(int *pointer) {
	sys_libc_log("sys_futex_wake is a stub!");
	return 0;
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	static int i;
	return i++;
}

[[noreturn]] void sys_exit(int status) {
	syscall(SYS_EXIT, status);
	__builtin_unreachable();
}

void sys_libc_panic() {
	sys_libc_log("unrecoverable MLIBC PANIC :(\n");
	sys_exit(-1);
	__builtin_unreachable();
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
	auto rv = syscall(SYS_WRITE, fd, buf, count);
	*bytes_written = rv.retval;
	return rv.err;
}

int sys_vm_protect(void *pointer, size_t size, int prot) {

	return syscall_err(SYS_MPROTECT, pointer, size, prot);
}

} // namespace mlibc
