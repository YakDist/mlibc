#include "bits/winsize.h"
#include "mlibc/ansi-sysdeps.hpp"
#include "mlibc/fsfd_target.hpp"
#include "mlibc/posix-sysdeps.hpp"
#include <abi-bits/ioctls.h>
#include <abi-bits/mode_t.h>
#include <abi-bits/vm-flags.h>
#include <alloca.h>
#include <bits/ansi/timespec.h>
#include <bits/ensure.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <errno.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <stddef.h>
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

gid_t sys_getgid() { return 0; }
gid_t sys_getegid() { return 0; }
uid_t sys_getuid() { return 0; }
uid_t sys_geteuid() { return 0; }

pid_t sys_getpid() { return syscall_rv(SYS_GETPID); }
pid_t sys_getppid() { return syscall_rv(SYS_GETPPID); }

int sys_getpgid(pid_t pid, pid_t *pgid) {
	auto rv = syscall(SYS_GETPGID, pid);
	*pgid = rv.retval;
	return rv.err;
}

int sys_getsid(pid_t pid, pid_t *sid) {
	auto rv = syscall(SYS_GETSID, pid);
	*sid = rv.retval;
	return rv.err;
}

int sys_setpgid(pid_t pid, pid_t pgid) { return syscall_err(SYS_SETPGID, pid, pgid); }

int sys_setsid(pid_t *sid) {
	auto rv = syscall(SYS_SETSID);
	*sid = rv.retval;
	return rv.err;
}

int sys_sleep(time_t *secs, long *nanos) {
	struct timespec req = {
	    .tv_sec = *secs,
	    .tv_nsec = *nanos,
	};
	struct timespec rem = {0, 0};

	auto rv = syscall(SYS_SLEEP, &req, &rem);
	*secs = rem.tv_sec;
	*nanos = rem.tv_nsec;

	return rv.err;
}

int sys_dup(int fd, [[maybe_unused]] int flags, int *newfd) {
	auto rv = syscall(SYS_DUP2, fd, -1);
	*newfd = rv.retval;
	return rv.err;
}

int sys_dup2(int fd, [[maybe_unused]] int flags, int newfd) {
	auto rv = syscall(SYS_DUP2, fd, newfd);
	return rv.err;
}

int sys_fork(pid_t *child) {

	auto rv = syscall(SYS_FORK);
	*child = rv.retval;

#if 0
	uintptr_t rsp;
	asm volatile("mov %%rsp, %0" : "=r"(rsp));
	infoLogger() << "rsp: " << (void *)rsp << frg::endlog;
	infoLogger() << "our pid: " << sys_getpid() << frg::endlog;
	infoLogger() << "return address: " << __builtin_return_address(0) << frg::endlog;
#endif

	return rv.err;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
	return syscall_err(SYS_EXECVE, path, argv, envp);
}

/* yak implements a linux-style fallocate */
int sys_fallocate(int fd, off_t offset, size_t size) {
	return syscall_err(SYS_FALLOCATE, fd, 0, offset, size);
}

int sys_sigaction(
    int signum, const struct sigaction *__restrict act, struct sigaction *__restrict oldact
) {
	infoLogger() << "sys_sigaction is a stub! sys_sigaction(" << signum << ", " << (void *)act
	             << ", " << oldact << ")" << frg::endlog;
	return 0;
}

int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {

	infoLogger() << "sys_sigprocmask is a stub! sys_sigprocmask(" << how << ", " << (void *)set
	             << ", " << retrieve << ")" << frg::endlog;
	return 0;
}

int sys_fcntl(int fd, int request, va_list args, int *result) {
	size_t arg = va_arg(args, size_t);
	auto rv = syscall(SYS_FCNTL, fd, request, arg);
	*result = rv.retval;
	return rv.err;
}

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
	auto rv = syscall(SYS_IOCTL, fd, request, arg);
	if (result)
		*result = rv.retval;
	return rv.err;
}

int sys_tcgetattr(int fd, struct termios *attr) {
	return sys_ioctl(fd, TCGETS, (void *)attr, NULL);
}

int sys_tcsetattr(int fd, int act, const struct termios *attr) {
	(void)act;
	return sys_ioctl(fd, TCSETS, (void *)attr, NULL);
}

// In contrast to the isatty() library function, the sysdep function uses return value
// zero (and not one) to indicate that the file is a terminal.
int sys_isatty(int fd) {
	struct winsize ws;
	if (0 == sys_ioctl(fd, TIOCGWINSZ, &ws, NULL))
		return 0;
	return ENOTTY;
}

int sys_tcgetwinsize(int fd, struct winsize *winsz) {
	return sys_ioctl(fd, TIOCGWINSZ, winsz, NULL);
}

int sys_tcsetwinsize(int fd, const struct winsize *winsz) {
	struct winsize ws = *winsz;
	return sys_ioctl(fd, TIOCSWINSZ, &ws, NULL);
}

int sys_chdir(const char *path) { return syscall_err(SYS_CHDIR, path); }

int sys_fchdir(int fd) { return syscall_err(SYS_FCHDIR, fd); }

int sys_read_entries(int fd, void *buffer, size_t max_size, size_t *bytes_read) {
	auto rv = syscall(SYS_GETDENTS, fd, buffer, max_size);
	*bytes_read = rv.retval;
	return rv.err;
}

} // namespace mlibc
