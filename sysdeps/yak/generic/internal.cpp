#include "mlibc/ansi-sysdeps.hpp"
#include "mlibc/debug.hpp"
#include "mlibc/posix-sysdeps.hpp"
#include <abi-bits/mode_t.h>
#include <abi-bits/vm-flags.h>
#include <alloca.h>
#include <bits/ansi/timespec.h>
#include <bits/ensure.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
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
	return rv.errno;
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
	return rv.errno;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	auto rv = syscall(SYS_READ, fd, buf, count);
	*bytes_read = rv.retval;
	return rv.errno;
}

int sys_close(int fd) { return syscall_err(SYS_CLOSE, fd); }

int sys_open(const char *pathname, int flags, mode_t mode, int *fd) {
	auto rv = syscall(SYS_OPEN, pathname, flags, mode);
	*fd = rv.retval;
	return rv.errno;
}

int sys_futex_wait(int *pointer, int expected, const timespec *time) { STUB; }

int sys_futex_wake(int *pointer) { STUB; }

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
	return rv.errno;
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
	return rv.errno;
}

int sys_getsid(pid_t pid, pid_t *sid) {
	auto rv = syscall(SYS_GETSID, pid);
	*sid = rv.retval;
	return rv.errno;
}

int sys_setpgid(pid_t pid, pid_t pgid) { return syscall_err(SYS_SETPGID, pid, pgid); }

int sys_setsid(pid_t *sid) {
	auto rv = syscall(SYS_SETSID);
	*sid = rv.retval;
	return rv.errno;
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

	return rv.errno;
}

int sys_dup(int fd, [[maybe_unused]] int flags, int *newfd) {
	auto rv = syscall(SYS_DUP2, fd, -1);
	*newfd = rv.retval;
	return rv.errno;
}

int sys_dup2(int fd, [[maybe_unused]] int flags, int newfd) {
	auto rv = syscall(SYS_DUP2, fd, newfd);
	return rv.errno;
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

	return rv.errno;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
	return syscall_err(SYS_EXECVE, path, argv, envp);
}

/* yak implements a linux-style fallocate */
int sys_fallocate(int fd, off_t offset, size_t size) {
	return syscall_err(SYS_FALLOCATE, fd, 0, offset, size);
}

} // namespace mlibc
