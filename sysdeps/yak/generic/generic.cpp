#include "mlibc/posix-sysdeps.hpp"
#include <abi-bits/ioctls.h>
#include <abi-bits/pid_t.h>
#include <errno.h>
#include <fcntl.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <yak/syscall.h>

namespace mlibc {

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

int sys_kill(int pid, int signal) {
	infoLogger() << "sys_kill is a stub! sys_kill(" << pid << ", " << signal << ")" << frg::endlog;
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
	return sys_ioctl(fd, TCGETS, (void *)attr, nullptr);
}

int sys_tcsetattr(int fd, int act, const struct termios *attr) {
	(void)act;
	return sys_ioctl(fd, TCSETS, (void *)attr, nullptr);
}

// In contrast to the isatty() library function, the sysdep function uses return value
// zero (and not one) to indicate that the file is a terminal.
int sys_isatty(int fd) {
	struct winsize ws;
	if (0 == sys_ioctl(fd, TIOCGWINSZ, &ws, nullptr))
		return 0;
	return ENOTTY;
}

int sys_tcgetwinsize(int fd, struct winsize *winsz) {
	return sys_ioctl(fd, TIOCGWINSZ, winsz, nullptr);
}

int sys_tcsetwinsize(int fd, const struct winsize *winsz) {
	struct winsize ws = *winsz;
	return sys_ioctl(fd, TIOCSWINSZ, &ws, nullptr);
}

int sys_chdir(const char *path) { return syscall_err(SYS_CHDIR, path); }

int sys_fchdir(int fd) { return syscall_err(SYS_FCHDIR, fd); }

int sys_read_entries(int fd, void *buffer, size_t max_size, size_t *bytes_read) {
	auto rv = syscall(SYS_GETDENTS, fd, buffer, max_size);
	*bytes_read = rv.retval;
	return rv.err;
}

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
	return syscall_err(SYS_FACCESSAT, dirfd, (uint64_t)pathname, mode, flags);
}

int sys_access(const char *path, int mode) { return sys_faccessat(AT_FDCWD, path, mode, 0); }

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	(void)ru;
	auto rv = syscall(SYS_WAITPID, pid, status, flags);
	*ret_pid = rv.retval;
	return rv.err;
}

int sys_ppoll(
    struct pollfd *fds,
    nfds_t count,
    const struct timespec *ts,
    const sigset_t *mask,
    int *num_events
) {
	auto rv = syscall(SYS_POLL, fds, count, ts, mask);
	*num_events = rv.retval;
	return rv.err;
}

int sys_poll(struct pollfd *fds, nfds_t count, int timeout_ms, int *num_events) {
	struct timespec ts;
	struct timespec *pts = NULL;

	if (timeout_ms >= 0) {
		ts.tv_sec = timeout_ms / 1000;
		ts.tv_nsec = (timeout_ms % 1000) * 1000000;
		pts = &ts;
	}

	return sys_ppoll(fds, count, pts, NULL, num_events);
}

int sys_pselect(
    int num_fds,
    fd_set *read_set,
    fd_set *write_set,
    fd_set *except_set,
    const struct timespec *timeout,
    const sigset_t *sigmask,
    int *num_events
) {
	if (num_fds < 0) {
		return EINVAL;
	}

	int nfds = 0;
	for (int fd = 0; fd < num_fds; fd++) {
		if ((read_set && FD_ISSET(fd, read_set)) || (write_set && FD_ISSET(fd, write_set))
		    || (except_set && FD_ISSET(fd, except_set)))
			nfds++;
	}

	struct pollfd *pfds = nullptr;
	if (nfds > 0) {
		pfds = (struct pollfd *)malloc(sizeof(struct pollfd) * nfds);
		if (!pfds) {
			return ENOMEM;
		}
	}

	int idx = 0;
	for (int fd = 0; fd < num_fds; fd++) {
		short events = 0;

		if (read_set && FD_ISSET(fd, read_set))
			events |= POLLIN;
		if (write_set && FD_ISSET(fd, write_set))
			events |= POLLOUT;
		if (except_set && FD_ISSET(fd, except_set))
			events |= POLLPRI;

		if (events) {
			pfds[idx].fd = fd;
			pfds[idx].events = events;
			pfds[idx].revents = 0;
			idx++;
		}
	}

	int tmp;
	int ret = sys_ppoll(pfds, nfds, timeout, sigmask, &tmp);
	if (ret != 0) {
		free(pfds);
		return ret;
	}

	if (read_set)
		FD_ZERO(read_set);
	if (write_set)
		FD_ZERO(write_set);
	if (except_set)
		FD_ZERO(except_set);

	int ready = 0;

	for (int i = 0; i < nfds; i++) {
		int fd = pfds[i].fd;
		short re = pfds[i].revents;

		if (re & (POLLIN | POLLERR | POLLHUP)) {
			if (read_set)
				FD_SET(fd, read_set);
		}
		if (re & POLLOUT) {
			if (write_set)
				FD_SET(fd, write_set);
		}
		if (re & POLLPRI) {
			if (except_set)
				FD_SET(fd, except_set);
		}

		if (re)
			ready++;
	}

	*num_events = ready;

	free(pfds);
	return 0;
}

} // namespace mlibc
