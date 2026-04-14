#include <abi-bits/ioctls.h>
#include <abi-bits/pid_t.h>
#include <cstddef>
#include <errno.h>
#include <fcntl.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/sysdeps.hpp>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <yak/syscall.h>

namespace mlibc {

gid_t Sysdeps<GetGid>::operator()() { return 0; }

gid_t Sysdeps<GetEgid>::operator()() { return 0; }

uid_t Sysdeps<GetUid>::operator()() { return 0; }

uid_t Sysdeps<GetEuid>::operator()() { return 0; }

pid_t Sysdeps<GetPid>::operator()() { return syscall_rv(SYS_GETPID); }

pid_t Sysdeps<GetPpid>::operator()() { return syscall_rv(SYS_GETPPID); }

int Sysdeps<GetPgid>::operator()(pid_t pid, pid_t *pgid) {
	auto rv = syscall(SYS_GETPGID, pid);
	*pgid = rv.retval;
	return rv.err;
}

int Sysdeps<GetSid>::operator()(pid_t pid, pid_t *sid) {
	auto rv = syscall(SYS_GETSID, pid);
	*sid = rv.retval;
	return rv.err;
}

int Sysdeps<SetPgid>::operator()(pid_t pid, pid_t pgid) {
	return syscall_err(SYS_SETPGID, pid, pgid);
}

int Sysdeps<SetSid>::operator()(pid_t *sid) {
	auto rv = syscall(SYS_SETSID);
	*sid = rv.retval;
	return rv.err;
}

int Sysdeps<Sleep>::operator()(time_t *secs, long *nanos) {
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

int Sysdeps<Dup>::operator()(int fd, [[maybe_unused]] int flags, int *newfd) {
	auto rv = syscall(SYS_DUP2, fd, -1);
	*newfd = rv.retval;
	return rv.err;
}

int Sysdeps<Dup2>::operator()(int fd, [[maybe_unused]] int flags, int newfd) {
	auto rv = syscall(SYS_DUP2, fd, newfd);
	return rv.err;
}

int Sysdeps<Fork>::operator()(pid_t *child) {

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

int Sysdeps<Execve>::operator()(const char *path, char *const argv[], char *const envp[]) {
	return syscall_err(SYS_EXECVE, path, argv, envp);
}

/* yak implements a linux-style fallocate */
int Sysdeps<Fallocate>::operator()(int fd, off_t offset, size_t size) {
	return syscall_err(SYS_FALLOCATE, fd, 0, offset, size);
}

int Sysdeps<Sigaction>::operator()(
    int signum, const struct sigaction *__restrict act, struct sigaction *__restrict oldact
) {
#if 0
	infoLogger() << "sys_sigaction is a stub! sys_sigaction(" << signum << ", " << (void *)act
	             << ", " << oldact << ")" << frg::endlog;
#endif
	return 0;
}

int Sysdeps<Sigprocmask>::operator()(
    int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve
) {

#if 0
	infoLogger() << "sys_sigprocmask is a stub! sys_sigprocmask(" << how << ", " << (void *)set
	             << ", " << retrieve << ")" << frg::endlog;
#endif
	return 0;
}

int Sysdeps<Kill>::operator()(int pid, int signal) {
	infoLogger() << "sys_kill is a stub! sys_kill(" << pid << ", " << signal << ")" << frg::endlog;
	return 0;
}

int Sysdeps<Fcntl>::operator()(int fd, int request, va_list args, int *result) {
	size_t arg = va_arg(args, size_t);
	auto rv = syscall(SYS_FCNTL, fd, request, arg);
	*result = rv.retval;
	return rv.err;
}

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *arg, int *result) {
	auto rv = syscall(SYS_IOCTL, fd, request, arg);
	if (result)
		*result = rv.retval;
	return rv.err;
}

int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
	return sysdep<Ioctl>(fd, TCGETS, (void *)attr, nullptr);
}

int Sysdeps<Tcsetattr>::operator()(int fd, int act, const struct termios *attr) {
	(void)act;
	return sysdep<Ioctl>(fd, TCSETS, (void *)attr, nullptr);
}

// In contrast to the isatty() library function, the sysdep function uses return value
// zero (and not one) to indicate that the file is a terminal.
int Sysdeps<Isatty>::operator()(int fd) {
	struct winsize ws;
	if (0 == sysdep<Ioctl>(fd, TIOCGWINSZ, &ws, nullptr))
		return 0;
	return ENOTTY;
}

int Sysdeps<Tcgetwinsize>::operator()(int fd, struct winsize *winsz) {
	return sysdep<Ioctl>(fd, TIOCGWINSZ, winsz, nullptr);
}

int Sysdeps<Tcsetwinsize>::operator()(int fd, const struct winsize *winsz) {
	struct winsize ws = *winsz;
	return sysdep<Ioctl>(fd, TIOCSWINSZ, &ws, nullptr);
}

int Sysdeps<Chdir>::operator()(const char *path) { return syscall_err(SYS_CHDIR, path); }

int Sysdeps<Fchdir>::operator()(int fd) { return syscall_err(SYS_FCHDIR, fd); }

int Sysdeps<ReadEntries>::operator()(int fd, void *buffer, size_t max_size, size_t *bytes_read) {
	auto rv = syscall(SYS_GETDENTS, fd, buffer, max_size);
	*bytes_read = rv.retval;
	return rv.err;
}

int Sysdeps<Faccessat>::operator()(int dirfd, const char *pathname, int mode, int flags) {
	return syscall_err(SYS_FACCESSAT, dirfd, (uint64_t)pathname, mode, flags);
}

int Sysdeps<Access>::operator()(const char *path, int mode) {
	return sysdep<Faccessat>(AT_FDCWD, path, mode, 0);
}

int
Sysdeps<Waitpid>::operator()(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	(void)ru;
	auto rv = syscall(SYS_WAITPID, pid, status, flags);
	*ret_pid = rv.retval;
	return rv.err;
}

int Sysdeps<Ppoll>::operator()(
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

int Sysdeps<Poll>::operator()(struct pollfd *fds, nfds_t count, int timeout_ms, int *num_events) {
	struct timespec ts;
	struct timespec *pts = NULL;

	if (timeout_ms >= 0) {
		ts.tv_sec = timeout_ms / 1000;
		ts.tv_nsec = (timeout_ms % 1000) * 1000000;
		pts = &ts;
	}

	return sysdep<Ppoll>(fds, count, pts, NULL, num_events);
}

int Sysdeps<Pselect>::operator()(
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
	int ret = sysdep<Ppoll>(pfds, nfds, timeout, sigmask, &tmp);
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

int Sysdeps<OpenDir>::operator()(const char *path, int *handle) {
	return sysdep<Open>(path, O_DIRECTORY, 0, handle);
}

int Sysdeps<Readlinkat>::operator()(
    int dirfd, const char *path, void *buffer, size_t max_size, ssize_t *length
) {
	auto rv = syscall(SYS_READLINKAT, dirfd, path, buffer, max_size);
	*length = rv.retval;
	return rv.err;
}

int
Sysdeps<Readlink>::operator()(const char *path, void *buffer, size_t max_size, ssize_t *length) {
	return sysdep<Readlinkat>(AT_FDCWD, path, buffer, max_size, length);
}

int Sysdeps<Linkat>::operator()(
    int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags
) {
	return syscall_err(SYS_LINKAT, olddirfd, old_path, newdirfd, new_path, flags);
}

int Sysdeps<Link>::operator()(const char *old_path, const char *new_path) {
	return sysdep<Linkat>(AT_FDCWD, old_path, AT_FDCWD, new_path, 0);
}

int Sysdeps<Symlinkat>::operator()(const char *target_path, int dirfd, const char *link_path) {
	return syscall_err(SYS_SYMLINKAT, dirfd, target_path, link_path);
}

int Sysdeps<Symlink>::operator()(const char *target_path, const char *link_path) {
	return sysdep<Symlinkat>(target_path, AT_FDCWD, link_path);
}

int Sysdeps<Pread>::operator()(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	auto rv = syscall(SYS_PREAD, fd, buf, n, off);
	*bytes_read = rv.retval;
	return rv.err;
}

int Sysdeps<Pwrite>::operator()(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_read) {

	auto rv = syscall(SYS_PWRITE, fd, buf, n, off);
	*bytes_read = rv.retval;
	return rv.err;
}

} // namespace mlibc
