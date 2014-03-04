/*
 * FD polling functions for SunOS event ports.
 *
 * Copyright 2014 Joyent, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <poll.h>
#include <port.h>

#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/log.h>
#include <proto/signal.h>
#include <proto/task.h>

/*
 * The assertions in this file are cheap and we always want them enabled.
 */
#ifdef NDEBUG
#undef NDEBUG
#include <assert.h>
#define NDEBUG
#else
#include <assert.h>
#endif

/*
 * NOTE: All of the functions in this file should logically be marked "static",
 * but this causes gcc 4.6.2 with "-O2" to generate code that violates the i386
 * ABI, passing arguments in registers rather than on the stack.  This makes
 * debuggability a nightmare, and isn't worth the optimization.
 */
int  ev_do_init(struct poller *);
void ev_do_term(struct poller *);
int  ev_do_test(struct poller *);
void ev_do_poll(struct poller *, int);

int  ev_fd_is_set(const int fd, int dir);
int  ev_fd_set(const int fd, int dir);
int  ev_fd_clr(const int fd, int dir);
void ev_fd_rem(const int fd);
void ev_fd_clo(const int fd);

int  ev_fd_events(const int fd);
void ev_fd_update(const int fd);

/*
 * Like the kqueue() and poll()-based pollers, the event ports poller keeps
 * track of the intended state of each fd's associations using a pair of fd_sets
 * (bitmasks) in "evp_evts".  This bitmask is updated by the
 * ev_fd_{set,clr,rem,clo} functions.  Changes are registered with the event
 * port using ev_fd_update().
 */
static fd_set 		*evp_evts[2];	/* bitmasks for read/write assocs.  */
static port_event_t	*evp_events;	/* list of events for port_getn() */
static int 		evp_nevents;	/* size of evp_events */
static int 		evp_port;	/* event port fd */
static int 		evp_pollfd;	/* fd being processed in ev_do_poll() */

/*
 * Given an haproxy "direction", return the corresponding poll(2) events.
 */
#define	DIR2POLLEVENT(dir) ((dir) == DIR_RD ? POLLIN : POLLOUT)

/*
 * It is a constructor, which means that it will automatically be called before
 * main(). This is GCC-specific but it works at least since 2.95.
 * Special care must be taken so that it does not need any uninitialized data.
 */
__attribute__((constructor))
void ev_do_register(void)
{
	struct poller *p;

	if (nbpollers >= MAX_POLLERS)
		return;

	evp_port = -1;
	p = &pollers[nbpollers++];

	p->name = "evports";
	p->pref = 300;
	p->private = NULL;

	p->test = ev_do_test;
	p->init = ev_do_init;
	p->term = ev_do_term;
	p->poll = ev_do_poll;

	p->is_set  = ev_fd_is_set;
	p->cond_s = p->set = ev_fd_set;
	p->cond_c = p->clr = ev_fd_clr;
	p->rem = ev_fd_rem;
	p->clo = ev_fd_clo;
}


/*
 * Entry points
 */

/*
 * Initialization of the event ports poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
int ev_do_init(struct poller *p)
{
	int fd_set_bytes;

	/*
	 * Like the "kqueue" poller, we track fd state using a pair of bitmasks,
	 * each implemented as an array of "fd_set" objects and using the
	 * existing FD_SET/FD_CLR/FD_ISSET macros to manipulate them.
	 */
	fd_set_bytes = sizeof(fd_set) *
	    ((global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE);
	evp_pollfd = -1;
	evp_port = port_create();
	evp_nevents = global.tune.maxpollevents;
	evp_events = (port_event_t *)calloc(evp_nevents, sizeof(port_event_t));
	evp_evts[DIR_RD] = (fd_set *)calloc(1, fd_set_bytes);
	evp_evts[DIR_WR] = (fd_set *)calloc(1, fd_set_bytes);

	if (evp_port < 0 || evp_events == NULL ||
	    evp_evts[DIR_RD] == NULL || evp_evts[DIR_WR] == NULL) {
		Alert("failed to initialize event ports backend\n");
		ev_do_term(p);
		return 0;
	}

	p->pref = 300;
	return 1;
}

/*
 * Termination of the event ports poller.
 * Memory is released and the poller is marked as unselectable.
 */
void ev_do_term(struct poller *p)
{
	free(evp_evts[DIR_WR]);
	free(evp_evts[DIR_RD]);
	free(evp_events);

	if (evp_port >= 0) {
		close(evp_port);
		evp_port = -1;
	}

	p->pref = 0;
}

/*
 * Check that the poller works.
 * Returns 1 if OK, otherwise 0.
 */
int ev_do_test(struct poller *p)
{
	int fd;

	fd = port_create();
	if (fd < 0)
		return 0;
	close(fd);
	return 1;
}

/*
 * Event ports poller
 */
void ev_do_poll(struct poller *p, int exp)
{
	int wait_time, status, fd;
	unsigned int i, count, handled;
	port_event_t *ev;
	struct timespec timeout;

	/* now let's wait for events */
	if (run_queue || signal_queue_len)
		wait_time = 0;
	else if (!exp)
		wait_time = MAX_DELAY_MS;
	else if (tick_is_expired(exp, now_ms))
		wait_time = 0;
	else {
		wait_time = TICKS_TO_MS(tick_remain(now_ms, exp)) + 1;
		if (wait_time > MAX_DELAY_MS)
			wait_time = MAX_DELAY_MS;
	}

	timeout.tv_sec = wait_time / 1000;
	timeout.tv_nsec = (wait_time % 1000) * 1000000;
	count = 1;
	status = port_getn(evp_port, evp_events, evp_nevents, &count, &timeout);

	/*
	 * Recall that contrary to the man page, port_getn can return -1 with
	 * errno == ETIME and still have returned events, so we treat the ETIME
	 * case as a success.
	 */
	if (status == -1 && errno != ETIME) {
		assert(errno == EINTR);
		tv_update_date(wait_time, 1);
		return;
	}

	/*
	 * Process each of the events we've seen.  This looks similar to the
	 * other pollers, except that we must reassociate the file descriptor
	 * with the event port after the caller has handled each event.
	 * Importantly, it's possible that the callback that we invoke to
	 * process each event may call back into this module to set or clear an
	 * association, remove both associations, or even close the file
	 * descriptor.  In such cases, when we finish handling events for this
	 * fd, we must be careful to reassociate the previous events (if nothing
	 * was changed), create a new association for newly-registered events,
	 * or even skip the reassociation altogether (if the fd was closed by
	 * one of the callbacks).  Since we're single-threaded and event-based,
	 * we deal with this by recording the fd that's currently being
	 * processed into the global "evp_pollfd".  If the user changes
	 * associations for this fd while we're in this code path, we defer the
	 * change until we would normally reassociate the fd (after handling).
	 */
	assert(status == 0 || errno == ETIME);
	tv_update_date(wait_time, status == 0);
	for (i = 0; i < count; i++) {
		ev = &evp_events[i];
		fd = ev->portev_object;
		evp_pollfd = fd;
		handled = 0;

		if (FD_ISSET(fd, evp_evts[DIR_RD])) {
			if (fdtab[fd].state == FD_STCLOSE)
				continue;
			if (ev->portev_events & (POLLIN | POLLERR | POLLHUP)) {
				fdtab[fd].cb[DIR_RD].f(fd);
				handled++;
			}
		}

		if (FD_ISSET(fd, evp_evts[DIR_WR])) {
			if (fdtab[fd].state == FD_STCLOSE)
				continue;
			if (ev->portev_events & (POLLOUT | POLLERR | POLLHUP)) {
				fdtab[fd].cb[DIR_WR].f(fd);
				handled++;
			}
		}

		/*
		 * If we handled any events for this file descriptor, and there
		 * are still some associations for it, then re-establish those
		 * associations with the port now.  Although ev_fd_update() is
		 * idempotent (calling it when there are no associations would
		 * only cause a spurious port_dissociate() call, and that should
		 * technically be okay here), it would be deeply suspicious (not
		 * to mention sloppy) to call port_dissociate() on something
		 * that may well be dissociated already (ENOENT) or even closed
		 * completely (EBADFD).
		 */
		if (handled &&
		    (FD_ISSET(fd, evp_evts[DIR_RD]) || 
		    FD_ISSET(fd, evp_evts[DIR_WR])))
			ev_fd_update(fd);
	}
	evp_pollfd = -1;
}

/*
 * Returns non-zero if direction <dir> is already set for <fd>.
 */
int ev_fd_is_set(const int fd, int dir)
{
	return FD_ISSET(fd, evp_evts[dir]);
}

/*
 * Sets an association on "fd" for direction "dir".
 */
int ev_fd_set(const int fd, int dir)
{
	/* if the value was set, do nothing */
	if (FD_ISSET(fd, evp_evts[dir]))
		return 0;

	assert(((ev_fd_events(fd)) & DIR2POLLEVENT(dir)) == 0);
	FD_SET(fd, evp_evts[dir]);
	if (fd != evp_pollfd)
		ev_fd_update(fd);
	return 1;
}

/*
 * Clears any association on "fd" for direction "dir".
 */
int ev_fd_clr(const int fd, int dir)
{
	if (!FD_ISSET(fd, evp_evts[dir]))
		return 0;

	assert(((ev_fd_events(fd)) & DIR2POLLEVENT(dir)) != 0);
	FD_CLR(fd, evp_evts[dir]);
	if (fd != evp_pollfd)
		ev_fd_update(fd);
	return 1;
}

/*
 * Removes all associations for "fd".
 */
void ev_fd_rem(const int fd)
{
	if (!FD_ISSET(fd, evp_evts[DIR_RD]) &&
	    !FD_ISSET(fd, evp_evts[DIR_WR]))
		return;

	FD_CLR(fd, evp_evts[DIR_RD]);
	FD_CLR(fd, evp_evts[DIR_WR]);
	if (fd != evp_pollfd)
		ev_fd_update(fd);
}

/*
 * Cleans up local state for "fd", which is being closed.  This only needs to
 * clear the intended state of the association because the close() operation that
 * accompanies this call will automatically dissociate this fd from the port.
 */
void ev_fd_clo(const int fd)
{
	FD_CLR(fd, evp_evts[DIR_RD]);
	FD_CLR(fd, evp_evts[DIR_WR]);
}

/*
 * Helper functions
 */

/*
 * Returns the poll events that are currently associated for the given fd.
 */
int ev_fd_events(const int fd)
{
	int events = 0;

	if (FD_ISSET(fd, evp_evts[DIR_RD]))
		events |= POLLIN;
	if (FD_ISSET(fd, evp_evts[DIR_WR]))
		events |= POLLOUT;
	
	return (events);
}

/*
 * Propagates the intended state for this fd to the event port.  This function
 * is called when the intended state has changed (i.e., an association is added
 * or removed) as well as after an event is retrieved and handled for this
 * file descriptor to re-arm the association.  Both port_associate() and
 * port_dissociate() are idempotent and clobber any existing associations for
 * this file descriptor, which is why we always fetch the local state for both
 * DIR_RD and DIR_WR whenever we need to update either one.
 *
 * The caller is responsible for avoiding unnecessary system calls by avoiding
 * calling this function for operations that don't actually change the intended
 * state.  For the most part, this is just an optimization, but the code here is
 * very paranoid about error codes and assumes that we won't get ENOENT or
 * EBADFD because we tried to dissociate something that wasn't previously
 * associated.
 */
void ev_fd_update(const int fd)
{
	int events, rv;

	events = ev_fd_events(fd);
	if (events == 0)
		rv = port_dissociate(evp_port, PORT_SOURCE_FD, fd);
	else
		rv = port_associate(evp_port, PORT_SOURCE_FD, fd, events, NULL);

	if (rv != 0) {
		/*
		 * This is very bad.  There's either a serious bug (EBADF,
		 * EBADFD, EINVAL, or ENOENT) or we've run into system limits
		 * (EAGAIN or ENOMEM).  Unfortunately, none of our callers'
		 * callers check the return value, so this error cannot be
		 * handled gracefully.  The failure mode is bad, too: we think
		 * we're waiting for some event to happen, but we'll never be
		 * notified about it.  The result is a leaked connection in this
		 * process and possibly at a client or backend server as well.
		 * None of these failure modes is likely to be transient, so we
		 * likely won't be able to make much progress on either new
		 * connections or existing connections.  The best thing we can
		 * do is log what happened and crash, in hopes that an
		 * administrator will notice and correct the problem.  In the
		 * meantime, the system restarter can restart the service, which
		 * may temporarily alleviate the problem.
		 */
		Alert("%s() failed unexpectedly: fd %d, events 0x%x, "
		    "error=%s\n", events == 0 ? "port_dissociate" :
		    "port_associate", fd, events, strerror(errno));
		abort();
	}
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
