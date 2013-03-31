/*
 * FD polling functions for generic poll()
 *
 * Copyright 2000-2008 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <unistd.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/types.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/ticks.h>
#include <common/time.h>

#include <types/global.h>

#include <proto/fd.h>
#include <proto/signal.h>
#include <proto/task.h>


static unsigned int *fd_evts[2];

/* private data */
static struct pollfd *poll_events = NULL;

static inline unsigned int hap_fd_isset(int fd, unsigned int *evts)
{
	return evts[fd / (8*sizeof(*evts))] & (1U << (fd & (8*sizeof(*evts) - 1)));
}

static inline void hap_fd_set(int fd, unsigned int *evts)
{
	evts[fd / (8*sizeof(*evts))] |= 1U << (fd & (8*sizeof(*evts) - 1));
}

static inline void hap_fd_clr(int fd, unsigned int *evts)
{
	evts[fd / (8*sizeof(*evts))] &= ~(1U << (fd & (8*sizeof(*evts) - 1)));
}
/*
 * Benchmarks performed on a Pentium-M notebook show that using functions
 * instead of the usual macros improve the FD_* performance by about 80%,
 * and that marking them regparm(2) adds another 20%.
 */
REGPRM2 static int __fd_is_set(const int fd, int dir)
{
	return hap_fd_isset(fd, fd_evts[dir]);
}

REGPRM2 static int __fd_set(const int fd, int dir)
{
	hap_fd_set(fd, fd_evts[dir]);
	return 0;
}

REGPRM2 static int __fd_clr(const int fd, int dir)
{
	hap_fd_clr(fd, fd_evts[dir]);
	return 0;
}

REGPRM2 static int __fd_cond_s(const int fd, int dir)
{
	int ret;
	ret = !hap_fd_isset(fd, fd_evts[dir]);
	if (ret)
		hap_fd_set(fd, fd_evts[dir]);
	return ret;
}

REGPRM2 static int __fd_cond_c(const int fd, int dir)
{
	int ret;
	ret = hap_fd_isset(fd, fd_evts[dir]);
	if (ret)
		hap_fd_clr(fd, fd_evts[dir]);
	return ret;
}

REGPRM1 static void __fd_rem(const int fd)
{
	hap_fd_clr(fd, fd_evts[DIR_RD]);
	hap_fd_clr(fd, fd_evts[DIR_WR]);
}

/*
 * Poll() poller
 */
REGPRM2 static void _do_poll(struct poller *p, int exp)
{
	int status;
	int fd, nbfd;
	int wait_time;

	int fds, count;
	int sr, sw;
	unsigned rn, wn; /* read new, write new */

	nbfd = 0;
	for (fds = 0; (fds * 8*sizeof(**fd_evts)) < maxfd; fds++) {
		rn = fd_evts[DIR_RD][fds];
		wn = fd_evts[DIR_WR][fds];
	  
		if (!(rn|wn))
			continue;

		for (count = 0, fd = fds * 8*sizeof(**fd_evts); count < 8*sizeof(**fd_evts) && fd < maxfd; count++, fd++) {
			sr = (rn >> count) & 1;
			sw = (wn >> count) & 1;
			if ((sr|sw)) {
				poll_events[nbfd].fd = fd;
				poll_events[nbfd].events = (sr ? POLLIN : 0) | (sw ? POLLOUT : 0);
				nbfd++;
			}
		}		  
	}
      
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

	status = poll(poll_events, nbfd, wait_time);
	tv_update_date(wait_time, status);

	for (count = 0; status > 0 && count < nbfd; count++) {
		fd = poll_events[count].fd;
	  
		if (!(poll_events[count].revents & ( POLLOUT | POLLIN | POLLERR | POLLHUP )))
			continue;

		/* ok, we found one active fd */
		status--;

		if (hap_fd_isset(fd, fd_evts[DIR_RD])) {
			if (fdtab[fd].state == FD_STCLOSE)
				continue;
			if (poll_events[count].revents & ( POLLIN | POLLERR | POLLHUP ))
				fdtab[fd].cb[DIR_RD].f(fd);
		}
	  
		if (hap_fd_isset(fd, fd_evts[DIR_WR])) {
			if (fdtab[fd].state == FD_STCLOSE)
				continue;
			if (poll_events[count].revents & ( POLLOUT | POLLERR | POLLHUP ))
				fdtab[fd].cb[DIR_WR].f(fd);
		}
	}

}

/*
 * Initialization of the poll() poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	__label__ fail_swevt, fail_srevt, fail_pe;
	int fd_evts_bytes;

	p->private = NULL;
	fd_evts_bytes = (global.maxsock + sizeof(**fd_evts) - 1) / sizeof(**fd_evts) * sizeof(**fd_evts);

	poll_events = calloc(1, sizeof(struct pollfd) * global.maxsock);

	if (poll_events == NULL)
		goto fail_pe;
		
	if ((fd_evts[DIR_RD] = calloc(1, fd_evts_bytes)) == NULL)
		goto fail_srevt;

	if ((fd_evts[DIR_WR] = calloc(1, fd_evts_bytes)) == NULL)
		goto fail_swevt;

	return 1;

 fail_swevt:
	free(fd_evts[DIR_RD]);
 fail_srevt:
	free(poll_events);
 fail_pe:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the poll() poller.
 * Memory is released and the poller is marked as unselectable.
 */
REGPRM1 static void _do_term(struct poller *p)
{
	free(fd_evts[DIR_WR]);
	free(fd_evts[DIR_RD]);
	free(poll_events);
	p->private = NULL;
	p->pref = 0;
}

/*
 * Check that the poller works.
 * Returns 1 if OK, otherwise 0.
 */
REGPRM1 static int _do_test(struct poller *p)
{
	return 1;
}

/*
 * It is a constructor, which means that it will automatically be called before
 * main(). This is GCC-specific but it works at least since 2.95.
 * Special care must be taken so that it does not need any uninitialized data.
 */
__attribute__((constructor))
static void _do_register(void)
{
	struct poller *p;

	if (nbpollers >= MAX_POLLERS)
		return;
	p = &pollers[nbpollers++];

	p->name = "poll";
	p->pref = 200;
	p->private = NULL;

	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;
	p->is_set = __fd_is_set;
	p->set = __fd_set;
	p->clr = __fd_clr;
	p->clo = p->rem = __fd_rem;
	p->cond_s = __fd_cond_s;
	p->cond_c = __fd_cond_c;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
