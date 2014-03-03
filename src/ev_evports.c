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

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <port.h>
#include <sys/time.h>

#include <common/compat.h>
#include <common/config.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/tools.h>

#include <types/global.h>

#include <proto/fd.h>
#include <proto/signal.h>
#include <proto/task.h>

/* private data */
static int evp_port;
static port_event_t *evp_events;
static fd_set *fd_evts[2];

/*
 * Returns non-zero if direction <dir> is already set for <fd>.
 */
REGPRM2 static int __fd_is_set(const int fd, int dir)
{
	// XXX dap NYI
	abort();
	return 1;
}

REGPRM2 static int __fd_set(const int fd, int dir)
{
	// XXX dap NYI
	abort();
	return 1;
}

REGPRM2 static int __fd_clr(const int fd, int dir)
{
	// XXX dap NYI
	abort();
	return 1;
}

REGPRM1 static void __fd_rem(int fd)
{
	// XXX dap NYI
	abort();
}

REGPRM1 static void __fd_clo(int fd)
{
	// XXX dap NYI
	abort();
}

/*
 * Event ports poller
 */
REGPRM2 static void _do_poll(struct poller *p, int exp)
{
	// XXX dap NYI
	abort();
}

/*
 * Initialization of the event ports poller.
 * Returns 0 in case of failure, non-zero in case of success. If it fails, it
 * disables the poller by setting its pref to 0.
 */
REGPRM1 static int _do_init(struct poller *p)
{
	__label__ fail_wevt, fail_revt, fail_fd;
	int fd_set_bytes;

	// XXX dap: this is from kqueue code, but how do we know FD_SETSIZE is big enough?
	p->private = NULL;
	fd_set_bytes = sizeof(fd_set) * (global.maxsock + FD_SETSIZE - 1) / FD_SETSIZE;

	evp_port = port_create();
	if (evp_port < 0)
		goto fail_fd;

	evp_events = (port_event_t *)calloc(1,
	    sizeof(port_event_t) * global.tune.maxpollevents);

	if (evp_events == NULL)
		goto fail_events;
		
	if ((fd_evts[DIR_RD] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_revt;

	if ((fd_evts[DIR_WR] = (fd_set *)calloc(1, fd_set_bytes)) == NULL)
		goto fail_wevt;

	// XXX dap NYI: when we're ready to enable this, we actually want to
	// return 1 and not set pref to 0.
	free(fd_evts[DIR_WR]);

 fail_wevt:
	free(fd_evts[DIR_RD]);
 fail_revt:
	free(evp_events);
 fail_events:
	close(evp_port);
	evp_port = -1;
 fail_fd:
	p->pref = 0;
	return 0;
}

/*
 * Termination of the event ports poller.
 * Memory is released and the poller is marked as unselectable.
 */
REGPRM1 static void _do_term(struct poller *p)
{
	free(fd_evts[DIR_WR]);
	free(fd_evts[DIR_RD]);
	free(evp_events);

	if (evp_port >= 0) {
		close(evp_port);
		evp_port = -1;
	}

	p->private = NULL;
	p->pref = 0;
}

/*
 * Check that the poller works.
 * Returns 1 if OK, otherwise 0.
 */
REGPRM1 static int _do_test(struct poller *p)
{
	int fd;

	fd = port_create();
	if (fd < 0)
		return 0;
	close(fd);
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

	evp_port = -1;
	p = &pollers[nbpollers++];

	p->name = "evports";
	p->pref = 300;
	p->private = NULL;

	p->test = _do_test;
	p->init = _do_init;
	p->term = _do_term;
	p->poll = _do_poll;

	p->is_set  = __fd_is_set;
	p->cond_s = p->set = __fd_set;
	p->cond_c = p->clr = __fd_clr;
	p->rem = __fd_rem;
	p->clo = __fd_clo;
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
