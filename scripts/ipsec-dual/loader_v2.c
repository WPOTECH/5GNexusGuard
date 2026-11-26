/* loader_v2.c — Load kernel_gate_v2.bpf.o using host libbpf 1.3+ */
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/resource.h>
#include <errno.h>

static const char *TC_PROG_NAMES[] = {
	"health_control",
	"wg_ingress",
	"resource_ingress",
};
#define PROG_COUNT (sizeof(TC_PROG_NAMES) / sizeof(TC_PROG_NAMES[0]))

/* Remove existing BPF map pin at the given path (ignores ENOENT) */
static void unlink_pin(const char *pin_path)
{
	unlink(pin_path);
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_tc_hook hook;
	struct bpf_tc_opts opts;
	const char *file;
	int ifindex, ret, i;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <interface> [bpf_object_file]\n", argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Cannot resolve interface '%s': %s\n", argv[1], strerror(errno));
		return 1;
	}

	file = (argc >= 3) ? argv[2] : "kernel_gate_v2.bpf.o";
	fprintf(stderr, "Loading %s on %s (ifindex=%d)...\n", file, argv[1], ifindex);

	/* Detach all existing BPF TC programs on this interface first */
	{
		struct bpf_tc_hook h = { .sz = sizeof(h), .ifindex = ifindex, .attach_point = BPF_TC_INGRESS };
		struct bpf_tc_opts d = { .sz = sizeof(d) };
		ret = bpf_tc_hook_create(&h);
		if (ret >= 0 || errno == EEXIST) {
			ret = bpf_tc_query(&h, &d);
			if (ret == 0 && d.prog_fd > 0) {
				bpf_tc_detach(&h, &d);
				fprintf(stderr, "  Detached existing TC programs from %s\n", argv[1]);
			}
			bpf_tc_hook_destroy(&h);
		}
	}
	sleep(1);

	/* Increase memlock */
	struct rlimit rl = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
	setrlimit(RLIMIT_MEMLOCK, &rl);

	/* Open the BPF object */
	obj = bpf_object__open_file(file, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Failed to open BPF object %s\n", file);
		return 1;
	}

	/* Explicitly set program types — custom SEC names are not auto-detected by libbpf */
	bpf_object__for_each_program(prog, obj) {
		const char *sec = bpf_program__section_name(prog);
		if (strncmp(sec, "tc/", 3) == 0) {
			bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);
		} else if (strncmp(sec, "tcx/", 4) == 0) {
			bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);
		} else if (strncmp(sec, "xdp/", 4) == 0) {
			bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
		} else if (strstr(sec, "_tc")) {
			/* Custom _tc suffix sections are also sched_cls */
			bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);
		}
	}

	/* Load the BPF object (verify + load to kernel) */
	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "bpf_object__load failed: %s\n", strerror(errno));
		bpf_object__close(obj);
		return 1;
	}
	fprintf(stderr, "OK: All BPF programs loaded into kernel.\n");

	/* Pin maps to /sys/fs/bpf/nexus_<mapname> */
	const char *map_names[] = {"health_map", "renewal_state", NULL};
	struct bpf_map *map;
	bpf_object__for_each_map(map, obj) {
		int i;
		for (i = 0; map_names[i]; i++) {
			if (strcmp(bpf_map__name(map), map_names[i]) == 0) {
				/* Unpin existing entry first (EEXIST is fatal to libbpf pinning) */
				char pin_path[256];
				snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/nexus_%s", map_names[i]);
				unlink_pin(pin_path);

				/* Pin maps to /sys/fs/bpf/nexus_<mapname> */
				snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/nexus_%s", map_names[i]);
				ret = bpf_map__pin(map, pin_path);
				if (ret) {
					fprintf(stderr, "  Warning: failed to pin map %s: %s\n",
						map_names[i], strerror(errno));
				} else {
					fprintf(stderr, "  Pinned map %s -> %s\n", map_names[i], pin_path);
				}
				break;
			}
		}
	}
	/* Print loaded programs */
	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);
		const char *sec = bpf_program__section_name(prog);
		int fd = bpf_program__fd(prog);
		if (fd >= 0)
			fprintf(stderr, "  %s (sec=%s) fd=%d\n", name, sec, fd);
	}

	/* Attach each program using a single TC hook */
	{
		struct bpf_tc_hook hook;
		struct bpf_tc_opts opts;
		int hook_created = 0;

		memset(&hook, 0, sizeof(hook));
		hook.sz = sizeof(hook);
		hook.ifindex = ifindex;
		hook.attach_point = BPF_TC_INGRESS;

		for (i = 0; i < PROG_COUNT; i++) {
			prog = bpf_object__find_program_by_name(obj, TC_PROG_NAMES[i]);
			if (!prog) {
				fprintf(stderr, "  %s: not found\n", TC_PROG_NAMES[i]);
				continue;
			}

			int prog_fd = bpf_program__fd(prog);
			if (prog_fd < 0) {
				fprintf(stderr, "  %s: no FD\n", TC_PROG_NAMES[i]);
				continue;
			}

			/* Create TC hook on first program only */
			if (!hook_created) {
				ret = bpf_tc_hook_create(&hook);
				if (ret < 0) {
					fprintf(stderr, "  DEBUG: bpf_tc_hook_create returned %d, errno=%d EBUSY=%d\n", 
						ret, errno, EBUSY);
					if (errno == EEXIST) {
						fprintf(stderr, "  TC qdisc already exists, reusing\n");
						hook_created = 1;
						ret = 0;
					} else {
						fprintf(stderr, "  %s: bpf_tc_hook_create failed: %s\n",
							TC_PROG_NAMES[i], strerror(errno));
						continue;
					}
				}
				if (hook_created == 0) {
					hook_created = 1;
					fprintf(stderr, "  TC hook created on %s (ifindex=%d)\n",
						argv[1], ifindex);
				}
			}

			/* Attach program to the shared hook */
			memset(&opts, 0, sizeof(opts));
			opts.sz = sizeof(opts);
			opts.prog_fd = prog_fd;
			opts.flags = BPF_TC_F_REPLACE;
			opts.priority = PROG_COUNT - i; /* reverse order: health_control first */
			ret = bpf_tc_attach(&hook, &opts);
			if (ret < 0) {
				fprintf(stderr, "  %s: bpf_tc_attach failed: %s\n",
					TC_PROG_NAMES[i], strerror(errno));
			} else {
				fprintf(stderr, "  %s: attached to %s (ifindex=%d, prio=%u)\n",
					TC_PROG_NAMES[i], argv[1], ifindex, opts.priority);
			}
		}
	}

	bpf_object__close(obj);
	return 0;
}
