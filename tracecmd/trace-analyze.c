// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2022 Google Inc, Steven Rostedt <srostedt@redhat.com>
 */
#define _LARGEFILE64_SOURCE
#include <getopt.h>
#include <stdlib.h>

#include "trace-cmd-local.h"
#include "trace-local.h"
#include "trace-hash.h"
#include "list.h"

static bool time_in_nsecs;

struct analysis_data;

struct cpu_data {
	unsigned long long	start_ts;
	unsigned long long	last_ts;
	struct analysis_data	*data;
	struct trace_hash	tasks;
	int			nr_tasks;
	int			cpu;
	int			current_pid;
	int			first_pid;
};

struct analysis_data {
	unsigned long long	start_ts;
	unsigned long long	last_ts;
	struct cpu_data		*cpu_data;
	struct trace_hash	tasks;
	int			nr_tasks;
	int			allocated_cpus;
	int			cpus;
};

struct task_item {
	unsigned long long	runtime;
	unsigned long long	start_ts;
	struct trace_hash_item	hash;
	int			pid;
};

struct task_cpu_item {
	struct trace_hash_item	hash;
	struct task_item       	*task;
};

#define CPU_BLOCKS	32

#define task_from_hash(item) container_of(item, struct task_item, hash)
#define task_cpu_from_hash(item)  container_of(item, struct task_cpu_item, hash)

static struct cpu_data *get_cpu_data(struct analysis_data *data,
				     struct tep_record *record)
{
	struct cpu_data *cpu_data;
	int cpu = record->cpu;
	int cnt;

	if (cpu < data->allocated_cpus) {
		cpu_data = &data->cpu_data[cpu];
		if (!cpu_data->data)
			goto init_cpu_data;
		return cpu_data;
	}

	/* Round up to CPU_BLOCKS multiplier */
	cnt = ((cpu + CPU_BLOCKS) / CPU_BLOCKS) * CPU_BLOCKS;

	cpu_data = realloc(data->cpu_data, sizeof(*cpu_data) * cnt);

	if (!cpu_data)
		die("Allocating cpu size %d for cpu %d", cnt, cpu);

	memset(cpu_data + data->allocated_cpus, 0,
	       sizeof(*cpu_data) * (cnt - data->allocated_cpus));

	data->allocated_cpus = cnt;

	data->cpu_data = cpu_data;
	cpu_data += cpu;

 init_cpu_data:
	cpu_data->current_pid = -1;
	cpu_data->cpu = cpu;
	cpu_data->data = data;

	trace_hash_init(&cpu_data->tasks, 32);

	return cpu_data;
}

static int check_idle(struct cpu_data *cpu_data, int pid)
{
	if (pid)
		return pid;

	/*
	 * Since pid 0 is the per cpu swapper task that
	 * means several of these tasks have the same pid
	 * and only differentiate between CPUs. Set the pid
	 * that is stored in the hash as -2 - CPU id.
	 */

	return -2 - cpu_data->cpu;
}

static struct task_item *get_task(struct cpu_data *cpu_data, int pid)
{
	struct trace_hash_item *hash;
	struct task_item *task;
	int find_pid;

	find_pid = check_idle(cpu_data, pid);

	hash = trace_hash_find(&cpu_data->data->tasks, find_pid, NULL, NULL);
	if (!hash) {
		task = calloc(sizeof(*task), 1);
		if (!task)
			die("allocating task");
		task->pid = find_pid;
		hash = &task->hash;
		hash->key = find_pid;
		cpu_data->data->nr_tasks++;
		trace_hash_add(&cpu_data->data->tasks, hash);
	}

	return task_from_hash(hash);
}

static struct task_cpu_item *get_cpu_task(struct cpu_data *cpu_data, int pid)
{
	struct trace_hash_item *hash;
	struct task_cpu_item *task;

	hash = trace_hash_find(&cpu_data->tasks, pid, NULL, NULL);
	if (!hash) {
		task = calloc(sizeof(*task), 1);
		if (!task)
			die("allocating cpu task");
		task->task = get_task(cpu_data, pid);
		hash = &task->hash;
		hash->key = pid;
		cpu_data->nr_tasks++;
		trace_hash_add(&cpu_data->tasks, hash);
	}

	return task_cpu_from_hash(hash);
};

/* Update times for a task scheduling off the CPU */
static void update_cpu_task_times(struct cpu_data *cpu_data,
				  struct task_cpu_item *cpu_task,
				  unsigned long long ts)
{
	unsigned long long delta;
	struct task_item *task = cpu_task->task;

	/*
	 * If the last event was a sched switch where the previous task
	 * ran on another CPU, and migrated back to this CPU, and sched
	 * switch was not recorded (saying that this task scheduled off)
	 * It could be miscronstrued to still be on this CPU, and that
	 * its start_ts is later than the last_ts of this CPU.
	 */
	if (ts < task->start_ts)
		return;

	delta = ts - task->start_ts;
	task->runtime += delta;
}

static void update_pid(struct cpu_data *cpu_data,
		       struct tep_record *record, int pid)
{
	struct task_cpu_item *cpu_task;
	struct task_item *task;
	int curr_pid = cpu_data->current_pid;
	unsigned long long delta;

	cpu_task = get_cpu_task(cpu_data, curr_pid);
	task = cpu_task->task;

	update_cpu_task_times(cpu_data, cpu_task, cpu_data->last_ts);

	if (!record)
		return;

	cpu_task = get_cpu_task(cpu_data, pid);
	task = cpu_task->task;

	if (record->ts < cpu_data->last_ts) {
		tracecmd_warning("task %d start time %llu greater than CPU time %llu",
				 pid, record->ts, cpu_data->last_ts);
	} else {
		delta = record->ts - cpu_data->last_ts;
		task->runtime += delta;
	}

	cpu_data->last_ts = record->ts;

	task->start_ts = cpu_data->last_ts;
	cpu_data->current_pid = pid;
}

static void update_cpu_times(struct cpu_data *cpu_data,
			     struct tep_handle *tep, int pid,
			     struct tep_record *record)
{
	struct task_cpu_item *cpu_task;
	struct task_item *task;

	if (cpu_data->current_pid < 0) {
		/* First time called */
		cpu_data->start_ts = record->ts;
		cpu_data->last_ts = record->ts;
		cpu_data->current_pid = pid;
		cpu_data->first_pid = pid;
		cpu_task = get_cpu_task(cpu_data, pid);
		task = cpu_task->task;
		task->start_ts = record->ts;
		if (record->ts < cpu_data->data->start_ts)
			cpu_data->data->start_ts = record->ts;
		return;
	}

	if (pid != cpu_data->current_pid) {
		update_pid(cpu_data, record, pid);
		return;
	}

	cpu_data->last_ts = record->ts;
}

static void update_first_pid(struct cpu_data *cpu_data)
{
	struct task_cpu_item *cpu_task;
	struct task_item *task;
	unsigned long long start_ts = cpu_data->data->start_ts;
	unsigned long long delta;

	cpu_task = get_cpu_task(cpu_data, cpu_data->first_pid);
	task = cpu_task->task;
	delta = cpu_data->start_ts - start_ts;
	task->runtime += delta;
	cpu_data->start_ts = start_ts;
}

static void process_cpu(struct analysis_data *data,
			struct tep_handle *tep,
			struct tep_record *record)
{
	struct cpu_data *cpu_data;
	int pid;

	pid = tep_data_pid(tep, record);
	if (pid < 0) /* Warn? */
		return;

	cpu_data = get_cpu_data(data, record);
	update_cpu_times(cpu_data, tep, pid, record);
}

static void print_time(unsigned long long ts, char delim)
{
	unsigned long long secs;
	unsigned long long msecs;
	unsigned long long usecs;
	unsigned long long nsecs;

	secs = ts / 1000000000;
	ts -= secs * 1000000000;

	msecs = ts / 1000000;
	ts -= msecs * 1000000;

	usecs = ts / 1000;
	ts -= usecs * 1000;

	nsecs = ts;

	if (delim) {
		printf("%6llu.%03llu%c%03llu",
		       secs, msecs, delim, usecs);
		if (time_in_nsecs)
			printf("%c%03llu", delim, nsecs);
	} else {
		printf("%6llu.%03llu%03llu",
		       secs, msecs, usecs);
		if (time_in_nsecs)
			printf("%03llu", nsecs);
	}
}

static void print_total(struct tep_handle *tep, struct analysis_data *data)
{
	unsigned long long total_time;
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct task_item **idle_tasks;
	struct task_item *task;
	bool first = true;
	int cpu;
	int i = 0;

	total_time = data->last_ts - data->start_ts;
	printf("\nTotal time: ");
	print_time(total_time, '_');
	printf("\n");

	idle_tasks = calloc(sizeof(*idle_tasks), data->allocated_cpus);
	if (!idle_tasks)
		die("Could not allocate idle task array");

	trace_hash_for_each_bucket(bucket, &data->tasks) {
		trace_hash_for_each_item(item, bucket) {
			task = task_from_hash(item);
			if (task->pid < 0) {
				cpu = -2 - task->pid;
				idle_tasks[cpu] = task;
			}
		}
	}

	for (i = 0; i < data->allocated_cpus; i++) {
		if (!idle_tasks[i])
			continue;

		if (first) {
			printf("\n Idle CPU\t     Run time\n");
			printf(" --------\t     --------\n");
			first = false;
		}
		printf("CPU %d idle:\t", i);
		print_time(idle_tasks[i]->runtime, '_');
		printf(" (%%%lld)\n", (idle_tasks[i]->runtime * 100) / total_time);
	}
	free(idle_tasks);
}

static void free_tasks(struct trace_hash *hash)
{
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct task_item *task;

	trace_hash_for_each_bucket(bucket, hash) {
		trace_hash_while_item(item, bucket) {
			task = task_from_hash(item);
			trace_hash_del(item);
			free(task);
		}
	}
	trace_hash_free(hash);
}

static void free_cpu_tasks(struct trace_hash *hash)
{
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct task_cpu_item *cpu_task;

	trace_hash_for_each_bucket(bucket, hash) {
		trace_hash_while_item(item, bucket) {
			cpu_task = task_cpu_from_hash(item);
			trace_hash_del(item);
			free(cpu_task);
		}
	}
	trace_hash_free(hash);
}

static void free_cpus(struct analysis_data *data)
{
	struct cpu_data *cpu_data;
	int i;

	for (i = 0; i < data->allocated_cpus; i++) {
		cpu_data = &data->cpu_data[i];
		if (!cpu_data->data)
			continue;
		free_cpu_tasks(&cpu_data->tasks);
	}
	free(data->cpu_data);
}

static void do_trace_analyze(struct tracecmd_input *handle)
{
	struct tep_handle *tep = tracecmd_get_tep(handle);
	struct tep_record *record;
	struct analysis_data data;
	struct cpu_data *cpu_data;
	int i;

	memset(&data, 0, sizeof(data));

	trace_hash_init(&data.tasks, 128);

	/* Set to a very large number */
	data.start_ts = -1ULL;

	do {
		record = tracecmd_read_next_data(handle, NULL);
		if (record)
			process_cpu(&data, tep, record);
		tracecmd_free_record(record);
	} while (record);

	for (i = 0; i < data.allocated_cpus; i++) {
		cpu_data = &data.cpu_data[i];
		if (!cpu_data->data || !cpu_data->nr_tasks)
			continue;
		if (cpu_data->last_ts > data.last_ts)
			data.last_ts = cpu_data->last_ts;
	}

	for (i = 0; i < data.allocated_cpus; i++) {
		cpu_data = &data.cpu_data[i];
		if (!cpu_data->data || !cpu_data->nr_tasks)
			continue;
		cpu_data->last_ts = data.last_ts;
		update_pid(cpu_data, NULL, -1);
		update_first_pid(cpu_data);
	}

	print_total(tep, &data);

	free_cpus(&data);
	free_tasks(&data.tasks);
}

void trace_analyze(int argc, char **argv)
{
	struct tracecmd_input *handle;
	const char *input_file = NULL;
	int instances;
	int ret;

	for (;;) {
		int c;

		c = getopt(argc-1, argv+1, "+hti:");
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'i':
			if (input_file)
				die("Only one input for historgram");
			input_file = optarg;
			break;
		case 't':
			time_in_nsecs = true;
			break;
		default:
			usage(argv);
		}
	}

	if ((argc - optind) >= 2) {
		if (input_file)
			usage(argv);
		input_file = argv[optind + 1];
	}

	if (!input_file)
		input_file = DEFAULT_INPUT_FILE;

	handle = tracecmd_alloc(input_file, 0);
	if (!handle)
		die("can't open %s\n", input_file);

	ret = tracecmd_read_headers(handle, 0);
	if (ret)
		return;

	ret = tracecmd_init_data(handle);
	if (ret < 0)
		die("failed to init data");

	if (ret > 0)
		die("trace-cmd hist does not work with latency traces\n");

	do_trace_analyze(handle);

	instances = tracecmd_buffer_instances(handle);
	if (instances) {
		struct tracecmd_input *new_handle;
		int i;

		for (i = 0; i < instances; i++) {
			new_handle = tracecmd_buffer_instance_handle(handle, i);
			if (!new_handle) {
				warning("could not retrieve handle %d", i);
				continue;
			}
			do_trace_analyze(new_handle);
			tracecmd_close(new_handle);
		}
	}

	tracecmd_close(handle);
}
