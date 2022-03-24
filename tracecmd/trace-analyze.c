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
struct task_item;

struct cpu_data {
	unsigned long long	start_ts;
	unsigned long long	last_ts;
	unsigned long long	missed_events;
	unsigned long long	unknown_missed_events;
	struct task_item	*idle_task;
	struct analysis_data	*data;
	struct trace_hash	tasks;
	int			nr_tasks;
	int			cpu;
	int			current_pid;
	int			first_pid;
	bool			last_idle;
	bool			keep_start;
};

struct analysis_data {
	unsigned long long	start_ts;
	unsigned long long	last_ts;
	struct tep_event	*switch_event;
	struct tep_event	*wakeup_event;
	struct tep_event	*page_fault_event;
	struct tep_format_field	*prev_comm;
	struct tep_format_field	*prev_state;
	struct tep_format_field	*next_comm;
	struct tep_format_field	*next_pid;
	struct tep_format_field	*wakeup_pid;
	struct cpu_data		*cpu_data;
	struct trace_hash	tasks;
	int			nr_tasks;
	int			allocated_cpus;
	int			cpus;
	bool			missed_events;
};

struct sched_timings {
	unsigned long long	last;
	unsigned long long	total;
	unsigned long long	nr;
	unsigned long long	longest;
	unsigned long long	longest_ts;
};

struct task_item {
	unsigned long long	runtime;
	unsigned long long	start_ts;
	unsigned long long	migrated;
	unsigned long long	faulted;
	struct sched_timings	preempt;
	struct sched_timings	sleep;
	struct sched_timings	blocked;
	struct sched_timings	other;
	struct sched_timings	wakeup;
	char			*comm;
	struct trace_hash_item	hash;
	int			pid;
	int			last_cpu;
	int			last_state;
	bool			woken;
	bool			dropped_events;
};

struct task_cpu_item {
	unsigned long long	runtime;
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
		task->last_cpu = cpu_data->cpu;
		task->last_state = -1;
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

static void update_sched_timings (struct sched_timings *time, unsigned long long ts)
{
	unsigned long long delta;

	delta = ts - time->last;
	time->total += delta;
	if (delta > time->longest) {
		time->longest = delta;
		time->longest_ts = time->last;
	}
	time->nr++;
}

static void update_idle_task(struct cpu_data *cpu_data, struct task_item *task,
			     unsigned long long ts)
{
	if (!cpu_data->idle_task) {
		if (task && task->pid <= 0) {
			cpu_data->idle_task = task;
			task->other.last = ts;
			cpu_data->last_idle = true;
		}
		return;
	}
	if (!task || task->pid > 0) {
		if (cpu_data->last_idle)
			update_sched_timings(&cpu_data->idle_task->other, ts);

		cpu_data->last_idle = false;
		return;
	}
	if (cpu_data->last_idle)
		update_sched_timings(&task->other, ts);

	cpu_data->last_idle = true;
	task->other.last = ts;
}

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

	update_idle_task(cpu_data, task, ts);

	delta = ts - task->start_ts;
	task->runtime += delta;
	cpu_task->runtime += delta;
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
	if (task->last_cpu != cpu_data->cpu) {
		task->last_cpu = cpu_data->cpu;
		task->migrated++;
	}

	update_idle_task(cpu_data, task, record->ts);

	if (record->ts < cpu_data->last_ts) {
		tracecmd_warning("task %d start time %llu greater than CPU time %llu",
				 pid, record->ts, cpu_data->last_ts);
	} else {
		delta = record->ts - cpu_data->last_ts;
		task->runtime += delta;
		cpu_task->runtime += delta;
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
		update_idle_task(cpu_data, task, record->ts);
		if (record->ts < cpu_data->data->start_ts)
			cpu_data->data->start_ts = record->ts;
		/* If we lost events before here, keep the current start time */
		if (record->missed_events)
			cpu_data->keep_start = true;
		return;
	}

	if (pid != cpu_data->current_pid) {
		update_pid(cpu_data, record, pid);
		return;
	}

	update_idle_task(cpu_data, !pid ? cpu_data->idle_task : NULL, record->ts);

	cpu_data->last_ts = record->ts;
}

static void update_first_pid(struct cpu_data *cpu_data)
{
	struct task_cpu_item *cpu_task;
	struct task_item *task;
	unsigned long long start_ts = cpu_data->data->start_ts;
	unsigned long long delta;

	/* If the CPU started with dropped events, do not update */
	if (cpu_data->keep_start)
		return;

	cpu_task = get_cpu_task(cpu_data, cpu_data->first_pid);
	task = cpu_task->task;
	delta = cpu_data->start_ts - start_ts;
	task->runtime += delta;
	cpu_task->runtime += delta;

	/* Handle idle timings if it was the first task */
	if (task->pid <= 0) {
		task->other.total += delta;
		if (delta > task->other.longest) {
			task->other.longest = delta;
			task->other.longest_ts = cpu_data->start_ts;
		}
		task->other.nr++;
	}

	cpu_data->start_ts = start_ts;
}

static void process_switch(struct analysis_data *data,
			   struct tep_handle *tep, int pid,
			   struct tep_record *record)
{
	struct cpu_data *cpu_data = &data->cpu_data[record->cpu];
	struct task_cpu_item *cpu_task;
	struct task_item *task;
	unsigned long long val;
	const char *comm;

	cpu_task = get_cpu_task(cpu_data, pid);
	task = cpu_task->task;

	update_cpu_task_times(cpu_data, cpu_task, record->ts);

	/* Fill in missing comms */
	if (pid) {
		if (data->prev_state) {
			tep_read_number_field(data->prev_state, record->data, &val);
			switch (val & 0x1f) {
			case 0:
				task->preempt.last = record->ts;
				break;
			case 0x1:
				task->sleep.last = record->ts;
				break;
			case 0x2:
				task->blocked.last = record->ts;
				break;
			default:
				task->other.last = record->ts;
			}
			task->last_state = val & 0x1f;
		}

		if (data->prev_comm && !task->comm) {
			comm = (char *)(record->data + data->prev_comm->offset);
			task->comm = strdup(comm);
		}
	}

	if (data->next_pid) {
		unsigned long long val;

		tep_read_number_field(data->next_pid, record->data, &val);
		pid = val;
		cpu_task = get_cpu_task(cpu_data, pid);
		task = cpu_task->task;
		task->start_ts = record->ts;
		cpu_data->current_pid = pid;

		if (task->last_cpu != cpu_data->cpu) {
			task->last_cpu = cpu_data->cpu;
			task->migrated++;
		}

		update_idle_task(cpu_data, task, record->ts);

		switch (task->last_state) {
		case -1:
			/* First time seen */
			break;
		case 0:
			update_sched_timings(&task->preempt, record->ts);
			break;
		case 0x1:
			update_sched_timings(&task->sleep, record->ts);
			break;
		case 0x2:
			update_sched_timings(&task->blocked, record->ts);
			break;
		default:
			update_sched_timings(&task->other, record->ts);
		}
		task->last_state = val & 0x1f;

		/* Fill in missing comms */
		if (pid && data->next_comm && !task->comm) {
			comm = (char *)(record->data + data->next_comm->offset);
			task->comm = strdup(comm);
		}

		if (task->woken)
			update_sched_timings(&task->wakeup, record->ts);
		task->woken = false;
	}
}

static void process_wakeup(struct analysis_data *data,
			   struct tep_handle *tep,
			   struct tep_record *record)
{
	struct cpu_data *cpu_data = &data->cpu_data[record->cpu];
	struct task_cpu_item *cpu_task;
	struct task_item *task;
	unsigned long long val;
	int pid;

	tep_read_number_field(data->wakeup_pid, record->data, &val);
	pid = val;
	cpu_task = get_cpu_task(cpu_data, pid);
	task = cpu_task->task;
	task->wakeup.last = record->ts;
	task->woken = true;
}

static void process_page_fault(struct analysis_data *data,
			       struct tep_handle *tep, int pid,
			       struct tep_record *record)
{
	struct cpu_data *cpu_data = &data->cpu_data[record->cpu];
	struct task_cpu_item *cpu_task;
	struct task_item *task;

	cpu_task = get_cpu_task(cpu_data, pid);
	task = cpu_task->task;
	task->faulted++;
}

static void handle_missed_events(struct analysis_data *data,
				 struct tep_record *record)
{
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct task_cpu_item *cpu_task;
	struct cpu_data *cpu_data;
	struct task_item *task;
	long long missed_events = record->missed_events;
	int cpu;

	/* If this is the first event for the CPU do nothing here */
	if (record->cpu >= data->allocated_cpus ||
	    !data->cpu_data[record->cpu].data)
		return;

	data->missed_events = true;

	cpu_data = &data->cpu_data[record->cpu];
	cpu = cpu_data->cpu;

	if (missed_events > 0)
		cpu_data->missed_events += missed_events;
	else
		cpu_data->unknown_missed_events++;

	/* Need to reset all timings */
	trace_hash_for_each_bucket(bucket, &cpu_data->tasks) {
		trace_hash_for_each_item(item, bucket) {
			cpu_task = task_cpu_from_hash(item);
			task = cpu_task->task;
			if (task->last_cpu != cpu)
				continue;
			task->preempt.last = record->ts;
			task->sleep.last = record->ts;
			task->blocked.last = record->ts;
			task->other.last = record->ts;
			task->woken = false;
			task->last_state = -1;
			task->dropped_events = true;
		}
	}
}

static bool match_type(int type, struct tep_event *event)
{
	return event && type == event->id;
}

static void process_cpu(struct analysis_data *data,
			struct tep_handle *tep,
			struct tep_record *record)
{
	struct cpu_data *cpu_data;
	int type;
	int pid;

	if (record->missed_events)
		handle_missed_events(data, record);

	pid = tep_data_pid(tep, record);
	if (pid < 0) /* Warn? */
		return;

	cpu_data = get_cpu_data(data, record);
	update_cpu_times(cpu_data, tep, pid, record);

	type = tep_data_type(tep, record);
	if (match_type(type, data->switch_event))
		process_switch(data, tep, pid, record);

	else if (match_type(type, data->wakeup_event))
		process_wakeup(data, tep, record);

	else if (match_type(type, data->page_fault_event))
		process_page_fault(data, tep, pid, record);
}

static int cmp_tasks(const void *A, const void *B)
{
	struct task_item * const *a = A;
	struct task_item * const *b = B;

	if ((*a)->runtime > (*b)->runtime)
		return -1;

	return (*a)->runtime < (*b)->runtime;
}

static int cmp_cpu_tasks(const void *A, const void *B)
{
	struct task_cpu_item * const *a = A;
	struct task_cpu_item * const *b = B;

	if ((*a)->runtime > (*b)->runtime)
		return -1;

	return (*a)->runtime < (*b)->runtime;
}

static int cmp_task_pids(const void *A, const void *B)
{
	struct task_item * const *a = A;
	struct task_item * const *b = B;

	if ((*a)->pid < (*b)->pid)
		return -1;

	return (*a)->pid > (*b)->pid;
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

static void print_timings_title(const char *label)
{
	const char *a = "";
	int len;
	int i;

	if (time_in_nsecs)
		a = "   ";

	len = snprintf(NULL, 0, "%s", label);

	printf("%s%*sTotal    %s(cnt)       Avg              Longest       Where\n",
		label, 21 - len, "", a);

	for (i = 0; i < len; i++)
		printf("-");

	printf("%*s-----    %s-----       ---              -------       -----\n",
		21 - len, "", a);
}

static void print_sched_timings(const char *label, struct sched_timings *time)
{
	unsigned long long avg;
	int n;

	if (!time->nr)
		return;

	if (label)
		printf("%s:%*s", label, 15 - (int)strlen(label), "");
	else
		printf("\t\t");
	print_time(time->total, 0);
	n = printf(" (%llu)", time->nr);
	if (n < 8)
		printf("%*.s", 8 - n, "");
	avg = time->total / time->nr;
	print_time(avg, 0);
	if (time_in_nsecs)
		printf(" ");
	else
		printf("    ");
	print_time(time->longest, 0);
	if (time_in_nsecs)
		printf(" ");
	else
		printf("    ");
	print_time(time->longest_ts, 0);
	printf("\n");
}

static void print_cpu_data(struct tep_handle *tep, struct cpu_data *cpu_data)
{
	unsigned long long total_time;
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct task_cpu_item **cpu_tasks;
	struct task_cpu_item *cpu_task;
	struct task_item *idle_task = NULL;
	struct task_item *task;
	struct analysis_data *data;
	int nr_tasks;
	int i = 0;

	printf("\nCPU %d\n", cpu_data->cpu);
	printf("-------\n");

	if (cpu_data->missed_events || cpu_data->unknown_missed_events) {
		printf("Missed: %llu events", cpu_data->missed_events);
		if (cpu_data->unknown_missed_events)
			printf(" + %llu drops of unknown events",
			       cpu_data->unknown_missed_events);
		printf("\n");
	}

	data = cpu_data->data;

	if (cpu_data->keep_start) {
		total_time = data->last_ts - cpu_data->start_ts;
		printf("[ Events dropped before start of this CPU ]\n");
		printf("Total time: ");
		print_time(total_time, '_');
		printf("\n");
	} else {
		total_time = data->last_ts - data->start_ts;
	}

	cpu_tasks = malloc(sizeof(*cpu_tasks) * cpu_data->nr_tasks);

	if (!cpu_tasks)
		die("Could not allocate task array");

	trace_hash_for_each_bucket(bucket, &cpu_data->tasks) {
		trace_hash_for_each_item(item, bucket) {
			cpu_task = task_cpu_from_hash(item);
			if (cpu_task->task->pid <= 0)
				idle_task = cpu_task->task;
			else
				cpu_tasks[i++] = cpu_task;
		}
	}
	nr_tasks = i;

	if (idle_task) {
		printf("idle:\t");
		print_time(idle_task->runtime, '_');
		printf(" (%%%lld)\n", (idle_task->runtime * 100) / total_time);
		print_timings_title("Idleness");
		print_sched_timings(NULL, &idle_task->other);
	} else {
		printf("Never idle!\n");
	}

	qsort(cpu_tasks, nr_tasks, sizeof(*cpu_tasks), cmp_cpu_tasks);

	for (i = 0; i < nr_tasks; i++) {
		task = cpu_tasks[i]->task;

		if (!i) {
			printf("    Task name        PID \t     Run time\n");
			printf("    ---------        --- \t     --------\n");
		}
		printf("%16s %8d\t",
		       task->comm ? : tep_data_comm_from_pid(tep, task->pid),
		       task->pid);
		print_time(cpu_tasks[i]->runtime, '_');
		printf(" (%%%lld)\n", (task->runtime * 100) / total_time);
	}
	free(cpu_tasks);
}

static void print_task(struct tep_handle *tep, struct task_item *task)
{
	printf("\nTask: %d : %s:\n",
	       task->pid , task->comm ? : tep_data_comm_from_pid(tep, task->pid));
	if (task->dropped_events)
		printf("[ Events dropped for this task's CPU, may be missing data ]\n");
	printf("Runtime:    ");
	print_time(task->runtime, '_');
	printf("\n");
	if (task->migrated)
		printf("Migrated: %8llu\n", task->migrated);
	if (task->faulted)
		printf("Faulted:  %8llu\n", task->faulted);
	print_timings_title("Type");
	print_sched_timings("Wakeup", &task->wakeup);
	print_sched_timings("Preempted", &task->preempt);
	print_sched_timings("Blocked", &task->blocked);
	print_sched_timings("Sleeping", &task->sleep);
	print_sched_timings("Other", &task->other);
}

static void print_total(struct tep_handle *tep, struct analysis_data *data)
{
	unsigned long long total_time;
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;
	struct task_item **idle_tasks;
	struct task_item **tasks;
	struct task_item *task;
	bool first = true;
	int nr_tasks;
	int cpu;
	int i = 0;

	if (data->missed_events)
		printf("\n[ Missed events, some data may be missing ]\n");

	total_time = data->last_ts - data->start_ts;
	printf("\nTotal time: ");
	print_time(total_time, '_');
	printf("\n");

	tasks = malloc(sizeof(*tasks) * data->nr_tasks);
	if (!tasks)
		die("Could not allocate task array");

	idle_tasks = calloc(sizeof(*idle_tasks), data->allocated_cpus);
	if (!idle_tasks)
		die("Could not allocate idle task array");

	trace_hash_for_each_bucket(bucket, &data->tasks) {
		trace_hash_for_each_item(item, bucket) {
			task = task_from_hash(item);
			if (task->pid < 0) {
				cpu = -2 - task->pid;
				idle_tasks[cpu] = task;
			} else
				tasks[i++] = task;
		}
	}
	nr_tasks = i;

	qsort(tasks, nr_tasks, sizeof(*tasks), cmp_tasks);

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

	printf("\n");
	for (i = 0; i < nr_tasks; i++) {
		if (!i) {
			printf("    Task name        PID \t     Run time\n");
			printf("    ---------        --- \t     --------\n");
		}
		printf("%16s %8d\t",
		       tasks[i]->comm ? : tep_data_comm_from_pid(tep, tasks[i]->pid),
		       tasks[i]->pid);
		print_time(tasks[i]->runtime, '_');
		printf(" (%%%lld)\n", (tasks[i]->runtime * 100) / total_time);
	}

	printf("\n");

	for (i = 0; i < data->allocated_cpus; i++) {
		if (!data->cpu_data[i].data)
			continue;
		print_cpu_data(tep, &data->cpu_data[i]);
	}

	qsort(tasks, nr_tasks, sizeof(*tasks), cmp_task_pids);

	printf("\n");
	for (i = 0; i < nr_tasks; i++) {
		print_task(tep, tasks[i]);
	}
	free(tasks);
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
			free(task->comm);
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

	data.switch_event = tep_find_event_by_name(tep, "sched", "sched_switch");
	data.wakeup_event = tep_find_event_by_name(tep, "sched", "sched_waking");
	if (!data.wakeup_event)
		data.wakeup_event = tep_find_event_by_name(tep, "sched", "sched_wakeup");
	data.page_fault_event = tep_find_event_by_name(tep, "exceptions", "page_fault_user");

	/* Set to a very large number */
	data.start_ts = -1ULL;

	if (data.switch_event) {
		data.next_pid = tep_find_field(data.switch_event, "next_pid");
		data.next_comm = tep_find_field(data.switch_event, "next_comm");
		data.prev_comm = tep_find_field(data.switch_event, "prev_comm");
		data.prev_state = tep_find_field(data.switch_event, "prev_state");
	}

	if (data.wakeup_event) {
		data.wakeup_pid = tep_find_field(data.wakeup_event, "pid");
		if (!data.wakeup_pid)
			data.wakeup_event = NULL;
	}

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
