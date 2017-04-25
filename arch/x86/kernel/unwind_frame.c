#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <asm/ptrace.h>
#include <asm/bitops.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

#define FRAME_HEADER_SIZE (sizeof(long) * 2)

/*
 * This disables KASAN checking when reading a value from another task's stack,
 * since the other task could be running on another CPU and could have poisoned
 * the stack in the meantime.
 */
#define READ_ONCE_TASK_STACK(task, x)			\
({							\
	unsigned long val;				\
	if (task == current)				\
		val = READ_ONCE(x);			\
	else						\
		val = READ_ONCE_NOCHECK(x);		\
	val;						\
})

static void unwind_dump(struct unwind_state *state, unsigned long *sp)
{
	static bool dumped_before = false;
	bool prev_zero, zero = false;
	unsigned long word;

	if (dumped_before)
		return;

	dumped_before = true;

	printk_deferred("unwind stack type:%d next_sp:%p mask:%lx graph_idx:%d\n",
			state->stack_info.type, state->stack_info.next_sp,
			state->stack_mask, state->graph_idx);

	for (sp = state->orig_sp; sp < state->stack_info.end; sp++) {
		word = READ_ONCE_NOCHECK(*sp);

		prev_zero = zero;
		zero = word == 0;

		if (zero) {
			if (!prev_zero)
				printk_deferred("%p: %016x ...\n", sp, 0);
			continue;
		}

		printk_deferred("%p: %016lx (%pB)\n", sp, word, (void *)word);
	}
}

unsigned long unwind_get_return_address(struct unwind_state *state)
{
	unsigned long addr;
	unsigned long *addr_p = unwind_get_return_address_ptr(state);

	if (unwind_done(state))
		return 0;

	if (state->regs && user_mode(state->regs))
		return 0;

	addr = READ_ONCE_TASK_STACK(state->task, *addr_p);
	addr = ftrace_graph_ret_addr(state->task, &state->graph_idx, addr,
				     addr_p);

	return __kernel_text_address(addr) ? addr : 0;
}
EXPORT_SYMBOL_GPL(unwind_get_return_address);

static size_t regs_size(struct pt_regs *regs)
{
	/* x86_32 regs from kernel mode are two words shorter: */
	if (IS_ENABLED(CONFIG_X86_32) && !user_mode(regs))
		return sizeof(*regs) - 2*sizeof(long);

	return sizeof(*regs);
}

#ifdef CONFIG_X86_32
#define GCC_REALIGN_WORDS 3
#else
#define GCC_REALIGN_WORDS 1
#endif

static bool is_last_task_frame(struct unwind_state *state)
{
	unsigned long *last_bp = (unsigned long *)task_pt_regs(state->task) - 2;
	unsigned long *aligned_bp = last_bp - GCC_REALIGN_WORDS;

	/*
	 * We have to check for the last task frame at two different locations
	 * because gcc can occasionally decide to realign the stack pointer and
	 * change the offset of the stack frame in the prologue of a function
	 * called by head/entry code.  Examples:
	 *
	 * <start_secondary>:
	 *      push   %edi
	 *      lea    0x8(%esp),%edi
	 *      and    $0xfffffff8,%esp
	 *      pushl  -0x4(%edi)
	 *      push   %ebp
	 *      mov    %esp,%ebp
	 *
	 * <x86_64_start_kernel>:
	 *      lea    0x8(%rsp),%r10
	 *      and    $0xfffffffffffffff0,%rsp
	 *      pushq  -0x8(%r10)
	 *      push   %rbp
	 *      mov    %rsp,%rbp
	 *
	 * Note that after aligning the stack, it pushes a duplicate copy of
	 * the return address before pushing the frame pointer.
	 */
	return (state->bp == last_bp ||
		(state->bp == aligned_bp && *(aligned_bp+1) == *(last_bp+1)));
}

/*
 * This determines if the frame pointer actually contains an encoded pointer to
 * pt_regs on the stack.  See ENCODE_FRAME_POINTER.
 */
static struct pt_regs *decode_frame_pointer(unsigned long *bp)
{
	unsigned long regs = (unsigned long)bp;

	if (!(regs & 0x1))
		return NULL;

	return (struct pt_regs *)(regs & ~0x1);
}

static bool update_stack_state(struct unwind_state *state, void *addr,
			       size_t len)
{
	struct stack_info *info = &state->stack_info;
	enum stack_type orig_type = info->type;

	/*
	 * If addr isn't on the current stack, switch to the next one.
	 *
	 * We may have to traverse multiple stacks to deal with the possibility
	 * that 'info->next_sp' could point to an empty stack and 'addr' could
	 * be on a subsequent stack.
	 */
	while (!on_stack(info, addr, len))
		if (get_stack_info(info->next_sp, state->task, info,
				   &state->stack_mask))
			return false;

	if (!state->orig_sp || info->type != orig_type)
		state->orig_sp = addr;

	return true;
}

bool unwind_next_frame(struct unwind_state *state)
{
	struct pt_regs *regs;
	unsigned long *next_bp, *next_frame;
	size_t next_len;
	enum stack_type prev_type = state->stack_info.type;

	if (unwind_done(state))
		return false;

	/* have we reached the end? */
	if (state->regs && user_mode(state->regs))
		goto the_end;

	if (is_last_task_frame(state)) {
		regs = task_pt_regs(state->task);

		/*
		 * kthreads (other than the boot CPU's idle thread) have some
		 * partial regs at the end of their stack which were placed
		 * there by copy_thread_tls().  But the regs don't have any
		 * useful information, so we can skip them.
		 *
		 * This user_mode() check is slightly broader than a PF_KTHREAD
		 * check because it also catches the awkward situation where a
		 * newly forked kthread transitions into a user task by calling
		 * do_execve(), which eventually clears PF_KTHREAD.
		 */
		if (!user_mode(regs))
			goto the_end;

		/*
		 * We're almost at the end, but not quite: there's still the
		 * syscall regs frame.  Entry code doesn't encode the regs
		 * pointer for syscalls, so we have to set it manually.
		 */
		state->regs = regs;
		state->bp = NULL;
		return true;
	}

	/* get the next frame pointer */
	if (state->regs)
		next_bp = (unsigned long *)state->regs->bp;
	else
		next_bp = (unsigned long *)READ_ONCE_TASK_STACK(state->task,*state->bp);

	/* is the next frame pointer an encoded pointer to pt_regs? */
	regs = decode_frame_pointer(next_bp);
	if (regs) {
		next_frame = (unsigned long *)regs;
		next_len = sizeof(*regs);
	} else {
		next_frame = next_bp;
		next_len = FRAME_HEADER_SIZE;
	}

	/* make sure the next frame's data is accessible */
	if (!update_stack_state(state, next_frame, next_len)) {
		/*
		 * Don't warn on bad regs->bp.  An interrupt in entry code
		 * might cause a false positive warning.
		 */
		if (state->regs)
			goto the_end;

		goto bad_address;
	}

	/* Make sure it only unwinds up and doesn't overlap the last frame: */
	if (state->stack_info.type == prev_type) {
		if (state->regs && (void *)next_frame < (void *)state->regs + regs_size(state->regs))
			goto bad_address;

		if (state->bp && (void *)next_frame < (void *)state->bp + FRAME_HEADER_SIZE)
			goto bad_address;
	}

	/* move to the next frame */
	if (regs) {
		state->regs = regs;
		state->bp = NULL;
	} else {
		state->bp = next_bp;
		state->regs = NULL;
	}

	return true;

bad_address:
	/*
	 * When unwinding a non-current task, the task might actually be
	 * running on another CPU, in which case it could be modifying its
	 * stack while we're reading it.  This is generally not a problem and
	 * can be ignored as long as the caller understands that unwinding
	 * another task will not always succeed.
	 */
	if (state->task != current)
		goto the_end;

	if (state->regs) {
		printk_deferred_once(KERN_WARNING
			"WARNING: kernel stack regs at %p in %s:%d has bad 'bp' value %p\n",
			state->regs, state->task->comm,
			state->task->pid, next_frame);
		unwind_dump(state, (unsigned long *)state->regs);
	} else {
		printk_deferred_once(KERN_WARNING
			"WARNING: kernel stack frame pointer at %p in %s:%d has bad value %p\n",
			state->bp, state->task->comm,
			state->task->pid, next_frame);
		unwind_dump(state, state->bp);
	}
the_end:
	state->stack_info.type = STACK_TYPE_UNKNOWN;
	return false;
}
EXPORT_SYMBOL_GPL(unwind_next_frame);

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *first_frame)
{
	unsigned long *bp, *frame;
	size_t len;

	memset(state, 0, sizeof(*state));
	state->task = task;

	/* don't even attempt to start from user mode regs */
	if (regs && user_mode(regs)) {
		state->stack_info.type = STACK_TYPE_UNKNOWN;
		return;
	}

	/* set up the starting stack frame */
	bp = get_frame_pointer(task, regs);
	regs = decode_frame_pointer(bp);
	if (regs) {
		state->regs = regs;
		frame = (unsigned long *)regs;
		len = sizeof(*regs);
	} else {
		state->bp = bp;
		frame = bp;
		len = FRAME_HEADER_SIZE;
	}

	/* initialize stack info and make sure the frame data is accessible */
	get_stack_info(frame, state->task, &state->stack_info,
		       &state->stack_mask);
	update_stack_state(state, frame, len);

	/*
	 * The caller can provide the address of the first frame directly
	 * (first_frame) or indirectly (regs->sp) to indicate which stack frame
	 * to start unwinding at.  Skip ahead until we reach it.
	 */
	while (!unwind_done(state) &&
	       (!on_stack(&state->stack_info, first_frame, sizeof(long)) ||
			state->bp < first_frame))
		unwind_next_frame(state);
}
EXPORT_SYMBOL_GPL(__unwind_start);
