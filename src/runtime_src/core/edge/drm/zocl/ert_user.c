/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * Copyright (C) 2021 Xilinx, Inc. All rights reserved.
 *
 * Author(s):
 *
 * This file is dual-licensed; you may select either the GNU General Public
 * License version 2 or Apache License, Version 2.0.
 */

#include <linux/sched/signal.h>
#include "zocl_drv.h"
#include "zocl_aie.h"
#include "zocl_util.h"
#include "zocl_xclbin.h"
#include "kds_core.h"
#include "xclbin.h"
#include "ert_user.h"

int ert_user_mode = 0;
static const unsigned int no_index = -1;
module_param(ert_user_mode, int, (S_IRUGO|S_IWUSR));
MODULE_PARM_DESC(ert_user_mode,
		 "enable new ERT mode which interact with RPU (0 = disable (default), 1 = enable)");

extern int kds_echo;

static irqreturn_t ert_user_isr(int irq, void *arg);
static void eu_submit(struct kds_ert *ert_user, struct kds_command *xcmd);
static void eu_abort(struct kds_ert *ert_user, struct kds_client *client,
			  int cu_idx);
static bool eu_abort_done(struct kds_ert *ert_user,
						 struct kds_client *client, int cu_idx);
static inline struct kds_client*
		first_event_client_or_null(struct zocl_ert_user *ert_user);
static int zocl_ert_cfg_cmd(struct zocl_ert_user *ert_user,
							struct ert_user_command *ecmd);
static inline int process_ert_rq(struct zocl_ert_user *ert_user,
								 struct zocl_eu_queue *rq);
static inline bool ert_special_cmd(struct ert_user_command *ecmd);

static void zocl_ert_intc_enable(struct zocl_ert_user *ert_user, bool enable);

void zocl_fini_ert_user_sched(struct drm_zocl_dev *zdev);
static inline void ert_post_process(struct zocl_ert_user *ert_user,
									struct ert_user_command *ecmd);
static inline void ert_get_return(struct zocl_ert_user *ert_user,
								  struct ert_user_command *ecmd);
static void zocl_ert_cfg_host(struct zocl_ert_user *ert_user,
							  struct ert_user_command *ecmd);
static void ert_user_free_cmd(struct ert_user_command* ecmd);
static void ert_user_reset(struct zocl_ert_user *ert_user);
static inline u32 cmd_opcode(struct ert_user_command *ecmd)
{
	return ecmd->xcmd->opcode;
}
/**
 * idx_in_mask32() - Index of command queue slot within the mask that contains it
 *
 * @slot_idx: Global [0..127] index of a CQ slot
 * Return: Index of slot within the mask that contains it
 */
static inline unsigned int
idx_in_mask32(unsigned int idx, unsigned int mask_idx)
{
	return idx - (mask_idx << 5);
}

/*
 * release_slot_idx() - Release specified slot idx
 */
static void
ert_release_slot_idx(struct zocl_ert_user *ert_user, unsigned int slot_idx)
{
	clear_bit(slot_idx, ert_user->slot_status);
}

/**
 * release_slot() - Release a slot index for a command
 *
 * Special case for control commands that execute in slot 0.  This
 * slot cannot be marked free ever.
 */
static void
ert_release_slot(struct zocl_ert_user *ert_user, struct ert_user_command *ecmd)
{
	int opc = cmd_opcode(ecmd);
	if (ecmd->slot_idx == no_index)
		return;

	if (ert_special_cmd(ecmd)) {
		ERTUSER_INFO( "do nothing %s for opcode: %d\n", __func__, opc);
		ert_user->ctrl_busy = false;
	} else {
		ERTUSER_INFO( "ecmd->slot_idx %d for opcode: %d\n", ecmd->slot_idx, opc);
		ert_release_slot_idx(ert_user, ecmd->slot_idx);
	}
	ecmd->slot_idx = no_index;
}

/**
 * process_ert_pq() - Process pending queue
 * @ert_user: Target XRT ERT
 * @pq: Target pending queue
 * @rq: Target running queue
 *
 * Move all of the pending queue commands to the tail of run queue
 * and re-initialized pending queue
 */
static inline void process_ert_pq(struct zocl_ert_user *ert_user,
					struct zocl_eu_queue *pq, struct zocl_eu_queue *rq)
{
	unsigned long flags;

	/* Get pending queue command number without lock.
	 * The idea is to reduce the possibility of conflict on lock.
	 * Need to check pending command number again after lock.
	 */
	if (!pq->num)
		return;
	ERTUSER_INFO( "->%s: pq->num: %d...\n", __func__, pq->num);

	spin_lock_irqsave(&ert_user->pq_lock, flags);
	if (pq->num) {
		list_splice_tail_init(&pq->head, &rq->head);
		rq->num += pq->num;
		pq->num = 0;
	}
	spin_unlock_irqrestore(&ert_user->pq_lock, flags);
	ERTUSER_INFO( "<- %s\n", __func__);
}

/**
 * process_ert_sq() - Process cmd which is submitted
 * @ert_user: Target XRT ERT
 */
static inline void process_ert_sq(struct zocl_ert_user *ert_user)
{
	struct kds_command *xcmd;
	struct ert_user_command *ecmd, *next;
	struct kds_client *ev_client = NULL;
	unsigned int tick;

	if (!ert_user->sq.num)
		return;

	ERTUSER_INFO( "%s -> ert_user->sq.num: %d...\n",
				  __func__, ert_user->sq.num);

	ev_client = first_event_client_or_null(ert_user);

	list_for_each_entry_safe(ecmd, next, &ert_user->sq.head, list) {
		xcmd = ecmd->xcmd;
		if (ecmd->completed) {
			ert_get_return(ert_user, ecmd);
			ecmd->status = KDS_COMPLETED;
		} else if (unlikely(ev_client)) {
			/* Client event happens rarely */
			if (xcmd->client != ev_client)
				continue;

			tick = atomic_read(&ert_user->tick);
			/* Record command tick to start timeout counting */
			if (!xcmd->tick) {
				xcmd->tick = tick;
				continue;
			}

			/* If xcmd haven't timeout */
			if (tick - xcmd->tick < ERT_EXEC_DEFAULT_TTL)
				continue;

			ecmd->status = KDS_TIMEOUT;
			/* Mark ERT as bad state */
			ert_user->bad_state = true;
		} else {
			ERTUSER_INFO("%s: in else part, ev_client: 0x%x\n", __func__,
						 ev_client);
			continue;
		}

		ERTUSER_INFO( "%s -> ecmd %llx xcmd: %p, completed: %d, status: %d\n",
				  __func__, (u64)ecmd, xcmd, ecmd->completed, ecmd->status);
		list_move_tail(&ecmd->list, &ert_user->cq.head);
		--ert_user->sq.num;
		++ert_user->cq.num;
		ert_user->submit_queue[ecmd->slot_idx] = NULL;
	}
	ERTUSER_INFO( "<- %s\n", __func__);
}

static void ert_user_reset(struct zocl_ert_user *ert_user)
{
	bitmap_zero(ert_user->slot_status, ERT_MAX_SLOTS);
	set_bit(0, ert_user->slot_status);
}

static inline bool zocl_eu_thread_sleep_cond(struct zocl_ert_user *ert_user)
{
	bool ret = false;
	bool polling_sleep = false, intr_sleep = false, no_event = false
	, no_completed_cmd = false, no_submmited_cmd = false
	, cant_submit = false, cant_submit_start = false, cant_submit_ctrl = false
	, no_need_to_fetch_new_cmd = false, no_need_to_fetch_start_cmd = false
	, no_need_to_fetch_ctrl_cmd = false;


	/* When ert_thread should go to sleep to save CPU usage
	 * 1. There is no event to be processed
	 * 2. We don't have to process command when
	 *    a. We can't submit cmd if we don't have cmd in running queue or submitted queue is full
	 *    b. There is no cmd in pending queue or we still have cmds in running queue
	 *    c. There is no cmd in completed queue
	 * 3. We are not in polling mode and there is no cmd in submitted queue
	 */

	no_completed_cmd = !ert_user->cq.num;

	cant_submit_start = (!ert_user->rq.num) ||
		(ert_user->sq.num == (ert_user->num_slots-1));
	cant_submit_ctrl = (!ert_user->rq_ctrl.num) || (ert_user->sq.num == 1);
	cant_submit = cant_submit_start && cant_submit_ctrl;

	no_need_to_fetch_start_cmd = ert_user->rq.num !=0 || !ert_user->pq.num;
	no_need_to_fetch_ctrl_cmd = ert_user->rq_ctrl.num !=0 ||
		!ert_user->pq_ctrl.num;
	no_need_to_fetch_new_cmd = no_need_to_fetch_ctrl_cmd &&
		no_need_to_fetch_start_cmd;

	no_submmited_cmd = !ert_user->sq.num;

	polling_sleep = no_completed_cmd && no_need_to_fetch_new_cmd &&
		no_submmited_cmd;
	intr_sleep = no_completed_cmd && no_need_to_fetch_new_cmd && cant_submit;

	no_event = first_event_client_or_null(ert_user) == NULL;


	ret = no_event && ((ert_user->polling_mode && polling_sleep) ||
					   (!ert_user->polling_mode && intr_sleep));
	if (ert_user->sq.num)
		ret = 0;
	return ret;
}

/**
 * process_ert_cq() - Process cmd which is completed
 * @ert_user: Target XRT CU
 */
static inline void process_ert_cq(struct zocl_ert_user *ert_user)
{
	struct kds_command *xcmd;
	struct ert_user_command *ecmd;

	if (!ert_user->cq.num)
		return;

	ERTUSER_INFO( "%s -> ert_user->cq.num: %d\n", __func__, ert_user->cq.num);
	while (ert_user->cq.num) {
		ecmd = list_first_entry(&ert_user->cq.head, struct ert_user_command,
								list);
		list_del(&ecmd->list);
		xcmd = ecmd->xcmd;
		ert_post_process(ert_user, ecmd);
		ert_release_slot(ert_user, ecmd);
		ERTUSER_INFO("-> %s before notify_host(), ecmd->status: %d\n",
				 __func__, ecmd->status);
		xcmd->cb.notify_host(xcmd, ecmd->status);
		ERTUSER_INFO("-> %s after notify_host()\n", __func__);
		xcmd->cb.free(xcmd);
		ert_user_free_cmd(ecmd);
		--ert_user->cq.num;
	}

	ERTUSER_INFO( "<- %s\n", __func__);
}

static void zocl_intc_ert_write32(struct zocl_ert_user *ert_user, u32 mask,
								 u32 intr)
{
	ERTUSER_INFO("%s: TODO\n", __func__);
}

static u32 zocl_intc_ert_read32(struct zocl_ert_user *ert_user, int id)
{
	u32 status = ioread32(ert_user->csr_reg[id]);

	return status;
}

/**
 * process_ert_sq_polling() - Process submitted queue
 * @ert_user: Target XRT ERT
 */
static inline void process_ert_sq_polling(struct zocl_ert_user *ert_user)
{
	struct kds_command *xcmd;
	struct ert_user_command *ecmd;
	u32 mask = 0;
	u32 slot_idx = 0, section_idx = 0;
	struct kds_client *ev_client = NULL;
	unsigned int tick;

	if (!ert_user->sq.num)
		return;

	for (section_idx = 0; section_idx < 4; ++section_idx) {
		mask = zocl_intc_ert_read32(ert_user, section_idx);
		if (!mask)
			return;//continue;
		u32 csr = mask;
	    ERTUSER_INFO( "%s: ert_user->sq.num: %d, mask: 0x%x, section_idx: %d\n",
				  __func__, ert_user->sq.num, mask, section_idx);
		for ( slot_idx = 0; slot_idx < 32; mask>>=1, ++slot_idx ) {
			u32 cmd_idx = slot_idx+(section_idx<<5);
			if (mask & 0x1) {
				ecmd = ert_user->submit_queue[cmd_idx];
				if (ecmd) {
					xcmd = ecmd->xcmd;
					ert_get_return(ert_user, ecmd);
					ecmd->completed = true;
					ecmd->status = KDS_COMPLETED;
					ERTUSER_INFO( "%s -> ecmd: 0x%llx, xcmd: %p\n", __func__,
							  (u64)ecmd, xcmd);
					list_move_tail(&ecmd->list, &ert_user->cq.head);
					--ert_user->sq.num;
					++ert_user->cq.num;
					ert_user->submit_queue[cmd_idx] = NULL;
				} else {
					ERTUSER_INFO( "ERR: submit queue slot is empty\n");
					--ert_user->sq.num;
				}
				csr = csr & ~(1 << slot_idx);
				iowrite32(csr, ert_user->csr_reg[(section_idx)]);//<<2)]);
			}
		}//for (slot_idx)
	}//for (section_idx)

	return;

	ev_client = first_event_client_or_null(ert_user);
	if (likely(!ev_client))
		return;

	for (slot_idx = 0; slot_idx < ert_user->num_slots; ++slot_idx) {
		ecmd = ert_user->submit_queue[slot_idx];
		if (!ecmd)
			continue;
		xcmd = ecmd->xcmd;

		/* Client event happens rarely */
		if (xcmd->client != ev_client)
			continue;

		tick = atomic_read(&ert_user->tick);
		/* Record CU tick to start timeout counting */
		if (!xcmd->tick) {
			xcmd->tick = tick;
			continue;
		}

		/* If xcmd haven't timeout */
		if (tick - xcmd->tick < ERT_EXEC_DEFAULT_TTL)
			continue;

		ecmd->status = KDS_TIMEOUT;
		/* Mark this CU as bad state */
		ert_user->bad_state = true;

		ERTUSER_INFO( "%s -> KDS_TIMEOUT ecmd %llx xcmd%p\n", __func__, (u64)ecmd, xcmd);
		list_move_tail(&ecmd->list, &ert_user->cq.head);
		--ert_user->sq.num;
		++ert_user->cq.num;
		ert_user->submit_queue[slot_idx] = NULL;
	}
}

static inline void
ert_post_process(struct zocl_ert_user *ert_user, struct ert_user_command *ecmd)
{
	ERTUSER_INFO("%s: opcode: %d\n", __func__, cmd_opcode(ecmd));
	if (likely(!ert_special_cmd(ecmd)))
		return;

	switch (cmd_opcode(ecmd)) {
	case OP_VALIDATE:
	case OP_CLK_CALIB:
		memcpy(&ert_user->ert_valid, ert_user->cq_base,
			   sizeof(struct ert_validate_cmd));
		break;
	case OP_CONFIG:
		zocl_ert_cfg_host(ert_user, ecmd);
		break;
	default:
		break;
	}

	return;
}

static void
zocl_ert_cfg_host(struct zocl_ert_user *ert_user, struct ert_user_command *ecmd)
{
	struct ert_configure_cmd *cfg = (struct ert_configure_cmd *)ecmd->xcmd->execbuf;
	bool ert = 1;//(XOCL_DSA_IS_VERSAL(xdev) || XOCL_DSA_IS_MPSOC(xdev)) ? 1 : xocl_mb_sched_on(xdev);
	bool ert_full = !cfg->dataflow;
	bool ert_poll = cfg->dataflow;

	BUG_ON(cmd_opcode(ecmd) != OP_CONFIG);
	BUG_ON(!ert);

	ERTUSER_INFO("%s: opcode: %d\n", __func__, cmd_opcode(ecmd));
	if (ecmd->status != KDS_COMPLETED)
		return;

	ert_user->num_slots = ert_user->cq_range / cfg->slot_size;

	// Adjust slot size for ert poll mode
	if (ert_poll)
		ert_user->num_slots = MAX_CUS;

	ert_user->polling_mode = cfg->polling;

	if (ert_user->polling_mode)
		zocl_ert_intc_enable(ert_user, false);
	else
		zocl_ert_intc_enable(ert_user, true);

	if (ert_full && cfg->cu_dma && ert_user->num_slots > 32) {
		// Max slot size is 32 because of cudma bug
		ERTUSER_INFO( "Limitting CQ size to 32 due to ERT CUDMA bug\n");
		ert_user->num_slots = 32;
	}

	ERTUSER_INFO( "scheduler config ert completed, polling_mode(%d), slots(%d)\n"
		 , ert_user->polling_mode
		 , ert_user->num_slots);

	// TODO: reset all queues
	ert_user_reset(ert_user);

	ert_user->is_configured = true;
	return;
}

static void zocl_ert_intc_enable(struct zocl_ert_user *ert_user, bool enable)
{
	ERTUSER_INFO("%s: TODO: register ert_inc\n", __func__);
}

int zocl_ert_user_gpio_cfg(struct drm_zocl_dev *zdev, enum ert_gpio_cfg type)
{
	ERTUSER_INFO("%s: TODO\n", __func__);
	return -ENODEV;
}

/**
 * mask_idx32() - Slot mask idx index for a given slot_idx
 *
 * @slot_idx: Global [0..127] index of a CQ slot
 * Return: Index of the slot mask containing the slot_idx
 */
static inline unsigned int mask_idx32(unsigned int idx)
{
	return idx >> 5;
}

static irqreturn_t ert_user_isr(int irq, void *arg)
{
	struct zocl_ert_user *ert_user = (struct zocl_ert_user *)arg;
	ERTUSER_INFO("%s: irq: %d, TODO\n", __func__, irq);
	return IRQ_NONE;

	struct ert_user_command *ecmd;

	BUG_ON(!ert_user);

	ERTUSER_INFO( "-> xocl_user_event %d\n", irq);

	BUG_ON(irq>=ERT_MAX_SLOTS);

	if (!ert_user->polling_mode) {

		ecmd = ert_user->submit_queue[irq];
		if (ecmd) {
			ecmd->completed = true;
		} else {
			ERTUSER_ERR( "%s: not in submitted queue %d\n", __func__, irq);
		}

		up(&ert_user->sem);
	} else {
		ERTUSER_INFO( "unhandled isr irq %d", irq);
		return IRQ_NONE;
	}
	ERTUSER_INFO( "<- xocl_user_event %d\n", irq);
	return IRQ_HANDLED;
}

static void ert_user_free_cmd(struct ert_user_command* ecmd)
{
	ERTUSER_DBG("%s\n", __func__);
	kfree(ecmd);
}

static inline int
ert_return_size(struct ert_user_command *ecmd, int max_size)
{
	int ret;

	/* Different opcode has different size of return info */
	switch (cmd_opcode(ecmd)) {
	case OP_GET_STAT:
		ret = max_size;
		break;
	case OP_START_SK:
		ret = 2 * sizeof(u32);
		break;
	default:
		ret = 0;
	};

	return ret;
}

/* ERT would return some information when notify host. Ex. PS kernel start and
 * get CU stat commands. In this case, need read CQ slot to get return info.
 *
 * TODO:
 * Assume there are 64 PS kernel and 2 nornal CUs. The ERT_CU_STAT command
 * requires more than (64+2)*2*4 = 528 bytes (without consider other info).
 * In this case, the slot size needs to be 1K and maximum 64 CQ slots.
 *
 * In old kds, to avoid buffer overflow, it silently truncate return value.
 * Luckily there is always use 16 slots in old kds.
 * But truncate is definitly not ideal, this should be fixed in new KDS.
 */
static inline void
ert_get_return(struct zocl_ert_user *ert_user, struct ert_user_command *ecmd)
{
	u32 slot_addr;
	int slot_size = ert_user->cq_range / ert_user->num_slots;
	int size;

	size = ert_return_size(ecmd, slot_size);
	if (!size)
		return;

	slot_addr = ecmd->slot_idx * slot_size;
	memcpy_fromio(ecmd->xcmd->execbuf, ert_user->cq_base + slot_addr, size);
}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)

static void ert_timer(unsigned long data)
{
	struct zocl_ert_user *ert_user = (struct zocl_ert_user *)data;
#else
static void ert_timer(struct timer_list *t)
{
	struct zocl_ert_user *ert_user = from_timer(ert_user, t, timer);
#endif

	atomic_inc(&ert_user->tick);

	mod_timer(&ert_user->timer, jiffies + ERT_TIMER);
}

int zocl_ert_user_thread(void *data)
{
	struct zocl_ert_user *ert_user = (struct zocl_ert_user *)data;
	struct drm_zocl_dev *zdev = ert_user->pdev;
	int ret = 0;

	mod_timer(&ert_user->timer, jiffies + ERT_TIMER);

	ERTUSER_INFO("%s: invoked\n", __func__);
	while (!ert_user->stop) {
		/* Make sure to submit as many commands as possible.
		 * This is why we call continue here. This is important to make
		 * CU busy, especially CU has hardware queue.
		 */
		if (process_ert_rq(ert_user, &ert_user->rq_ctrl))
			continue;

		if (process_ert_rq(ert_user, &ert_user->rq))
			continue;
		/* process completed queue before submitted queue, for
		 * two reasons:
		 * - The last submitted command may be still running
		 * - while handling completed queue, running command might done
		 * - process_ert_sq_polling will check CU status, which is thru slow bus
		 */

//		if (ert_user->polling_mode)
			process_ert_sq_polling(ert_user);
//		else
//			process_ert_sq(ert_user);

		process_ert_cq(ert_user);

		/* If any event occured, we should drain all the related commands ASAP
		 * It only goes to sleep if there is no event
		 */
		if (zocl_eu_thread_sleep_cond(ert_user)) {
			ERTUSER_INFO("zocl_ert_user_thread in sleep mode\n");
			if (down_interruptible(&ert_user->sem))
				ret = -ERESTARTSYS;
		}

		process_ert_pq(ert_user, &ert_user->pq, &ert_user->rq);
		process_ert_pq(ert_user, &ert_user->pq_ctrl, &ert_user->rq_ctrl);
	}
	del_timer_sync(&ert_user->timer);

	if (!ert_user->bad_state)
		ret = -EBUSY;

	return ret;
}

static inline struct kds_client* first_event_client_or_null
(struct zocl_ert_user *ert_user)
{
	struct kds_client *curr = NULL;

	if (list_empty(&ert_user->events))
		return NULL;

	mutex_lock(&ert_user->ev_lock);
	if (list_empty(&ert_user->events))
		goto done;

	curr = list_first_entry(&ert_user->events, struct kds_client, ev_entry);

done:
	mutex_unlock(&ert_user->ev_lock);
	return curr;
}

static int zocl_ert_cfg_cmd(struct zocl_ert_user *ert_user,
							struct ert_user_command *ecmd)
{
	struct drm_zocl_dev *zdev = ert_user->pdev;
	struct ert_configure_cmd *cfg =
		(struct ert_configure_cmd *)ecmd->xcmd->execbuf;
	bool ert_full = !cfg->dataflow;
	bool ert_poll = cfg->dataflow;
	unsigned int ert_num_slots = 0;
	bool ert = 1;

	BUG_ON(!ert);

	ERTUSER_INFO("%s: opcode: %d\n", __func__, cmd_opcode(ecmd));
	if (cmd_opcode(ecmd) != OP_CONFIG) {
		ERTUSER_ERR("%s: opcode %d is not CONFIG cmd, returns -EINVAL\n",
					__func__, cmd_opcode(ecmd));
		return -EINVAL;
	}

	cfg->slot_size = 16;
	cfg->ert = 1;

	ERTUSER_INFO("%s: configuring scheduler cq_size(%lld), slot_size(%d), ert(%d)\n",
				__func__, ert_user->cq_range, cfg->slot_size, cfg->ert);

	if (ert_user->cq_range == 0 || cfg->slot_size == 0) {
		ERTUSER_ERR( "%s: should not have zeroed value of cq_size=%lld, slot_size=%d",
		    __func__, ert_user->cq_range, cfg->slot_size);
		return -EINVAL;
	}

	if (!zdev->ert) {
		if (cfg->ert)
			ERTUSER_INFO("%s: No ERT scheduler on MPSoC, using KDS\n", __func__);
		ert_user->polling_mode = cfg->polling;
		/*
		 * Interrupt may not be enabled for some of the kernel,
		 * Need to use polling mode in that case
		 */
		if (!zocl_xclbin_cus_support_intr(zdev)) {
			DRM_WARN("%s: Interrupt is not enabled for at least one "
			    "kernel. Fall back to polling mode.\n", __func__);
			ert_user->polling_mode = 1;
		} else {
			DRM_WARN("%s: Interrupt is enabled for at least one kernel.\n",
					 __func__);
		}
		ert_user->is_configured = true;
	}

	ert_poll = ert_user->polling_mode;

	ert_num_slots = ert_user->cq_range / cfg->slot_size;
	ert_poll = true;
	ert_full = false;

	if (ert_poll) {
		// Adjust slot size for ert poll mode
		ert_num_slots = MAX_CUS;
		ert_full = false;
	}
	if (ert_full && cfg->cu_dma && ert_num_slots > 32) {
		// Max slot size is 32 because of cudma bug
		ERTUSER_INFO( "Limitting CQ size to 32 due to ERT CUDMA bug\n");
		ert_num_slots = 32;
	}

	cfg->slot_size = ert_user->cq_range / ert_num_slots;

	if (ert_poll) {
		ERTUSER_INFO( "configuring dataflow mode with ert polling\n");
		cfg->cu_isr = 0;
		cfg->cu_dma = 0;
	} else if (ert_full) {
		ERTUSER_INFO( "configuring embedded scheduler mode\n");
		cfg->dsa52 = 1;//dsa;
		cfg->cdma = 0;//cdma ? 1 : 0;
	}

	cfg->intr = ert_user->intr;
	ERTUSER_INFO( "scheduler config ert(%d), polling(%d), dataflow(%d), cudma(%d), cuisr(%d)\n"
		 , cfg->ert
		 , ert_user->polling_mode
		 , cfg->dataflow
		 , cfg->cu_dma ? 1 : 0
		 , cfg->cu_isr ? 1 : 0);
	return 0;
}

static inline bool
ert_pre_process(struct zocl_ert_user *ert_user,
				struct ert_user_command *ecmd)
{
	bool bad_cmd = false;

	ERTUSER_INFO("%s: opcode: %d\n", __func__, cmd_opcode(ecmd));
	switch (cmd_opcode(ecmd)) {
	case OP_START:
	case OP_START_SK:
		BUG_ON(ert_user->ctrl_busy);
#if KERNEL_VERSION(5, 4, 0) > LINUX_VERSION_CODE
		__attribute__ ((fallthrough));
#else
		__attribute__ ((__fallthrough__));
#endif
	case OP_CLK_CALIB:
	case OP_CONFIG_SK:
	case OP_GET_STAT:
	case OP_VALIDATE:
		BUG_ON(!ert_user->is_configured);
		bad_cmd = false;
		break;
	case OP_CONFIG:
		if (zocl_ert_cfg_cmd(ert_user, ecmd))
			bad_cmd = true;
		break;
	default:
		bad_cmd = true;
	}

	return bad_cmd;
}

static inline bool ert_special_cmd(struct ert_user_command *ecmd)
{
	bool ret;

	switch (cmd_opcode(ecmd)) {
	case OP_CONFIG:
	case OP_CONFIG_SK:
	case OP_GET_STAT:
	case OP_CLK_CALIB:
	case OP_VALIDATE:
		ret = true;
		break;
	default:
		ret = false;
	}

	return ret;
}

/*
 * acquire_slot_idx() - First available slot index
 */
static unsigned int
ert_acquire_slot_idx(struct zocl_ert_user *ert_user)
{
	unsigned int idx = find_first_zero_bit(ert_user->slot_status,
										   ERT_MAX_SLOTS);

	if (idx < ert_user->num_slots) {
		set_bit(idx, ert_user->slot_status);
		return idx;
	}
	return no_index;
}

/**
 * acquire_slot() - Acquire a slot index for a command
 *
 * This function makes a special case for control commands which
 * must always dispatch to slot 0, otherwise normal acquisition
 */
static int ert_acquire_slot(struct zocl_ert_user *ert_user,
							struct ert_user_command *ecmd)
{
	// slot 0 is reserved for ctrl commands
	if (ert_special_cmd(ecmd)) {
		set_bit(0, ert_user->slot_status);

		if (ert_user->ctrl_busy) {
			ERTUSER_ERR("%s: ctrl slot is busy\n", __func__);
			return -1;
		}
		if (cmd_opcode(ecmd) != OP_GET_STAT)
			ert_user->ctrl_busy = true;
		ecmd->slot_idx = 0;
	} else {
		ecmd->slot_idx = ert_acquire_slot_idx(ert_user);
	}

	ERTUSER_INFO("%s: cmd opcode: %d, assigned slot_idx: %d\n",
				 __func__, cmd_opcode(ecmd), ecmd->slot_idx);
	return ecmd->slot_idx;
}

/**
 * process_ert_rq() - Process run queue
 * @ert_user: Target XRT ERT
 * @rq: Target running queue
 *
 * Return: return 0 if run queue is empty or no available slot
 *	   Otherwise, return 1
 */
static inline int process_ert_rq(struct zocl_ert_user *ert_user,
								 struct zocl_eu_queue *rq)
{
	struct ert_user_command *ecmd, *next;
	u32 slot_addr = 0;
	struct ert_packet *epkt = NULL;
	struct kds_client *ev_client = NULL;
	u32 mask_idx, cq_int_addr, mask;
	int i = 0;

	if (!rq->num)
		return 0;

	ERTUSER_INFO("->%s: rq->num: %d\n", __func__, rq->num);
	ev_client = first_event_client_or_null(ert_user);
	list_for_each_entry_safe(ecmd, next, &rq->head, list) {
		struct kds_command *xcmd = ecmd->xcmd;
		if (unlikely(ert_user->bad_state || (ev_client == xcmd->client))) {
			ERTUSER_ERR("%s abort, opcode: %d\n", __func__, cmd_opcode(ecmd));
			ecmd->status = KDS_ERROR;
			list_move_tail(&ecmd->list, &ert_user->cq.head);
			--rq->num;
			++ert_user->cq.num;
			continue;
		}

		if (ert_pre_process(ert_user, ecmd)) {
			ERTUSER_ERR("%s bad cmd, opcode: %d\n", __func__, cmd_opcode(ecmd));
			ecmd->status = KDS_ABORT;
			list_move_tail(&ecmd->list, &ert_user->cq.head);
			--rq->num;
			++ert_user->cq.num;
			continue;
		}

		if (ert_acquire_slot(ert_user, ecmd) == no_index) {
			ERTUSER_ERR("%s not slot available, opcode: %d, returns 0\n",
						__func__, cmd_opcode(ecmd));
			return 0;
		}
		epkt = (struct ert_packet *)ecmd->xcmd->execbuf;
		ERTUSER_INFO( "%s op_code %d ecmd->slot_idx %d\n", __func__,
				  cmd_opcode(ecmd), ecmd->slot_idx);
		sched_debug_packet(epkt, epkt->count+sizeof(epkt->header)/sizeof(u32));

		if (cmd_opcode(ecmd) == OP_CONFIG && !ert_user->polling_mode) {
			for (i = 0; i < ert_user->num_slots; i++) {
				//xocl_intc_ert_request(xdev, i, ert_user_isr, ert_user);
				//xocl_intc_ert_config(xdev, i, true);
			}
		}
		slot_addr = ecmd->slot_idx * (ert_user->cq_range/ert_user->num_slots);
		/* Hardware could be pretty fast, add to sq before touch the CQ_status or cmd queue*/
		list_move_tail(&ecmd->list, &ert_user->sq.head);
		ert_user->submit_queue[ecmd->slot_idx] = ecmd;
		--rq->num;
		++ert_user->sq.num;

		ERTUSER_INFO( "%s slot_addr %x, epkt->count: %d, cmd_opcode(ecmd): %d, kds_echo: %d\n",
				  __func__, slot_addr, epkt->count, cmd_opcode(ecmd), kds_echo);
		if (kds_echo) {
			ecmd->completed = true;
		} else {
			uint64_t taddr = ert_user->cq_base + slot_addr;
			if (cmd_opcode(ecmd) == OP_START) {
				// write kds selected cu_idx in first cumask (first word after header)
				iowrite32(ecmd->xcmd->cu_idx, taddr + 4);

				// write remaining packet (past header and cuidx)
				memcpy_toio(taddr + 8, ecmd->xcmd->execbuf+2,
							(epkt->count-1)*sizeof(u32));
			} else {
				memcpy_toio(taddr + 4, ecmd->xcmd->execbuf+1,
							epkt->count*sizeof(u32));
			}

			iowrite32(epkt->header, taddr);
			for (i = 0; i < epkt->count * sizeof(u32); i += 4)
				ERTUSER_INFO("%s: pkt:%d, val: 0x%x\n",
							 __func__, i/4, ioread32(taddr + i));
		}

		/*
		 * Always try to trigger interrupt to embedded scheduler.
		 * The reason is, the ert configure cmd is also sent to MB/PS through cq,
		 * and at the time the new ert configure cmd is sent, host doesn't know
		 * MB/PS is running in cq polling or interrupt mode. eg, if MB/PS is in
		 * cq interrupt mode, new ert configure is cq polling mode, but the new
		 * ert configure cmd has to be received by MB/PS throught interrupt mode
		 *
		 * Setting the bit in cq status register when MB/PS is in cq polling mode
		 * doesn't do harm since the interrupt is disabled and MB/PS will not read
		 * the register
		 */
		mask_idx = mask_idx32(ecmd->slot_idx);
		cq_int_addr = CQ_STATUS_OFFSET + (mask_idx << 2);
		mask = 1 << idx_in_mask32(ecmd->slot_idx, mask_idx);

		ERTUSER_INFO( "<-%s: mb_submit writes slot mask 0x%x to CQ_INT register at addr 0x%x\n",
				  __func__, mask, cq_int_addr);
		zocl_intc_ert_write32(ert_user, mask, cq_int_addr);
	}
	ERTUSER_INFO("<-%s, returns 1\n", __func__);

	return 1;
}

static struct ert_user_command* alloc_ecmd(struct kds_command *xcmd)
{
	struct ert_user_command* ecmd =
		kzalloc(sizeof(struct ert_user_command), GFP_KERNEL);

	if (!ecmd)
		return NULL;

	ecmd->xcmd = xcmd;

	return ecmd;
}

static void eu_submit(struct kds_ert *ert, struct kds_command *xcmd)
{
	struct zocl_ert_user *ert_user = container_of(ert, struct zocl_ert_user,
												  ert);
	unsigned long flags;
	bool first_command = false;
	struct ert_user_command *ecmd = alloc_ecmd(xcmd);

	ERTUSER_INFO("%s: invoked, ecmd: 0x%llx\n", __func__, (u64)ecmd);
	if (!ecmd)
		return;

	spin_lock_irqsave(&ert_user->pq_lock, flags);
	switch (cmd_opcode(ecmd)) {
	case OP_START:
		list_add_tail(&ecmd->list, &ert_user->pq.head);
		++ert_user->pq.num;
		break;
	case OP_VALIDATE:
	case OP_CONFIG:
	default:
		list_add_tail(&ecmd->list, &ert_user->pq_ctrl.head);
		++ert_user->pq_ctrl.num;
		break;
	}
	first_command = ((ert_user->pq.num + ert_user->pq_ctrl.num) == 1);
	spin_unlock_irqrestore(&ert_user->pq_lock, flags);
	/* Add command to pending queue
	 * wakeup service thread if it is the first command
	 */
	if (first_command)
		up(&ert_user->sem);

	ERTUSER_INFO("<-%s\n", __func__);
	return 0;
}

static void eu_abort(struct kds_ert *ert, struct kds_client *client,
			  int cu_idx)
{
	struct zocl_ert_user *exec = container_of(ert, struct zocl_ert_user, ert);
	struct kds_client *curr;

	ERTUSER_INFO("%s: invoked..\n", __func__);
	mutex_lock(&exec->ev_lock);
	if (list_empty(&exec->events))
		goto add_event;

	/* avoid re-add the same client */
	list_for_each_entry(curr, &exec->events, ev_entry) {
		if (client == curr)
			goto done;
	}

add_event:
	client->ev_type = EV_ABORT;
	list_add_tail(&client->ev_entry, &exec->events);
	/* The process thread may asleep, we should wake it up if
	 * abort event takes place
	 */
	up(&exec->sem);
done:
	mutex_unlock(&exec->ev_lock);
	ERTUSER_INFO("<-%s\n", __func__);
	return;
}
static bool eu_abort_done(struct kds_ert *ert,
				   struct kds_client *client, int cu_idx)
{
	struct zocl_ert_user *exec = container_of(ert, struct zocl_ert_user, ert);
	struct kds_client *curr, *next;

	ERTUSER_INFO("%s: invoked..\n", __func__);
	mutex_lock(&exec->ev_lock);
	if (list_empty(&exec->events))
		goto done;

	list_for_each_entry_safe(curr, next, &exec->events, ev_entry) {
		if (client != curr)
			continue;

		list_del(&curr->ev_entry);
		break;
	}
done:
	mutex_unlock(&exec->ev_lock);
	ERTUSER_INFO("<-%s\n", __func__);

	return exec->bad_state;
}

int zocl_init_ert_user_sched(struct drm_zocl_dev *zdev)
{
	struct zocl_ert_user *ert_user;
	int err = 0;

	ert_user = vzalloc(sizeof(struct zocl_ert_user));
	if (!ert_user)
		return -ENOMEM;

	zdev->ert_user = ert_user;
	ert_user->pdev = zdev;

	/* Initialize pending queue and lock */
	INIT_LIST_HEAD(&ert_user->pq.head);
	INIT_LIST_HEAD(&ert_user->pq_ctrl.head);
	spin_lock_init(&ert_user->pq_lock);
	/* Initialize run queue */
	INIT_LIST_HEAD(&ert_user->rq.head);
	INIT_LIST_HEAD(&ert_user->rq_ctrl.head);

	/* Initialize completed queue */
	INIT_LIST_HEAD(&ert_user->cq.head);
	INIT_LIST_HEAD(&ert_user->sq.head);

	mutex_init(&ert_user->ev_lock);
	INIT_LIST_HEAD(&ert_user->events);

	sema_init(&ert_user->sem, 0);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
	setup_timer(&ert_user->timer, ert_timer, (unsigned long)ert_user);
#else
	timer_setup(&ert_user->timer, ert_timer, 0);
#endif
	atomic_set(&ert_user->tick, 0);

	ert_user->thread = kthread_run(zocl_ert_user_thread, ert_user, "zocl_ert_user_thread");

	ert_user->cq_range = ERT_RPU_CQ_RANGE;//res->end - res->start + 1;
	ert_user->cq_base = ioremap_wc(ERT_RPU_CQ_BASE_ADDR, ert_user->cq_range);
	if (!ert_user->cq_base) {
		err = -EIO;
		ERTUSER_ERR("%s: ert_user->cq_base Map iomem failed, err: %d",
					__func__, err);
		goto done;
	}
	ert_user->csr_reg[0] = ioremap_wc(ERT_RPU_CSR_BASE_ADDR, 4);
	ert_user->csr_reg[1] = ioremap_wc(ERT_RPU_CSR_BASE_ADDR + 4, 4);
	ert_user->csr_reg[2] = ioremap_wc(ERT_RPU_CSR_BASE_ADDR + 8, 4);
	ert_user->csr_reg[3] = ioremap_wc(ERT_RPU_CSR_BASE_ADDR + 0xC, 4);

	ERTUSER_INFO( "CQ IO range: 0x%llx, start: 0x%llx", ert_user->cq_range,
			  ert_user->cq_base);

	ert_user->ert.submit = eu_submit;
	ert_user->ert.abort = eu_abort;
	ert_user->ert.abort_done = eu_abort_done;

	kds_init_ert(&zdev->kds, &ert_user->ert);

	/* Enable interrupt by default */
	ert_user->num_slots = 128;
	ert_user->polling_mode = false;
	zocl_ert_intc_enable(ert_user, true);
done:
	if (err) {
		zocl_fini_ert_user_sched(zdev);
		return err;
	}
	return 0;
}

void zocl_fini_ert_user_sched(struct drm_zocl_dev *zdev)
{
	struct zocl_ert_user *ert_user = zdev->ert_user;

	if (!ert_user)
		return;

	ERTUSER_INFO("->%s\n", __func__);
	mutex_destroy(&zdev->ert_user->ev_lock);

	if (ert_user->cq_base)
		iounmap(ert_user->cq_base);

	zocl_ert_intc_enable(ert_user, false);

	ert_user->stop = 1;
	up(&ert_user->sem);
	(void) kthread_stop(ert_user->thread);
	ERTUSER_INFO("<-%s: done...\n", __func__);
}

