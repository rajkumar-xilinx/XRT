#include "zocl_drv.h"
#include "kds_core.h"

#define ERT_RPU_CQ_BASE_ADDR 0xFFE01000 //TCM memory
#define ERT_RPU_CQ_RANGE 0x8000 //32KB
#define ERT_RPU_CSR_BASE_ADDR 0xFFE09000 //Used in polling mode

//TODO: clean this for zocl_ert_user.c
#define	ERT_MAX_SLOTS		128

#define	ERT_STATE_GOOD		0x1
#define	ERT_STATE_BAD		0x2

#define CQ_STATUS_OFFSET	(ERT_CQ_STATUS_REGISTER_ADDR - ERT_CSR_ADDR)

//#define	SCHED_VERBOSE	1
/* ERT gpio config has two channels 
 * CHANNEL 0 is control channel :
 * BIT 0: 0x0 Selects interrupts from embedded scheduler HW block
 * 	  0x1 Selects interrupts from the CU INTCs
 * BIT 2-1: TBD
 *
 * CHANNEL 1 is status channel :
 * BIT 0: check microblazer status
 */

#define GPIO_CFG_CTRL_CHANNEL	0x0
#define GPIO_CFG_STA_CHANNEL	0x8

#define SWITCH_TO_CU_INTR	0x1
#define SWITCH_TO_ERT_INTR	~SWITCH_TO_CU_INTR

#define WAKE_MB_UP		0x2
#define CLEAR_MB_WAKEUP		~WAKE_MB_UP

/* XRT ERT timer macros */
/* A low frequence timer for ERT to check if command timeout */
#define ERT_TICKS_PER_SEC	2
#define ERT_TIMER		(HZ / ERT_TICKS_PER_SEC) /* in jiffies */
#define ERT_EXEC_DEFAULT_TTL	(5UL * ERT_TICKS_PER_SEC)

#define ERTUSER_ERR(fmt, ...) DRM_ERROR(fmt, ##__VA_ARGS__)
#define ERTUSER_INFO(fmt, ...) DRM_INFO(fmt, ##__VA_ARGS__)
#define	ERTUSER_WARN(fmt, ...) DRM_WARN(fmt, ##__VA_ARGS__)

#ifdef SCHED_VERBOSE
#define ERTUSER_DBG(fmt, ...) DRM_INFO(fmt, ##__VA_ARGS__)
#else
#define ERTUSER_DBG(fmt, ...) DRM_DEBUG(fmt, ##__VA_ARGS__)
#endif

#define sched_debug_packet(packet, size)                \
({                                  \
     int i;                              \
     u32 *data = (u32 *)packet;                  \
     for (i = 0; i < size; ++i)                      \
         DRM_INFO("packet(0x%p) execbuf[%d] = 0x%x\n", data, i, data[i]); \
 })

struct zocl_eu_queue {
	struct list_head	head;
	uint32_t		num;
};

struct ert_user_command {
	struct kds_command *xcmd;
	struct list_head    list;
	uint32_t	slot_idx;
	bool		completed;
	uint32_t	status;
};

struct zocl_ert_user {
	void __iomem		*cq_base;
	void __iomem		*csr_reg[4];
	void *pdev;
	uint64_t		cq_range;
	bool			polling_mode;
	struct kds_ert          ert;
	/* Configure dynamically */
	unsigned int		num_slots;
	bool			is_configured;
	bool			ctrl_busy;
	// Bitmap tracks busy(1)/free(0) slots in command_queue
	DECLARE_BITMAP(slot_status, ERT_MAX_SLOTS);

	struct zocl_eu_queue	pq;
	struct zocl_eu_queue	pq_ctrl;

	spinlock_t		pq_lock;
	/*
	 * Pending Q is used in thread that is submitting CU cmds.
	 * Other Qs are used in thread that is completing them.
	 * In order to prevent false sharing, they need to be in different
	 * cache lines. Hence we add a "padding" in between (assuming 128-byte
	 * is big enough for most CPU architectures).
	 */
	u64			padding[16];
	/* run queue */
	struct zocl_eu_queue	rq;
	struct zocl_eu_queue	rq_ctrl;


	struct semaphore	sem;
	/* submitted queue */
	struct zocl_eu_queue	sq;
	struct ert_user_command	*submit_queue[ERT_MAX_SLOTS];

	struct zocl_eu_queue	cq;

	u32			stop;
	bool			bad_state;

	struct mutex		ev_lock;
	struct list_head	events;

	struct timer_list	timer;
	atomic_t		tick;

	struct task_struct	*thread;

	uint32_t		intr;

	/* ert validate result cache*/
	struct ert_validate_cmd ert_valid;
	unsigned int ipi_irq;
};

