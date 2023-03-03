/*
 * A GEM style device manager for PCIe based OpenCL accelerators.
 *
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 *
 * Authors: rampelli@amd.com
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/aio.h>
#include <linux/anon_inodes.h>
#include <linux/eventfd.h>
#include <linux/debugfs.h>
#include <linux/dmaengine.h>
#include <linux/dma-buf.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/dma/amd_qdma.h>
//#include "amd_mqdma.h"
#include <linux/platform_data/amd_mqdma.h>
#include "../xocl_drv.h"
#include "../xocl_drm.h"
#include "qdma_ioctl.h"

#define QDMA_FILTER_PARAM(chan_info) ((void *)(chan_info))

#define RESOURSE_LEN		1

#define MM_DEFAULT_RINGSZ_IDX	0

#define QDMA_QSETS_MAX		256
#define QDMA_QSETS_BASE		0

#define QDMA_REQ_TIMEOUT_MS	10000

#define MAX_QUEUES		8
/* Module Parameters */
unsigned int qdma_max_queues = MAX_QUEUES;
module_param(qdma_max_queues, uint, 0644);
MODULE_PARM_DESC(qdma_max_queues, "Set number of queues for qdma, default is 8");

static unsigned int qdma_interrupt_mode = 1;
module_param(qdma_interrupt_mode, uint, 0644);
MODULE_PARM_DESC(interrupt_mode, "0:auto, 1:poll, 2:direct, 3:intr_ring, default is 2");

unsigned int skip_dma_chan_err = 1;
module_param(skip_dma_chan_err, uint, 0644);
MODULE_PARM_DESC(skip_dma_chan_err, "skip_dma_chan_err used in debugging");

struct mm_queue {
	struct dma_chan		*chan;
	struct device		dev;
	struct xocl_qdma	*qdma;
	unsigned long		queue_id;
	struct qdma_queue_conf	qconf;
	u64			total_trans_bytes;
	dma_cookie_t		dma_cookie;
	struct completion	req_compl;
	char 			chan_name[16];
};

struct xocl_qdma {
	struct platform_device	*pdev;
	struct platform_device	*dma_dev;
	struct semaphore	queues_sem[2]; /* Semaphore, one for each direction */
	struct mm_queue		*queues[2];
	struct qdma_queue_conf	qconf[2][MAX_QUEUES];
	u32			n_queues; /* Number of bidirectional queues */
	/*
	 * Queues usage bitmasks, one for each direction
	 * bit 1 indicates queue is free, bit 0 indicates queue is alloted
	 */
	volatile unsigned long	queues_bitmap[2];
	u16			instance;
};

static u32 get_queue_count(struct platform_device *pdev);
static u64 get_queue_stat(struct platform_device *pdev, u32 queue_id, u32 write);

static void device_release(struct device *dev)
{
	xocl_err(dev, "dummy device release callback");
}

static void free_queues(struct platform_device *pdev)
{
	struct xocl_qdma *qdma;

	qdma = platform_get_drvdata(pdev);
	if (!qdma) {
		xocl_err(&pdev->dev, "%s: qdma null", __func__);
		return;
	}

	if (qdma->queues[0])
		devm_kfree(&pdev->dev, qdma->queues[0]);
	if (qdma->queues[1])
		devm_kfree(&pdev->dev, qdma->queues[1]);
}

static void qdma_free_dma_chans(struct xocl_qdma *qdma)
{
	struct mm_queue *queue;
	u32 write, qidx;
	int i;

	for (i = 0; i < qdma->n_queues * 2; i++) {
		write = i / qdma->n_queues;
		qidx = i % qdma->n_queues;
		queue = &qdma->queues[write][qidx];
		if (!IS_ERR(queue->chan))
			dma_release_channel(queue->chan);
	}
}

static int alloc_queues(struct xocl_qdma *qdma, u32 n_queues)
{
	struct platform_device *pdev = qdma->pdev;
	struct qdma_queue_conf *qconf;
	struct mm_queue *queue;
	u32 write, qidx;
	int i, ret;

	if (n_queues > sizeof(qdma->queues_bitmap[0]) * MAX_QUEUES) {
		xocl_err(&pdev->dev, "Invalide number of queues set %d", n_queues);
		ret = -EINVAL;
		goto failed_create_queue;
	}

	qdma->n_queues = n_queues;

	xocl_info(&pdev->dev, "Creating MM Queues %d\n", qdma->n_queues);
	qdma->queues[0] = devm_kzalloc(&pdev->dev, sizeof(struct mm_queue) *
				       qdma->n_queues, GFP_KERNEL);
	qdma->queues[1] = devm_kzalloc(&pdev->dev, sizeof(struct mm_queue) *
				       qdma->n_queues, GFP_KERNEL);
	if (qdma->queues[0] == NULL || qdma->queues[1] == NULL) {
		xocl_err(&pdev->dev, "Alloc queue mem failed");
		ret = -ENOMEM;
		goto failed_create_queue;
	}

	for (i = 0; i < qdma->n_queues * 2; i++) {
		int len = 0;
		write = i / qdma->n_queues;
		qidx = i % qdma->n_queues;
		queue = &qdma->queues[write][qidx];
		queue->qdma = qdma;
		/* queue basic feature setup */
		qconf = &queue->qconf;
		queue->queue_id = qidx;
		if (write) {
			qconf->q_type = Q_H2C;
			sprintf(queue->chan_name, "h2c%d", qidx);
		} else {
			qconf->q_type = Q_C2H;
			queue->queue_id += qdma->n_queues;
			sprintf(queue->chan_name, "c2h%d", qidx);
		}
		memset(qconf, 0, sizeof (struct qdma_queue_conf));
		qconf->wb_status_en =1;
		qconf->desc_rng_sz_idx = MM_DEFAULT_RINGSZ_IDX;
		qconf->qidx = qidx;
		qconf->irq_en = 0;
		len = sprintf(qconf->name, "amdmqdma");
		len += snprintf(qconf->name + len, 64 - len, "-MM-%s-%u", write ? "H2C" : "C2H", qconf->qidx);
		qconf->name[len] = '\0';
		pr_debug("%s: qconf[%d][%d]: %d (c2h=1, h2c=0) %s\n", __func__,
			write, qidx, qconf->q_type, qconf->name);
		qconf = &qdma->qconf[write][qidx];
		memset(qconf, 0, sizeof (struct qdma_queue_conf));
		qconf->wb_status_en =1;
		qconf->desc_rng_sz_idx = MM_DEFAULT_RINGSZ_IDX;
		qconf->q_type = write ? Q_H2C : Q_C2H;
		qconf->qidx = qidx;
		qconf->irq_en = 0;
		len = sprintf(qconf->name, "qdma");
		len += snprintf(qconf->name + len, 64 - len, "-MM-%s-%u", write ? "H2C" : "C2H", qconf->qidx);
		qconf->name[len] = '\0';
	}

	xocl_info(&pdev->dev, "Created %d MM queues", qdma->n_queues);

	return 0;
failed_create_queue:

	return ret;
}

static void release_queue(struct platform_device *pdev, u32 dir, u32 q_num)
{
	struct xocl_qdma *qdma;

	xocl_err(&pdev->dev, "[Debug]%s: %d, dir: %d, q_num: %d\n", __func__, __LINE__, dir, q_num);

	qdma = platform_get_drvdata(pdev);
        set_bit(q_num, &qdma->queues_bitmap[dir]);
        up(&qdma->queues_sem[dir]);
}

static int acquire_queue(struct platform_device *pdev, u32 dir)
{
	struct xocl_qdma *qdma;
	int q_num = 0;
	int result = 0;
	u32 write;

	xocl_err(&pdev->dev, "[Debug]%s: dir: %d, q_num: %d\n", __func__, dir, q_num);

	qdma = platform_get_drvdata(pdev);

	if (!qdma) {
		pr_err("%s: qdma is NULL\n", __func__);
		q_num = -ERESTARTSYS;
		goto out;
	}

	if (down_killable(&qdma->queues_sem[dir])) {
		q_num = -ERESTARTSYS;
		goto out;
	}

	write = dir ? 1 : 0;
	for (q_num = 0; q_num < qdma->n_queues; q_num++) {
		result = test_and_clear_bit(q_num,
			&qdma->queues_bitmap[write]);
		pr_err("%s: qnum: %d, queues_bitmap[%d]: 0X%X\n", __func__, q_num, dir, qdma->queues_bitmap[dir]);
		if (result)
			break;
        }
	pr_info("%s: queues[%d][%d].qconf.name: %s\n", __func__, write, q_num, qdma->queues[write][q_num].qconf.name);

	if (strlen(qdma->queues[write][q_num].qconf.name) == 0) {
		xocl_err(&pdev->dev, "queue not started, queue %d", q_num);
//		release_queue(pdev, dir, q_num);
//		q_num = -EINVAL;
	}
out:
	xocl_err(&pdev->dev, "[Debug]%s: dir: %d, q_num: %d\n", __func__, dir, q_num);
	return 0;//q_num;
}


static u32 get_queue_count(struct platform_device *pdev)
{
	struct xocl_qdma *qdma;

        qdma = platform_get_drvdata(pdev);
        BUG_ON(!qdma);

        return qdma->n_queues;
}

static u64 get_queue_stat(struct platform_device *pdev, u32 q_num,
	u32 write)
{
	struct xocl_qdma *qdma;

        qdma = platform_get_drvdata(pdev);
        BUG_ON(!qdma);

        return qdma->queues[write][q_num].total_trans_bytes;
}

static void qdma_queue_req_complete(void *param)
{
	struct mm_queue *queue = param;

	complete(&queue->req_compl);
}

static ssize_t qdma_migrate_bo(struct platform_device *pdev,
			       struct sg_table *sgt, u32 write,
			       u64 paddr, u32 q_num, u64 len)
{
	struct dma_async_tx_descriptor *tx;
	enum dma_data_direction dma_dir;
	struct dma_slave_config cfg;
	struct mm_queue *queue;
	pid_t pid = current->pid;
	struct pci_dev *pci_dev;
	struct xocl_qdma *qdma;
	xdev_handle_t xdev;
	ssize_t ret;
	u32 nents;

	qdma = platform_get_drvdata(pdev);
	pr_info("%s: TID %d, q_num:%d, Offset: 0x%llx, write: %d", __func__,
		pid, q_num, paddr, write);
	xdev = xocl_get_xdev(pdev);

	queue = &qdma->queues[write][q_num];

	if (write) {
		cfg.direction = DMA_MEM_TO_DEV;
		cfg.dst_addr = paddr;
		dma_dir = DMA_TO_DEVICE;
	} else {
		cfg.direction = DMA_DEV_TO_MEM;
		cfg.src_addr = paddr;
		dma_dir = DMA_FROM_DEVICE;
	}

	pci_dev = XDEV(xocl_get_xdev(pdev))->pdev;

	nents = dma_map_sg(&pci_dev->dev, sgt->sgl, sgt->orig_nents, dma_dir);
	if (!nents) {
		xocl_err(&pdev->dev, "failed to map sg");
		return -EIO;
	}

	sgt->nents = nents;

	xocl_info(&pdev->dev, "%s: before dmaengine_slave_config(), nents: %d\n", __func__, nents);
	ret = dmaengine_slave_config(queue->chan, &cfg);
	if (ret) {
		xocl_err(&pdev->dev, "failed to config dma: %ld", ret);
		return ret;
	}

	xocl_info(&pdev->dev, "%s: before dmaengine_prep_slave_sg()\n", __func__);
	tx = dmaengine_prep_slave_sg(queue->chan, sgt->sgl, nents, cfg.direction, 0);
	if (!tx) {
		dev_err(&pdev->dev, "failed to prep slave sg");
		dma_unmap_sg(&pci_dev->dev, sgt->sgl, sgt->orig_nents, cfg.direction);
		return -EIO;
	}

	tx->callback = qdma_queue_req_complete;
	tx->callback_param = queue;

	xocl_info(&pdev->dev, "%s: before dmaengine_submit()\n", __func__);
	queue->dma_cookie = dmaengine_submit(tx);

	xocl_info(&pdev->dev, "%s: before dma_async_issue_pending()\n", __func__);
	dma_async_issue_pending(queue->chan);

	xocl_info(&pdev->dev, "%s: before wait_for_completion_timeout()\n", __func__);
	if (!wait_for_completion_timeout(&queue->req_compl,
					 msecs_to_jiffies(QDMA_REQ_TIMEOUT_MS))) {
		dev_err(&pdev->dev, "dma timeout");
		ret = -EIO;
	} else {
		ret = len;
		queue->total_trans_bytes += len;
	}
	xocl_info(&pdev->dev, "%s: before dma_unmap_sg()\n", __func__);
	dma_unmap_sg(&pci_dev->dev, sgt->sgl, sgt->orig_nents, cfg.direction);
	xocl_info(&pdev->dev, "%s: done\n", __func__);

	return ret;
}

static struct xocl_dma_funcs qdma_ops = {
	.ac_chan = acquire_queue,
	.rel_chan = release_queue,
	.get_chan_count = get_queue_count,
	.get_chan_stat = get_queue_stat,
	/* qdma */
	.migrate_bo = qdma_migrate_bo,
};

static struct amdmqdma_queue_info h2c_queue_info = {
	.dir = DMA_MEM_TO_DEV,
};

static struct amdmqdma_queue_info c2h_queue_info = {
	.dir = DMA_DEV_TO_MEM,
};

static void qdma_remove_dma_dev(struct xocl_qdma *qdma)
{

	if (!qdma) {
		pr_err("%s: qdma is NULL\n", __func__);
		return;
	}
	platform_device_unregister(qdma->dma_dev);
}

static int qdma_configure_dma_chans(struct xocl_qdma *qdma)
{
	struct mm_queue *queue;
	u32 write, qidx;
	int i, ret;

	for (i = 0; i < qdma->n_queues * 2; i++) {
		write = i / qdma->n_queues;
		qidx = i % qdma->n_queues;
		queue = &qdma->queues[write][qidx];
		queue->chan = dma_request_chan(&qdma->pdev->dev, queue->chan_name);
		if (IS_ERR(queue->chan)) {
			queue->chan = NULL;
			ret = PTR_ERR(queue->chan);
			pr_err("%s: failed in %s dma_request_chan(), err: %d\n",
				__func__, queue->chan_name, ret);
			return ret;
		}
		init_completion(&queue->req_compl);
	}

	sema_init(&qdma->queues_sem[0], qdma->n_queues);
	sema_init(&qdma->queues_sem[1], qdma->n_queues);
	/* Initialize bit mask to represent individual queues */
	qdma->queues_bitmap[0] = BIT(qdma->n_queues);
	qdma->queues_bitmap[0]--;
	qdma->queues_bitmap[1] = qdma->queues_bitmap[0];
	//qdma->queues_bitmap[0] = GENMASK_ULL(qdma->n_queues - 1, 0);
	//qdma->queues_bitmap[1] = qdma->queues_bitmap[0];
	pr_info("%s: queues_bitmap[0]: 0X%X, queues_bitmap[1]: 0X%X",
		__func__, qdma->queues_bitmap[0], qdma->queues_bitmap[1]);

	return 0;
}

static int qdma_create_dma_dev(struct xocl_qdma *qdma)
{
	struct resource res[RESOURSE_LEN] = { 0 };
	struct amdmqdma_platdata data;
	struct qdma_queue_conf *qconf;
	struct qdma_dev_conf *conf;
	struct dma_slave_map *map;
	struct pci_dev *pdev;
	int i, ret, nvec;

	pdev = XDEV(xocl_get_xdev(qdma->pdev))->pdev;
	if (!pdev)
		return -EINVAL;

	pr_info("%s: dev_name: %s", dev_name(&pdev->dev), __func__);

	nvec = pci_msix_vec_count(pdev);

	res[0].start = pci_resource_start(pdev, 0);
	res[0].end = pci_resource_end(pdev, 0);
	res[0].flags = IORESOURCE_MEM;
	res[0].parent = &pdev->resource[0];
#if 0
	res[1].start = pci_irq_vector(pdev, 0);
	res[1].end = res[1].start + nvec - 1;
	res[1].flags = IORESOURCE_IRQ;
#endif

	data.device_map = devm_kzalloc(&qdma->pdev->dev,
			sizeof(struct dma_slave_map) * qdma_max_queues * 2,
			GFP_KERNEL);
	data.device_map_cnt = qdma_max_queues * 2;

	for (i = 0; i < qdma_max_queues; i++) {
		map = &data.device_map[i];
		map->devname = dev_name(&qdma->pdev->dev);
		map->slave = devm_kasprintf(&qdma->pdev->dev, GFP_KERNEL, "h2c%d", i);
		if (!map->slave) {
			pr_err("%s: devm_kasprintf() failed for h2c%d\n", __func__, i);
			ret = -EINVAL;
			goto failed;
		}
		map->param = QDMA_FILTER_PARAM(&h2c_queue_info);

		map = &data.device_map[i + qdma_max_queues];
		map->devname = dev_name(&qdma->pdev->dev);
		map->slave = devm_kasprintf(&qdma->pdev->dev, GFP_KERNEL, "c2h%d", i);
		if (!map->slave) {
			pr_err("%s: devm_kasprintf() failed for c2h%d\n", __func__, i);
			ret = -EINVAL;
			goto failed;
		}
		map->param = QDMA_FILTER_PARAM(&c2h_queue_info);
	}

	data.max_dma_queues = qdma_max_queues;

	conf = &(data.dev_conf);
	memset(conf, 0, sizeof(*conf));
	conf->pdev = pdev;
	conf->master_pf = 1;
	conf->qsets_base = QDMA_QSETS_BASE;
	conf->qsets_max = QDMA_QSETS_MAX;
	conf->bar_num_user = -1;
	conf->bar_num_bypass = -1;
	conf->qdma_drv_mode = qdma_interrupt_mode;

	conf->uld = (unsigned long)qdma;
	strncpy(data.mod_name, XOCL_MODULE_NAME, sizeof(XOCL_MODULE_NAME));

	memcpy(&data.qconf[0], &qdma->qconf[0], qdma_max_queues * sizeof(struct qdma_queue_conf));
	memcpy(&data.qconf[1], &qdma->qconf[1], qdma_max_queues * sizeof(struct qdma_queue_conf));


#if 1
	pr_info("%s: before platform_device_register_resndata()\n", __func__);
	qdma->dma_dev = platform_device_register_resndata(&qdma->pdev->dev,
			"amdmqdma", PLATFORM_DEVID_AUTO, res, RESOURSE_LEN, &data, sizeof(data));
	if (!qdma->dma_dev) {
		pr_err("%s: failed to alloc dma device", __func__);
		return -ENOMEM;
	}
#else
	qdma->dma_dev = platform_device_alloc("amdmqdma", PLATFORM_DEVID_AUTO);
	if (!qdma->dma_dev) {
		xocl_err(&qdma->pdev->dev, "failed to alloc dma device");
		return -ENOMEM;
	}

	pr_err("+++%s: before platform_device_add_resources()\n", __func__);
	ret = platform_device_add_resources(qdma->dma_dev, res, 2);
	if (ret) {
		xocl_err(&qdma->pdev->dev, "failed to add resource: %d", ret);
		goto failed;
	}

	pr_err("+++%s: before platform_device_add_data()\n", __func__);
	ret = platform_device_add_data(qdma->dma_dev, &data, sizeof(data));
	if (ret) {
		xocl_err(&qdma->pdev->dev, "failed to add data: %d", ret);
		goto failed;
	}

	pr_err("+++%s: before platform_device_add()\n", __func__);
	ret = platform_device_add(qdma->dma_dev);
	if (ret) {
		xocl_err(&qdma->pdev->dev, "failed to add qdma dev: %d", ret);
		goto failed;
	}
#endif
	pr_info("%s: done, successfully registered and received dma handle\n", __func__);
	return 0;
failed:
	if (qdma->dma_dev)
		platform_device_put(qdma->dma_dev);

	return ret;
}

static void qdma_pci_enable_relaxed_ordering(struct pci_dev *pdev)
{
	pcie_capability_set_word(pdev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_RELAX_EN);
}

static void pci_disable_relaxed_ordering(struct pci_dev *pdev)
{
	pcie_capability_clear_word(pdev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_RELAX_EN);
}

static void qdma_pci_enable_extended_tag(struct pci_dev *pdev)
{
	pcie_capability_set_word(pdev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_EXT_TAG);
}

static void pci_disable_extended_tag(struct pci_dev *pdev)
{
	pcie_capability_clear_word(pdev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_EXT_TAG);
}

static int qdma_pci_dma_mask_set(struct pci_dev *pdev)
{
	/** 64-bit addressing capability for XDMA? */
	if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(64))) {
		/** use 64-bit DMA for descriptors */
		dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
		/** use 64-bit DMA, 32-bit for consistent */
	} else if (!dma_set_mask(&pdev->dev, DMA_BIT_MASK(32))) {
		dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
		/** use 32-bit DMA */
		dev_info(&pdev->dev, "Using a 32-bit DMA mask.\n");
	} else {
		/** use 32-bit DMA */
		dev_info(&pdev->dev, "No suitable DMA possible.\n");
		return -EINVAL;
	}

	return 0;
}

static int qdma_config_pci(struct pci_dev *pdev)
{
	int ret = 0;

	/* enable relaxed ordering */
	qdma_pci_enable_relaxed_ordering(pdev);

	/* enable extended tag */
	qdma_pci_enable_extended_tag(pdev);

	/* enable bus master capability */
	pci_set_master(pdev);

	ret = qdma_pci_dma_mask_set(pdev);
	if (ret) {
		pr_err("Failed to set the dma mask");
		return ret;
	}

	if (pcie_get_readrq(pdev) < 512)
		pcie_set_readrq(pdev, 512);

	return ret;
}

static int qdma_probe(struct platform_device *pdev)
{
	struct xocl_qdma *qdma = NULL;
	xdev_handle_t xdev;
	int ret = 0;

	xdev = xocl_get_xdev(pdev);
	if (!xdev)
		return -ENOMEM;

	qdma = devm_kzalloc(&pdev->dev, sizeof(*qdma), GFP_KERNEL);
	if (!qdma) {
		xocl_err(&pdev->dev, "alloc qdma dev failed");
		ret = -ENOMEM;
		goto failed;
	}

	qdma->pdev = pdev;
	platform_set_drvdata(pdev, qdma);

	ret = qdma_config_pci(XDEV(xdev)->pdev);
	if (ret) {
		xocl_err(&pdev->dev, "failed to config pci %d", ret);
		goto failed;
	}

	ret = alloc_queues(qdma, qdma_max_queues);
	if (ret) {
		xocl_err(&pdev->dev, "Set max queues failed");
		goto failed;
	}

	pr_info("%s: before qdma_create_dma_dev()\n", __func__);
	ret = qdma_create_dma_dev(qdma);
	if (ret)
		goto failed;

	pr_info("%s: before qdma_configure_dma_chans()\n", __func__);
	ret = qdma_configure_dma_chans(qdma);
	if (ret) {
		pr_err("%s: qdma_configure_dma_chans failed, err: %d\n", __func__, ret);
		if (!skip_dma_chan_err)
			goto failed;
	}

	pr_info("%s: done\n", __func__);
	return 0;

failed:
	if (qdma) {
		qdma_free_dma_chans(qdma);
		qdma_remove_dma_dev(qdma);
		free_queues(qdma->pdev);
		devm_kfree(&pdev->dev, qdma);
	}

	platform_set_drvdata(pdev, NULL);

	return ret;
}

static int qdma_remove(struct platform_device *pdev)
{
	struct xocl_qdma *qdma = platform_get_drvdata(pdev);

	pr_err("[Debug]%s: %d\n", __func__, __LINE__);

	if (!qdma) {
		pr_err("%s: qdma driver data is NULL", __func__);
		return -EINVAL;
	}

	pr_err("[Debug]%s: %d\n", __func__, __LINE__);
	free_queues(pdev);

#if 0
	xocl_err(&pdev->dev, "[Debug]%s: %d\n", __func__, __LINE__);
	qdma_remove_dma_dev(qdma);
#endif

	pr_err("[Debug]%s: %d\n", __func__, __LINE__);
	platform_set_drvdata(pdev, NULL);
	return 0;
}

struct xocl_drv_private qdma_priv = {
	.ops = &qdma_ops,
};

static struct platform_device_id qdma_id_table[] = {
	{ XOCL_DEVNAME(XOCL_QDMA), (kernel_ulong_t)&qdma_priv },
	{ },
};

static struct platform_driver	qdma_driver = {
	.probe		= qdma_probe,
	.remove		= qdma_remove,
	.driver		= {
		.name = XOCL_DEVNAME(XOCL_QDMA),
	},
	.id_table	= qdma_id_table,
};

int __init xocl_init_qdma(void)
{
	return platform_driver_register(&qdma_driver);
}

void xocl_fini_qdma(void)
{
	platform_driver_unregister(&qdma_driver);
}
