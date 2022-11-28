/*
 * A GEM style device manager for PCIe based OpenCL accelerators.
 *
 * Copyright (C) 2022, Advanced Micro Devices, Inc.
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
#include <linux/platform_data/amd_mqdma.h>
#include "../xocl_drv.h"
#include "../xocl_drm.h"
#include "qdma_ioctl.h"

#define QDMA_FILTER_PARAM(chan_info) ((void *)(chan_info))

#define	MM_QUEUE_LEN		8
#define	MM_EBUF_LEN		256

#define MM_DEFAULT_RINGSZ_IDX	0

#define	MINOR_NAME_MASK		0xffffffff

#define QDMA_MAX_INTR		16
#define QDMA_USER_INTR_MASK	0xff

#define QDMA_QSETS_MAX		256
#define QDMA_QSETS_BASE		0

#define QDMA_REQ_TIMEOUT_MS	10000

/* Module Parameters */
unsigned int qdma_max_channel = 8;
module_param(qdma_max_channel, uint, 0644);
MODULE_PARM_DESC(qdma_max_channel, "Set number of channels for qdma, default is 8");

struct mm_channel {
	struct device		dev;
	struct dma_chan		*chan;
	void			*dma_hdl;
	unsigned long		queue;
	uint64_t		total_trans_bytes;
	dma_cookie_t		dma_cookie;
};

struct xocl_qdma {
	struct platform_device	*pdev;
	struct platform_device	*dma_dev;
	struct semaphore	channel_sem[2]; /* Semaphore, one for each direction */
	struct mm_channel	*chans[2];
	u32			channel; /* Number of bidirectional channels */
	/*
	 * Channel usage bitmasks, one for each direction
	 * bit 1 indicates channel is free, bit 0 indicates channel is free
	 */
	volatile unsigned long	channel_bitmap[2];
	u16			instance;
};

static u32 get_channel_count(struct platform_device *pdev);
static u64 get_channel_stat(struct platform_device *pdev, u32 channel, u32 write);

static void device_release(struct device *dev)
{
	xocl_err(dev, "dummy device release callback");
}

static void release_channel(struct platform_device *pdev, u32 dir, u32 channel)
{
	struct xocl_qdma *qdma;

	xocl_err(&pdev->dev, "[Debug]%s: %d, dir: %d, chan: %d\n", __func__, __LINE__, dir, channel);

	qdma = platform_get_drvdata(pdev);
	set_bit(channel, &qdma->channel_bitmap[dir]);
	up(&qdma->channel_sem[dir]);

	xocl_err(&pdev->dev, "[Debug]%s: %d, dir: %d, chan: %d\n", __func__, __LINE__, dir, channel);
}

static int acquire_channel(struct platform_device *pdev, u32 dir)
{
	struct xocl_qdma *qdma;
	int channel = 0;
	int result = 0;
	u32 write;

	qdma = platform_get_drvdata(pdev);

	if (down_killable(&qdma->channel_sem[dir])) {
		channel = -ERESTARTSYS;
		goto out;
	}

	for (channel = 0; channel < qdma->channel; channel++) {
		result = test_and_clear_bit(channel,
			&qdma->channel_bitmap[dir]);
		if (result)
			break;
        }
        if (!result) {
		// How is this possible?
		up(&qdma->channel_sem[dir]);
		channel = -EIO;
		goto out;
	}

	xocl_err(&pdev->dev, "[Debug]%s: %d, dir: %d, chan: %d\n", __func__, __LINE__, dir, channel);
	write = dir ? 1 : 0;
out:
	return channel;
}

static u32 get_channel_count(struct platform_device *pdev)
{
	struct xocl_qdma *qdma = platform_get_drvdata(pdev);

	xocl_err(&pdev->dev, "[Debug]%s: %d\n", __func__, __LINE__);
	return qdma ? qdma->channel : 0;
}

static u64 get_channel_stat(struct platform_device *pdev, u32 channel,
	u32 write)
{
	struct xocl_qdma *qdma = platform_get_drvdata(pdev);

	xocl_err(&pdev->dev, "[Debug]%s: %d\n", __func__, __LINE__);

	return qdma ? qdma->chans[write][channel].total_trans_bytes : 0;
}

static u64 get_str_stat(struct platform_device *pdev, u32 q_idx)
{
	xocl_err(&pdev->dev, "[Debug]%s: %d\n", __func__, __LINE__);
	return 0;
}

static struct xocl_dma_funcs qdma_ops = {
	.ac_chan = acquire_channel,
	.rel_chan = release_channel,
	.get_chan_count = get_channel_count,
	.get_chan_stat = get_channel_stat,
	/* qdma */
	.get_str_stat = get_str_stat,
};

static struct amdmqdma_chan_info h2c_chan_info = {
	.dir = DMA_MEM_TO_DEV,
};

static struct amdmqdma_chan_info c2h_chan_info = {
	.dir = DMA_DEV_TO_MEM,
};

static void qdma_remove_dma_dev(struct xocl_qdma *qdma)
{
	struct pci_dev *pci_dev;

	pci_dev = XDEV(xocl_get_xdev(qdma->pdev))->pdev;
	platform_device_unregister(qdma->dma_dev);
	pci_free_irq_vectors(pci_dev);
}

static int qdma_create_dma_dev(struct xocl_qdma *qdma)
{
	struct amdmqdma_platdata data;
	struct resource res[2] = { 0 };
	struct dma_slave_map *map;
	struct pci_dev *pdev;
	int i, ret, nvec;

	qdma->dma_dev = platform_device_alloc("amdmqdma", PLATFORM_DEVID_AUTO);
	if (!qdma->dma_dev) {
		xocl_err(&qdma->pdev->dev, "failed to alloc dma device");
		return -ENOMEM;
	}

	pdev = XDEV(xocl_get_xdev(qdma->pdev))->pdev;

	if (!pdev)
		return -EINVAL;
	nvec = pci_msix_vec_count(pdev);

	res[0].start = pci_resource_start(pdev, 0);
	res[0].end = pci_resource_end(pdev, 0);
	res[0].flags = IORESOURCE_MEM;
	res[0].parent = &pdev->resource[0];
	res[1].start = pci_irq_vector(pdev, 0);
	res[1].end = res[1].start + nvec - 1;
	res[1].flags = IORESOURCE_IRQ;
	ret = platform_device_add_resources(qdma->dma_dev, res, 2);
	if (ret) {
		xocl_err(&qdma->pdev->dev, "failed to add resource: %d", ret);
		goto failed;
	}

	data.device_map = devm_kzalloc(&qdma->pdev->dev,
			sizeof(struct dma_slave_map) * qdma_max_channel * 2,
			GFP_KERNEL);
	data.device_map_cnt = qdma_max_channel * 2;

	for (i = 0; i < qdma_max_channel; i++) {
		map = &data.device_map[i];
		map->devname = dev_name(&qdma->pdev->dev);
		map->slave = devm_kasprintf(&qdma->pdev->dev, GFP_KERNEL, "h2c%d", i);
		if (!map->slave)
			goto failed;
		map->param = QDMA_FILTER_PARAM(&h2c_chan_info);
		map = &data.device_map[i + qdma_max_channel];
		map->devname = dev_name(&qdma->pdev->dev);
		map->slave = devm_kasprintf(&qdma->pdev->dev, GFP_KERNEL, "c2h%d", i);
		if (!map->slave)
			goto failed;
		map->param = QDMA_FILTER_PARAM(&c2h_chan_info);
	}

	data.max_dma_channels = qdma_max_channel;

	ret = platform_device_add_data(qdma->dma_dev, &data, sizeof(data));
	if (ret) {
		xocl_err(&qdma->pdev->dev, "failed to add data: %d", ret);
		goto failed;
	}

	ret = platform_device_add(qdma->dma_dev);
	if (ret) {
		xocl_err(&qdma->pdev->dev, "failed to add qdma dev: %d", ret);
		goto failed;
	}

	return 0;
failed:
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

	if (!pdev)
		return -ENOMEM;

	xdev = xocl_get_xdev(pdev);

	if (!xdev)
		return -ENOMEM;
	qdma = devm_kzalloc(&pdev->dev, sizeof(*qdma), GFP_KERNEL);
	if (!qdma) {
		xocl_err(&pdev->dev, "alloc mm dev failed");
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

	ret = qdma_create_dma_dev(qdma);
	if (ret)
		goto failed;

	return 0;

failed:
	if (qdma) {
		qdma_remove_dma_dev(qdma);
		devm_kfree(&pdev->dev, qdma);
	}

	platform_set_drvdata(pdev, NULL);

	return ret;
}

static int qdma_remove(struct platform_device *pdev)
{
	struct xocl_qdma *qdma= platform_get_drvdata(pdev);
	xdev_handle_t xdev;
	void *hdl;

	xocl_err(&pdev->dev, "[Debug]%s: %d\n", __func__, __LINE__);

	if (!qdma) {
		xocl_err(&pdev->dev, "driver data is NULL");
		return -EINVAL;
	}

	xdev = xocl_get_xdev(pdev);

	platform_set_drvdata(pdev, NULL);

	xocl_err(&pdev->dev, "[Debug]%s: %d\n", __func__, __LINE__);
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
