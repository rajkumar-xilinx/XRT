/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * Copyright (C) 2021 Xilinx, Inc. All rights reserved.
 *
 * Author(s):
 *        Rajkumar Rampelli <rajkumar@xilinx.com>
 *
 * This file is dual-licensed; you may select either the GNU General Public
 * License version 2 or Apache License, Version 2.0.
 */
#include "zocl_ert.h"
#include "zocl_util.h"
 #include <linux/ktime.h>

#define irq_err(pdev, fmt, args...)  \
	zocl_err(&pdev->dev, fmt"\n", ##args)
#define irq_info(pdev, fmt, args...)  \
	zocl_info(&pdev->dev, fmt"\n", ##args)
#define irq_dbg(pdev, fmt, args...)  \
	zocl_info(&pdev->dev, fmt"\n", ##args)
//	zocl_dbg(&pdev->dev, fmt"\n", ##args)

struct ert_user_irq *euirq_global;

/* IPI registers offset */
#define IPI_TRIG_OFFSET 0x0  /* IPI trigger reg offset */
#define IPI_OBS_OFFSET  0x4  /* IPI observation reg offset */
#define IPI_ISR_OFFSET  0x10 /* IPI interrupt status reg offset */
#define IPI_IMR_OFFSET  0x14 /* IPI interrupt mask reg offset */
#define IPI_IER_OFFSET  0x18 /* IPI interrupt enable reg offset */
#define IPI_IDR_OFFSET  0x1C /* IPI interrup disable reg offset */

#define IPI_MASK        0x100 /* IPI mask for kick from RPU. */

#define NS_PER_SEC 1000000000

/* Shared memory offset */
#define SHM_DEMO_CNTRL_OFFSET    0x0
#define DEMO_STATUS_IDLE         0x0
#define DEMO_STATUS_START        0x1 /* Status value to indicate demo start */

#define ITERATIONS 1000

static void measure_ipi_latency(struct ert_user_irq *sirq);
ktime_t start[1000];
ktime_t end[1000];
u64 time_ns[1000];

static const struct of_device_id irq_of_match[] = {
	{ .compatible = "xlnx,ipi_uio",
	},
	{ /* end of table */ },
};

MODULE_DEVICE_TABLE(of, irq_of_match);

void ert_user_irq_enable(void)
{
	printk("%s called\n", __func__);
	/* Enable IPI interrupt */
	iowrite32(IPI_MASK, euirq_global->base + IPI_IER_OFFSET);
	euirq_global->ipi_enable = true;
}

void ert_user_irq_disable(void)
{
	printk("%s called\n", __func__);
	/* Disable IPI interrupt */
	iowrite32(IPI_MASK, euirq_global->base + IPI_IDR_OFFSET);
	/* clear old IPI interrupt */
	iowrite32(IPI_MASK, euirq_global->base + IPI_ISR_OFFSET);
	euirq_global->ipi_enable = false;
}

static ssize_t ipi_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct ert_user_irq *sirq = platform_get_drvdata(pdev);
	u8 val;

	if (!sirq)
		return 0;

	if (kstrtou8(buf, 16, &val) == -EINVAL)
		return -EINVAL;

	write_lock(&sirq->att_rwlock);

	if (val)
		ert_user_irq_enable();
	else
		ert_user_irq_disable();

	write_unlock(&sirq->att_rwlock);

	return count;
}

static ssize_t ipi_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct ert_user_irq *sirq = platform_get_drvdata(pdev);
	ssize_t size = 0;

	if (!sirq)
		return 0;

	read_lock(&sirq->att_rwlock);
	size += sprintf(buf, "%d\n", sirq->ipi_enable);
	read_unlock(&sirq->att_rwlock);

	return size;
}
static DEVICE_ATTR_RW(ipi_enable);

static ssize_t ipi_latency_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct ert_user_irq *sirq = platform_get_drvdata(pdev);
	u8 val;

	if (!sirq)
		return 0;

	if (kstrtou8(buf, 16, &val) == -EINVAL)
		return -EINVAL;

	printk("+++%s val: %d\n", __func__, val);
	write_lock(&sirq->att_rwlock);
	if (val == 1)
		measure_ipi_latency(sirq);
	write_unlock(&sirq->att_rwlock);

	return count;
}

static DEVICE_ATTR_WO(ipi_latency);

static struct attribute *eu_irq_attrs[] = {
	&dev_attr_ipi_latency.attr,
	&dev_attr_ipi_enable.attr,
	NULL,
};

static struct attribute_group eu_irq_attr_group = {
	.attrs = eu_irq_attrs,
};

static irqreturn_t ert_user_isr(int irq, void *arg)
{
	struct ert_user_irq *sirq = arg;
	u32 val;
	static int counter = 0;

	end[counter] = ktime_get();
	time_ns[counter] = ktime_to_ns(ktime_sub(end[counter], start[counter]));
	val = ioread32(sirq->base + IPI_ISR_OFFSET);
//	printk("+++%d: ipi_irq: %d, irq_rcvd: %d, val: 0x%x, ipi_mask: 0x%x, time_ns: %lld\n", counter, sirq->ipi_irq, irq, val, sirq->ipi_mask, time_ns[counter]);
	counter++;
	if (val & sirq->ipi_mask) {
		/* stop RPU -> APU timer */
		//stop_timer(ch->ttc_io, TTC_CNT_RPU_TO_APU);
		iowrite32(sirq->ipi_mask, sirq->base + IPI_ISR_OFFSET);
//		atomic_set(&sirq->remote_nkicked, 0);
		up(&sirq->sem);
		return IRQ_HANDLED;
	}
	printk("++++IRQ_NONE+++\n");
	return IRQ_NONE;
}

/**
 *  * @brief measure_ipi_latency() - Measure latency of IPI
 *  *Repeatedly kick IPI to notify the remote and then wait for IPI kick
 *    from RPU and measure the latency. Similarly, measure the latency
 *    from RPU to APU. Each iteration, record this latency and after the
 *    loop has finished, report the total latency in nanseconds.
 *    Notes:
 *         - RPU will repeatedly wait for IPI from APU until APU
 *           notifies remote demo has finished by setting the value in the
 *           shared memory.
 */
static void measure_ipi_latency(struct ert_user_irq *sirq)
{
	uint32_t apu_to_rpu_sum = 0, rpu_to_apu_sum = 0;
	int i;

	printk("Starting IPI latency task\n");
	/* write to shared memory to indicate demo has started */
/*	iowrite32(DEMO_STATUS_START, sirq->shm_base + SHM_DEMO_CNTRL_OFFSET);
	printk("+++shm ctrl_offset: 0x%x, val set: 0x%x, read_off: 0x%x\n",
			SHM_DEMO_CNTRL_OFFSET,
			DEMO_STATUS_START,
			ioread32(sirq->shm_base + SHM_DEMO_CNTRL_OFFSET));
*/
	for ( i = 1; i <= ITERATIONS; i++) {
		/* Reset TTC counter */
//		reset_timer(ch->ttc_io, TTC_CNT_APU_TO_RPU);
		start[i-1] = ktime_get();
		/* Kick IPI to notify the remote */
		iowrite32(IPI_MASK, sirq->base + IPI_TRIG_OFFSET);
		/* irq handler stops timer for
		 * rpu->apu irq */
//		printk("%s in sleep mode\n", __func__);
		if (down_interruptible(&sirq->sem))
			printk("error in down_interruptible: %d\n", -ERESTARTSYS);

//		apu_to_rpu_sum += read_timer(ch->ttc_io, TTC_CNT_APU_TO_RPU);
//		rpu_to_apu_sum += read_timer(ch->ttc_io, TTC_CNT_RPU_TO_APU);
	}

	/* write to shared memory to indicate demo has finished */
//	iowrite32(0, sirq->shm_base + SHM_DEMO_CNTRL_OFFSET);
	/* Kick IPI to notify the remote */
	iowrite32(IPI_MASK, sirq->base + IPI_TRIG_OFFSET);

	/* report avg latencies */
	u64 sum = 0, avg_ms = 0, temp;
	printk("IPI latency result with %i iterations:\n", ITERATIONS);
	for (i = 0; i < ITERATIONS; i++) {
		temp = ktime_to_ns(ktime_sub(end[i], start[i]));
		if (temp != time_ns[i])
			printk("+++i: %d, not matched.., temp: %llu, time_ns: %llu\n",
				   i, temp, time_ns[i]);
		else
			sum += time_ns[i];
	}
	avg_ms = sum / 1000000;
	avg_ms = avg_ms / ITERATIONS;
	printk("APU to APU latency:\n total time: %llu, avg_ns: %llu ns, avg_ms: %llu  \n", sum, sum / ITERATIONS, avg_ms);
//	printk("APU to RPU average latency: %u ns \n", apu_to_rpu_sum / ITERATIONS * NS_PER_SEC / TTC_CLK_FREQ_HZ );
//	printk("RPU to APU average latency: %u ns \n", rpu_to_apu_sum / ITERATIONS * NS_PER_SEC / TTC_CLK_FREQ_HZ );
	printk("Finished IPI latency task\n");
}

static int ert_user_irq_probe(struct platform_device *pdev)
{
	const struct of_device_id *id;
	struct drm_zocl_dev *zdev =
		platform_get_drvdata(to_platform_device(pdev->dev.parent));
	struct resource *res;
	struct ert_user_irq *sirq;
	int ret = 0;

	sirq = vzalloc(sizeof(struct ert_user_irq));
	if (!sirq)
		return -ENOMEM;

	sirq->pdev = pdev;
	if (!zdev)
		irq_info(pdev, "+++zdev is NULL\n");
	else
		irq_info(pdev, "+++zdev is NOT NULL\n");
//	zdev->euirq = sirq;
	euirq_global = sirq;
	id = of_match_node(irq_of_match, pdev->dev.of_node);
	irq_info(pdev, "Probing for %s", id->compatible);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	sirq->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(sirq->base)) {
		ret = PTR_ERR(sirq->base);
		irq_err(pdev, "Failed to map ipi_uio registers: %0lx", ret);
		return ret;
	}
//	sirq->shm_base = devm_ioremap(&pdev->dev, 0x3ed80000, 0x10);
	sirq->ipi_irq = platform_get_irq(pdev, 0);
	irq_info(pdev, "+++IPI IO start %lx, end %lx, ipi_irq: %d",
	      (unsigned long)res->start, (unsigned long)res->end, sirq->ipi_irq);

	/* disable IPI interrupt */
	iowrite32(IPI_MASK, sirq->base + IPI_IDR_OFFSET);
	/* clear old IPI interrupt */
	iowrite32(IPI_MASK, sirq->base + IPI_ISR_OFFSET);
	/* initialize remote_nkicked */
    atomic_set(&sirq->remote_nkicked, 1);
	sirq->ipi_mask = IPI_MASK;

	ret = request_irq(sirq->ipi_irq, ert_user_isr, 0, "ert_user_isr", sirq);
	if (ret) {
		irq_err(pdev, "Failed to request_irq, ret: %d\n", ret);
	}
	/* Enable IPI interrupt */
	iowrite32(IPI_MASK, sirq->base + IPI_IER_OFFSET);

	sema_init(&sirq->sem, 1);
	rwlock_init(&sirq->att_rwlock);

//	measure_ipi_latency(sirq);
	platform_set_drvdata(pdev, sirq);

	ret = sysfs_create_group(&pdev->dev.kobj, &eu_irq_attr_group);
	if (ret)
		irq_err(pdev, "Create zocl attrs failed: %d\n", ret);

	return ret;
}

unsigned int ert_user_irq_info(void)//struct platform_device *pdev)
{
//	struct ert_user_irq *euirq = platform_get_drvdata(pdev);

	printk("%s called\n", __func__);
//	irq_dbg(pdev, "ert_user_irq info:\n");
//	irq_info(pdev, "+++IPI IRQ %d\n", euirq_global->ipi_irq);//euirq->ipi_irq);
	printk( "+++IPI IRQ %d\n", euirq_global->ipi_irq);//euirq->ipi_irq);
	return euirq_global->ipi_irq;
}

static int ert_user_irq_remove(struct platform_device *pdev)
{
	struct ert_user_irq *euirq = platform_get_drvdata(pdev);
//	struct drm_zocl_dev *zdev =
//		platform_get_drvdata(to_platform_device(pdev->dev.parent));
	irq_dbg(pdev, "Release resource");
//	if (zdev->euirq->ipi_irq)
//		free_irq(zdev->euirq->ipi_irq, zdev->euirq);
	if (euirq->ipi_irq)
		free_irq(euirq->ipi_irq, euirq);
	sysfs_remove_group(&pdev->dev.kobj, &eu_irq_attr_group);
	return 0;
}

static struct platform_device_id irq_id_table[] = {
	{"xlnx,ipi_uio", 0 },
	{.name = "xlnx,ipi_uio"},
	{ },
};

struct platform_driver ert_user_irq_driver = {
	.driver = {
		.name = "xlnx,ipi_uio",
		.of_match_table = irq_of_match,
		.owner  = THIS_MODULE,
	},
	.probe  = ert_user_irq_probe,
	.remove = ert_user_irq_remove,
	.id_table	= irq_id_table,
};

#if 1
int ert_user_irq_init(struct drm_zocl_dev *zdev)
{
	int ret;

	printk("+++%s called...\n", __func__);
	ret = platform_driver_register(&ert_user_irq_driver);
	printk("+++%s driver reg ret: %d...\n", __func__, ret);
	if (ret < 0)
		goto err;

	return 0;
err:
	return ret;
}

void ert_user_irq_fini(struct drm_zocl_dev *zdev)
{
	printk("+++%s called...\n", __func__);
	platform_driver_unregister(&ert_user_irq_driver);
}
#endif
