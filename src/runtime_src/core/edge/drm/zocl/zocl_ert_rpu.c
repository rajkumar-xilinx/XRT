/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * A GEM style device manager for PCIe based OpenCL accelerators.
 *
 * Copyright (C) 2021 Xilinx, Inc. All rights reserved.
 *
 * Authors:
 *         Rajkumar Rampelli <rajkumar@xilinx.com>
 *
 * This file is dual-licensed; you may select either the GNU General Public
 * License version 2 or Apache License, Version 2.0.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include "zocl_drv.h"

//#define MSG		"hello world!"
char *input;

static int count = 5;
module_param(count, int, 0644);

struct instance_data {
	int rx_count;
};

static int rpmsg_sample_cb(struct rpmsg_device *rpdev, void *data, int len,
						void *priv, u32 src)
{
	int ret;
	struct instance_data *idata = dev_get_drvdata(&rpdev->dev);

	dev_info(&rpdev->dev, "Received msg from RPU, count: %d (src: 0x%x), data: %s\n",
		 ++idata->rx_count, src, (char*)data);

	print_hex_dump_debug(__func__, DUMP_PREFIX_NONE, 16, 1, data, len,
			     true);

	/* samples should not live forever */
	if (idata->rx_count >= count) {
		dev_info(&rpdev->dev, "goodbye from zocl!\n");
		return 0;
	}

	/* send a new message now */
	input = (char*)kmalloc(20 * sizeof(char), GFP_KERNEL);
//	dev_err(&rpdev->dev, "input_addr: %p, 0x%x\n", input, input);
	strcpy(input, "Hello");
	sprintf(input, "%s%d", input, idata->rx_count);
	dev_info(&rpdev->dev, "Sending message %s from zocl\n", input);
	ret = rpmsg_send(rpdev->ept, input, strlen(input));
//	ret = rpmsg_send(rpdev->ept, MSG, strlen(MSG));
	if (ret)
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);
	kfree(input);

	return 0;
}

static int rpmsg_sample_probe(struct rpmsg_device *rpdev)
{
	int ret;
	struct instance_data *idata;

	dev_info(&rpdev->dev, "new channel: 0x%x -> 0x%x!\n",
					rpdev->src, rpdev->dst);

	idata = devm_kzalloc(&rpdev->dev, sizeof(*idata), GFP_KERNEL);
	if (!idata)
		return -ENOMEM;

	dev_set_drvdata(&rpdev->dev, idata);

	/* send a message to our remote processor */
	input = (char*)kmalloc(20 * sizeof(char), GFP_KERNEL);
//	dev_err(&rpdev->dev, "input_addr: %p, 0x%x\n", input, input);
	strcpy(input, "Hello");
	dev_info(&rpdev->dev, "Sending message %s from zocl\n", input);
	ret = rpmsg_send(rpdev->ept, input, strlen(input));
	if (ret)
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);
	kfree(input);

	return 0;
}

static void rpmsg_sample_remove(struct rpmsg_device *rpdev)
{
	dev_info(&rpdev->dev, "rpmsg sample client driver is removed\n");
}
static struct rpmsg_device_id rpmsg_driver_sample_id_table[] = {
	{ .name	= "rpmsg-openamp-demo-channel" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_driver_sample_id_table);

static struct rpmsg_driver rpmsg_sample_client = {
	.drv.name	= KBUILD_MODNAME,
	.id_table	= rpmsg_driver_sample_id_table,
	.probe		= rpmsg_sample_probe,
	.callback	= rpmsg_sample_cb,
	.remove		= rpmsg_sample_remove,
};

int zocl_init_ert_rpu(struct device *dev)
{
	return register_rpmsg_driver(&rpmsg_sample_client);
}

void zocl_fini_ert_rpu(struct device *dev)
{
	unregister_rpmsg_driver(&rpmsg_sample_client);
}
