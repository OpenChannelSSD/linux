#include <linux/lightnvm.h>
#include <linux/sysfs.h>

#include "nvm.h"

static ssize_t nvm_attr_free_blocks_show(struct nvm_dev *nvm, char *buf)
{
	char *buf_start = buf;
	struct nvm_stor *stor = nvm->stor;
	struct nvm_pool *pool;
	unsigned int i;

	nvm_for_each_pool(stor, pool, i)
		buf += sprintf(buf, "%8u\t%u\n", i, pool->nr_free_blocks);

	return buf - buf_start;
}

static ssize_t nvm_attr_show(struct device *dev, char *page,
			      ssize_t (*fn)(struct nvm_dev *, char *))
{
	struct gendisk *disk = dev_to_disk(dev);
	struct nvm_dev *nvm = disk->private_data;

	return fn(nvm, page);
}

#define NVM_ATTR_RO(_name)						\
static ssize_t nvm_attr_##_name##_show(struct nvm_dev *, char *);	\
static ssize_t nvm_attr_do_show_##_name(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	return nvm_attr_show(d, b, nvm_attr_##_name##_show);		\
}									\
static struct device_attribute nvm_attr_##_name =			\
	__ATTR(_name, S_IRUGO, nvm_attr_do_show_##_name, NULL)

NVM_ATTR_RO(free_blocks);

static struct attribute *nvm_attrs[] = {
	&nvm_attr_free_blocks.attr,
	NULL,
};

static struct attribute_group nvm_attribute_group = {
	.name = "nvm",
	.attrs = nvm_attrs,
};

void nvm_remove_sysfs(struct device *dev)
{
	sysfs_remove_group(&dev->kobj, &nvm_attribute_group);
}
EXPORT_SYMBOL_GPL(nvm_remove_sysfs);

int nvm_add_sysfs(struct device *dev)
{
	int ret;

	ret = sysfs_create_group(&dev->kobj, &nvm_attribute_group);
	if (ret)
		return ret;

	kobject_uevent(&dev->kobj, KOBJ_CHANGE);

	return 0;
}
EXPORT_SYMBOL_GPL(nvm_add_sysfs);
