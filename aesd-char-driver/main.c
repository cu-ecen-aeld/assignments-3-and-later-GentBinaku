/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 * @author Gent Binaku @copyright Copyright (c) 2019
 */
#include "aesd-circular-buffer.h"
#include "aesd_ioctl.h"
#include "aesdchar.h"
#include <asm-generic/errno-base.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/init.h>
#include <linux/kernel.h> // min()
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h> // kmalloc, krealloc, kfree
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h> // copy_to_user and copy_from_user

int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Gent Binaku");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static size_t aesd_size(struct aesd_circular_buffer *buffer) {
  struct aesd_buffer_entry *entry = NULL;
  uint8_t index = 0;
  size_t size = 0;
  AESD_CIRCULAR_BUFFER_FOREACH(entry, buffer, index) { size += entry->size; }
  return size;
}

int aesd_open(struct inode *inode, struct file *filp) {
  struct aesd_dev *dev = NULL;

  PDEBUG("open");

  if (!inode || !filp)
    return -EFAULT;

  dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
  filp->private_data = dev;

  return 0;
}

int aesd_release(struct inode *inode, struct file *filp) {
  PDEBUG("release");
  return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos) {
  ssize_t retval = 0;
  struct aesd_dev *dev;
  struct aesd_buffer_entry *entry;
  size_t entry_offset = 0;
  ssize_t len = 0;

  if (!filp || !buf || !f_pos)
    return -EFAULT;

  PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

  dev = (struct aesd_dev *)filp->private_data;
  if (!dev)
    return -EFAULT;

  if (mutex_lock_interruptible(&dev->aesd_mutex) != 0)
    return -ERESTARTSYS;

  entry = aesd_circular_buffer_find_entry_offset_for_fpos(
      &dev->aesd_buffer, (size_t)(*f_pos), &entry_offset);

  if (!entry) {
    *f_pos = 0;
    retval = 0;
    goto done;
  }

  len = min(entry->size - entry_offset, count);

  if (copy_to_user(buf, entry->buffptr + entry_offset, len)) {
    retval = -EFAULT;
    goto done;
  }

  *f_pos += len;
  retval = len;

done:
  mutex_unlock(&dev->aesd_mutex);
  return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos) {
  ssize_t retval = -ENOMEM;
  struct aesd_dev *dev;
  struct aesd_buffer_entry *entry;
  size_t i, start_idx;

  if (!filp || !buf || !f_pos)
    return -EFAULT;

  PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

  dev = (struct aesd_dev *)filp->private_data;
  if (!dev)
    return -EFAULT;

  if (mutex_lock_interruptible(&dev->aesd_mutex) != 0)
    return -ERESTARTSYS;

  entry = &dev->entry;

  if (entry->size == 0) {
    entry->buffptr = kmalloc(count, GFP_KERNEL);
    start_idx = 0;
  } else {
    entry->buffptr = krealloc(entry->buffptr, entry->size + count, GFP_KERNEL);
    start_idx = entry->size;
  }

  if (!entry->buffptr) {
    retval = -ENOMEM;
    goto done;
  }

  if (copy_from_user(entry->buffptr + start_idx, buf, count)) {
    retval = -EFAULT;
    goto done;
  

  entry->size += count;
  retval = count;

  for (i = start_idx; i < entry->size; i++) {
    if (entry->buffptr[i] == '\n') {
      aesd_circular_buffer_add_entry(&dev->aesd_buffer, entry);
      entry->size = 0;
      break;
    }
  }

done:
  mutex_unlock(&dev->aesd_mutex);
  return retval;
}

static loff_t aesd_llseek(struct file *filp, loff_t offset, int whence) {
  loff_t ret;
  loff_t size;
  struct aesd_dev *dev = (struct aesd_dev *)filp->private_data;

  PDEBUG("llseek with offset %lld and whence %d", offset, whence);

  mutex_lock(&dev->lock);

  size = aesd_size(&dev->aesd_buffer);
  switch (whence) {
  case SEEK_SET:
  case SEEK_CUR:
  case SEEK_END:
    ret = fixed_size_llseek(filp, offset, whence, size);
    break;
  default:
    ret = -EINVAL;
  }

  mutex_unlock(&dev->lock);

  return ret;
}

static int aesd_adjust_file_offset(struct file *filp, uint32_t write_cmd,
                                   uint32_t write_cmd_offset) {
  size_t entry_start_offset = 0;

  struct aesd_buffer_entry *entry = aesd_circular_buffer_get_entry_and_offset(
      &aesd_device.aesd_buffer, write_cmd, &entry_start_offset);

  if (!entry || write_cmd_offset > entry->size)
    return -EINVAL;

  filp->f_pos = entry_start_offset + write_cmd_offset;
  return 0;
}

static long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  int retval = 0;

  if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC)
    return -ENOTTY;
  if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
    return -ENOTTY;

  switch (cmd) {

  case AESDCHAR_IOCSEEKTO: {
    struct aesd_seekto seekto;
    if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) !=
        0) {
      retval = -EFAULT;
      goto done;
    } else {
      retval = aesd_adjust_file_offset(filp, seekto.write_cmd,
                                       seekto.write_cmd_offset);
    }
    break;
  }
  default:
    retval = -ENOTTY;
    break;
  }
done:
  mutex_unlock(&aesd_device.aesd_mutex);
  return retval;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
    .llseek = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev) {
  int err, devno = MKDEV(aesd_major, aesd_minor);

  cdev_init(&dev->cdev, &aesd_fops);
  dev->cdev.owner = THIS_MODULE;
  dev->cdev.ops = &aesd_fops;
  err = cdev_add(&dev->cdev, devno, 1);
  if (err) {
    printk(KERN_ERR "Error %d adding aesd cdev", err);
  }
  return err;
}

int aesd_init_module(void) {
  dev_t dev = 0;
  int result;

  result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
  aesd_major = MAJOR(dev);
  if (result < 0) {
    printk(KERN_WARNING "Can't get major %d\n", aesd_major);
    return result;
  }
  memset(&aesd_device, 0, sizeof(struct aesd_dev));

  mutex_init(&aesd_device.aesd_mutex);
  aesd_circular_buffer_init(&aesd_device.aesd_buffer);
  result = aesd_setup_cdev(&aesd_device);

  if (result) {
    unregister_chrdev_region(dev, 1);
  }
  return result;
}

void aesd_cleanup_module(void) {
  dev_t devno = MKDEV(aesd_major, aesd_minor);
  cdev_del(&aesd_device.cdev);

  uint8_t index;
  struct aesd_buffer_entry *entry = NULL;
  AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.aesd_buffer, index) {
    kfree(entry->buffptr);
  }

  mutex_destroy(&aesd_device.aesd_mutex);
  unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
