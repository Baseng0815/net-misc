#include "linux/slab.h"
#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/device/class.h>
#include <linux/err.h>
#include <linux/minmax.h>
#include <asm/ioctl.h>
#include <linux/uaccess.h>
#include <linux/container_of.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bastian Engel");

#define DEVICE_NAME "nsufw"
#define CLASS_NAME DEVICE_NAME "class"

struct ioctl_data {
        int a;
        int b;
};

enum filter_rule_type {
        FRT_SRC_IP,
        FRT_SRC_PORT
};

struct fp_src_ip {
        uint8_t bytes[4];
};

struct fp_src_port {
        short port;
};

// struct filter_param_...

struct filter_rule {
        enum filter_rule_type type;
        int accept;
        union {
                struct fp_src_ip src_ip;
                struct fp_src_port src_port;
        };
};

struct filter_rule_list {
        struct filter_rule rule;
        struct list_head head;
};

#define MY_IOCTL_IN _IOC(_IOC_WRITE, 'k', 1, sizeof(struct ioctl_data))

static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static int device_close(struct inode *inode, struct file *file);
static ssize_t device_read(struct file *file, char __user *buffer, size_t size, loff_t *offset);
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static void print_filter_table(const struct list_head *list);
static void print_rule_src_ip(const struct fp_src_ip *param);
static void print_rule_src_port(const struct fp_src_port *param);

static struct file_operations fops = {
        .open = device_open,
        .release = device_release,
        .read = device_read,
        .unlocked_ioctl = device_ioctl
};

static struct nsufw_data {
        dev_t devnum; // MAJOR/MINOR allocated by alloc_chrdev_region
        struct cdev cdev; // used to register fops to the kernel
        struct class *class;
        struct device *device;
        atomic_t lock;
} nsufw_data;

static LIST_HEAD(filter_table);

int __init init_module(void)
{
        struct filter_rule_list *frl1 = kmalloc(sizeof *frl1, GFP_KERNEL);
        *frl1 = (struct filter_rule_list) {
                .rule = {
                        .type = FRT_SRC_PORT,
                        .src_port = {
                                .port = 12345
                        },
                        .accept = 1
                }
        };

        struct filter_rule_list *frl2 = kmalloc(sizeof *frl2, GFP_KERNEL);
        *frl2 = (struct filter_rule_list) {
                .rule = {
                        .type = FRT_SRC_IP,
                        .src_ip = {
                                .bytes = { 192, 168, 2, 1 }
                        },
                        .accept = 0
                }
        };

        list_add(&frl1->head, &filter_table);
        list_add(&frl2->head, &filter_table);

        print_filter_table(&filter_table);

        pr_info("NSUFW: Welcome\n");

        int result = alloc_chrdev_region(&nsufw_data.devnum, 0, 1, DEVICE_NAME);
        if (result) {
                pr_alert("NSUFW: failed to alloc chrdev region\n");
                return result;
        }

        pr_info("NSUFW: allocated chrdev region: (%d, %d)\n",
                MAJOR(nsufw_data.devnum), MINOR(nsufw_data.devnum));

        nsufw_data.class = class_create(CLASS_NAME);
        if (IS_ERR(nsufw_data.class)) {
                pr_alert("NSUFW: failed to create class\n");
                unregister_chrdev_region(nsufw_data.devnum, 1);
                return PTR_ERR(nsufw_data.class);
        }

        nsufw_data.device = device_create(nsufw_data.class, NULL, nsufw_data.devnum, NULL, DEVICE_NAME);
        if (IS_ERR(nsufw_data.device)) {
                pr_alert("NSUFW: failed to create device\n");
                class_destroy(nsufw_data.class);
        }

        cdev_init(&nsufw_data.cdev, &fops);
        result = cdev_add(&nsufw_data.cdev, nsufw_data.devnum, 1);

        if (result) {
                pr_alert("NSUFW: failed to add cdev\n");
                unregister_chrdev_region(nsufw_data.devnum, 1);
                return result;
        }

        printk(KERN_INFO "NSUFW: added cdev\n");

        return 0;
}

void __exit cleanup_module(void)
{
        cdev_del(&nsufw_data.cdev);
        device_destroy(nsufw_data.class, nsufw_data.devnum);
        class_destroy(nsufw_data.class);
        unregister_chrdev_region(nsufw_data.devnum, 1);

        pr_info("NSUFW: Goodbye\n");
}

int device_open(struct inode *inode, struct file *file)
{
        struct nsufw_data *data = container_of(inode->i_cdev, struct nsufw_data, cdev);
        int was_locked = atomic_cmpxchg(&data->lock, 0, 1);
        if (was_locked) {
                pr_info("NSUFW: process tried to open locked device file\n");
                return -EBUSY;
        }

        file->private_data = data;

        pr_info("NSUFW: opened device\n");
        return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
        struct nsufw_data *data = container_of(inode->i_cdev, struct nsufw_data, cdev);
        atomic_set(&data->lock, 0);

        pr_info("NSUFW: released device\n");
        return 0;
}

ssize_t device_read(struct file *file, char __user *buffer, size_t size,
                    loff_t *offset)
{
        const char *str = "hello man\n";
        size_t data_size = strlen(str) + 1;

        ssize_t len = min((ssize_t)(data_size - *offset), (ssize_t)size);

        if (len <= 0) {
                return 0;
        }

        if (copy_to_user(buffer, str + *offset, len)) {
                return -EFAULT;
        }

        *offset += len;
        return len;
}

long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        pr_info("NSUFW: ioctl\n");
        struct ioctl_data data;
        switch (cmd) {
                case MY_IOCTL_IN:
                        if (copy_from_user(&data, (struct ioctl_data*)arg, sizeof(struct ioctl_data))) {
                                return -EFAULT;
                        }
                        pr_info("NSUFW: ioctl (%d %d)\n", data.a, data.b);
                        break;

                default:
                        return -ENOTTY;
        }

        return 0;
}

void print_filter_table(const struct list_head *list)
{
        const struct list_head *cursor;
        list_for_each(cursor, list) {
                const struct filter_rule *rule= &list_entry(cursor, struct filter_rule_list, head)->rule;
                switch (rule->type) {
                        case FRT_SRC_IP:
                                print_rule_src_ip(&rule->src_ip);
                                break;
                        case FRT_SRC_PORT:
                                print_rule_src_port(&rule->src_port);
                                break;
                        default:
                                pr_alert("NSUFW: invalid type (%d)\n", rule->type);
                                break;
                }
        }
}

void print_rule_src_ip(const struct fp_src_ip *param)
{
        const uint8_t *b = param->bytes;
        pr_info("NSUFW: rule type SRC_IP (%d.%d.%d.%d)\n", b[0], b[1], b[2], b[3]);
}

void print_rule_src_port(const struct fp_src_port *param)
{
        pr_info("NSUFW: rule type SRC_PORT (%d)\n", param->port);
}
