/*
* Copyright (c) 2012 Sony Mobile Communications Inc.
* All rights, including trade secret rights, reserved.
*
*@ file drivers/misc/lastlogs.c
*
*
*/
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/rdtags.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/kmsg_dump.h>
#include "../../arch/arm/mach-msm/smd_private.h"

#if defined(CONFIG_LOG_BUF_MAGIC)
#define LOGBUF_MAGIC 0x5d7aefca
#endif

struct last_logs {
	u32 sig;
	u32 size;
	u8 data[0];
};
static struct device *dev;
static char __iomem *kmsg_base;
static char __iomem *amss_base;
static char *kmsg_buf;
static char *amss_buf;
static u32 kmsg_size, amss_size;
static u32 kmsg_data_size;
static int ramdump_mode;

static int __init warm_boot(char *str)
{
	unsigned long res;

	if (!*str)
		return 0;

	if (!kstrtoul(str, 0 , &res)) {
		if (res == 0xC0DEDEAD || res == 0xABADBABE)
			ramdump_mode = 1;
	}

	return 1;
}
__setup("warmboot=", warm_boot);

enum log_rec_flags {
	LOG_NOCONS = 1,         /* already flushed, do not print to console */
	LOG_NEWLINE = 2,        /* text ended with a newline */
	LOG_PREFIX = 4,         /* text started with a prefix */
	LOG_CONT = 8,           /* text is a fragment of a continuation line */
};

struct log_record {
	u64 ts_nsec;            /* timestamp in nanoseconds */
	u16 len;                /* length of entire record */
	u16 text_len;           /* length of text buffer */
	u16 dict_len;           /* length of dictionary buffer */
	u8 facility;            /* syslog facility */
	u8 flags:5;             /* internal record flags */
	u8 level:3;             /* syslog level */
#if defined(CONFIG_LOG_BUF_MAGIC)
	u32 magic;
#endif
};

#define KMSGLOG_SIG 0x48144848
#define AMSSLOG_SIG 0x47327894
#define LOG_LINE_MAX 900

static ssize_t amss_lastlog_read(struct file *file, char __user *buf,
					size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;

	if (pos >= amss_size)
		return 0;

	count = min(len, (size_t)(amss_size - pos));
	if (copy_to_user(buf, amss_buf + pos, count))
		return -EFAULT;

	*offset += count;
	return count;
}

static const struct file_operations amss_fops = {
	.owner = THIS_MODULE,
	.read = amss_lastlog_read,
};

static int export_amss_logs(void)
{
	struct proc_dir_entry *entry;
	struct last_logs *buffer = (struct last_logs __iomem *)amss_base;

	amss_buf = kzalloc(amss_size, GFP_KERNEL);
	if (amss_buf == NULL) {
		dev_err(dev,
			"Failed allocating amss buffer\n");
			return -ENOMEM;
	}

	amss_size = min(buffer->size, amss_size);
	memcpy(amss_buf, buffer->data, amss_size);
	entry = create_proc_entry("last_amsslog",
			S_IFREG | S_IRUGO, NULL);
	if (!entry) {
		dev_err(dev,
			"failed to create last_amsslog proc entry\n");
		kfree(amss_buf);
		amss_buf = NULL;
		return -ENOMEM;
	}

	entry->proc_fops = &amss_fops;
	entry->size = amss_size;
	return 0;
}

static int extract_amss_logs(void)
{
	struct last_logs *buffer = (struct last_logs __iomem *)amss_base;
	char *smem_errlog = NULL;
	size_t size;

	smem_errlog = smem_get_entry(SMEM_ERR_CRASH_LOG, &size);

	if (smem_errlog && !memcmp(smem_errlog, "ERR", 3)) {
		buffer->sig = AMSSLOG_SIG;

		if (size > (amss_size - (buffer->data - (uint8_t *)buffer)))
			buffer->size = amss_size -
				(buffer->data - (uint8_t *)buffer);
		else
			buffer->size = size;

		memcpy(buffer->data, smem_errlog, buffer->size);
	} else {
		dev_info(dev, "Failed to extract amss logs\n");
		return -EINVAL;
	}

	return 0;
}

static ssize_t kmsg_lastlog_read(struct file *file, char __user *buf,
				size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;

	if (pos >= kmsg_data_size)
		return 0;

	count = min(len, (size_t)(kmsg_data_size - pos));
	if (copy_to_user(buf, kmsg_buf + pos, count))
		return -EFAULT;

	*offset += count;
	return count;
}

static const struct file_operations last_kmsg_fops = {
	.owner = THIS_MODULE,
	.read = kmsg_lastlog_read,
};

static int is_logbuf_size_valid(u32 size)
{
	struct last_logs __iomem *buffer;
	u32 max_size;

	buffer = (struct last_logs __iomem *)kmsg_base;
	max_size = kmsg_size - ((unsigned long)buffer->data -
			(unsigned long)buffer);

	if (size > 0 && size <= max_size)
		return 1;

	return 0;
}

static unsigned long read_rdtags(char *name)
{
	unsigned long tag_data;
	char *log_data;
	int err = -EINVAL;
	size_t bufsize;

	if (rdtags_get_tag_data(name, NULL, &bufsize) != -ENOBUFS) {
		dev_err(dev, "Could not find tag \"%s\"!\n",
			name ? name : "NULL");
		return 0;
	}

	log_data = kzalloc(bufsize, GFP_KERNEL);
	if (!log_data) {
		dev_err(dev, "Could not allocate %zd bytes of memory!\n",
			bufsize);
		return 0;
	}

	err = rdtags_get_tag_data(name, log_data, &bufsize);
	if (err) {
		dev_err(dev, "Could not get %zd bytes of data to tag %s %d\n",
				bufsize, name, err);
		kfree(log_data);
		return 0;
	}

	err = kstrtoul(log_data, 16, &tag_data);
	if (err < 0) {
		dev_err(dev, "Failed kstrtoul %s %lx\n",
			log_data, tag_data);
		kfree(log_data);
		return 0;
	}

	dev_dbg(dev, "logbuf tags verify %s %lx\n",
			log_data, tag_data);

	kfree(log_data);
	return tag_data;
}

static int kmsg_export_logs(void)
{
	struct proc_dir_entry *entry;
	struct last_logs __iomem *buffer =
			(struct last_logs __iomem *)kmsg_base;
	u32 size, max_size;

	kmsg_buf = kzalloc(kmsg_size, GFP_KERNEL);
	if (kmsg_buf == NULL) {
		dev_err(dev,
			"failed allocating kmsg buffer\n");
		return -ENOMEM;
	}

	max_size = kmsg_size - ((unsigned long)buffer->data -
			(unsigned long)buffer);

	if (!is_logbuf_size_valid(readl_relaxed(&buffer->size))) {
		dev_err(dev, "invalid buffer length\n");
		kfree(kmsg_buf);
		kmsg_buf = NULL;
		return -EINVAL;
	}

	size = min(readl_relaxed(&buffer->size), max_size);
	memcpy_fromio(kmsg_buf, buffer->data, size);
	entry = proc_create_data("last_kmsg",
			S_IFREG | S_IRUGO, NULL, &last_kmsg_fops, NULL);
	if (!entry) {
		dev_err(dev,
			"failed to create last_kmsg proc entry\n");
		kfree(kmsg_buf);
		kmsg_buf = NULL;
		return -ENOMEM;
	}

	return 0;
}

static struct log_record *
kmsg_record_from_idx(u32 idx, char *logbuf)
{
	struct log_record *log_msg;
	char *buf = logbuf;

	log_msg = (struct log_record *) (buf + idx);

	if (!log_msg->len)
		return (struct log_record *) buf;

	return log_msg;
}

static unsigned int kmsg_next_idx(u32 idx, char *log_buf)
{
	struct log_record *msg = (struct log_record *)(log_buf + idx);

	if (!msg->len) {
		msg = (struct log_record *)log_buf;
		return msg->len;
	}

	return idx + msg->len;
}

static char *kmsg_text_from_msg(struct log_record *msg)
{
	return (char *)msg + sizeof(struct log_record);
}

#define DISP_FORMAT_SIZE 64
static size_t kmsg_print_time(u64 ts, char *buf)
{
	unsigned long rem_nsec;

	rem_nsec = do_div(ts, 1000000000);

	if (!buf)
		return snprintf(NULL, 0, "[%5lu.000000] ", (unsigned long)ts);

	return snprintf(buf, DISP_FORMAT_SIZE, "[%5lu.%06lu] ",
		(unsigned long)ts, rem_nsec / 1000);
}

static size_t kmsg_print_prefix(const struct log_record *msg, bool syslog,
		char *buf)
{
	size_t len = 0;
	unsigned int prefix = (msg->facility << 3) | msg->level;

	if (syslog) {
		if (buf) {
			len += snprintf(buf, DISP_FORMAT_SIZE, "<%u>", prefix);
		} else {
			len += 3;
			if (prefix > 999)
				len += 3;
			else if (prefix > 99)
				len += 2;
			else if (prefix > 9)
				len++;
		}
	}

	len += kmsg_print_time(msg->ts_nsec, buf ? buf + len : NULL);
	return len;
}

static size_t kmsg_get_line(const struct log_record *msg, const char *text,
		enum log_rec_flags prev, bool syslog, char *buf, size_t size)
{
	size_t text_size = msg->text_len;
	bool prefix = true;
	bool newline = true;
	size_t len = 0;

	if ((prev & LOG_CONT) && !(msg->flags & LOG_PREFIX))
		prefix = false;

	if (msg->flags & LOG_CONT) {
		if ((prev & LOG_CONT) && !(prev & LOG_NEWLINE))
			prefix = false;

	if (!(msg->flags & LOG_NEWLINE))
		newline = false;
	}

	do {
		const char *next;
		size_t text_len;

		next = memchr(text, '\n', text_size);
		if (next) {
			text_len = next - text;
			next++;
			text_size -= next - text;
		} else {
			text_len = text_size;
		}

		if (buf) {
			if (kmsg_print_prefix(msg, syslog, NULL) +
				text_len + 1 >= size - len)
				break;

			if (prefix)
				len += kmsg_print_prefix(msg, syslog,
						buf + len);
			snprintf((buf + len), (size - len), "%s", text);
			len += text_len;
			if (next || newline)
				buf[len++] = '\n';
			} else {
			if (prefix)
				len += kmsg_print_prefix(msg, syslog, NULL);
			len += text_len;
			if (next || newline)
				len++;
			}

			prefix = true;
			text = next;
	} while (text);

	return len;
}

static int process_records_to_plaintext(char *org_log_buf, u32 log_buf_len,
		u32 log_first_idx, u32 log_next_idx)
{
	struct last_logs __iomem *buffer =
				(struct last_logs __iomem *)kmsg_base;
	const char *text;
	struct log_record *msg;
	u32 idx = log_first_idx, msg_len, len, written = 0;
	char *buf, *log_buf;

	log_buf = (char *)__get_free_pages(GFP_KERNEL, get_order(log_buf_len));
	if (!log_buf) {
		dev_err(dev, "Failed to allocate pages of order %d\n",
				get_order(log_buf_len));
		return -ENOMEM;
	}
	memcpy_fromio(log_buf, org_log_buf, log_buf_len);

	while (idx != log_next_idx) {
		len = 0;
		msg = kmsg_record_from_idx(idx, log_buf);
#if defined(CONFIG_LOG_BUF_MAGIC)
		if (msg->magic != LOGBUF_MAGIC) {
			char err_buf[LOG_LINE_MAX];
			int buf_len;
			dev_warn(dev, "Kernel logbuf Corrupted at offset %d\n",
					idx);
			buf_len = snprintf(err_buf, LOG_LINE_MAX, "\n%s\n%s\n",
					"---- kernel log is truncated ----",
					"invalid log_buf entry encountered");
			if ((written + buf_len) < kmsg_size) {
				memcpy_toio(buffer->data + written, err_buf,
						buf_len);
				written += buf_len;
			}

			break;
		}
#endif

		text = kmsg_text_from_msg(msg);
		msg_len = msg->len + DISP_FORMAT_SIZE;

		if (msg_len > LOG_LINE_MAX) {
			dev_err(dev, "Invalid msg length %d\n", msg_len);
			return -EINVAL;
		}

		buf = kzalloc(msg_len, GFP_KERNEL);
		if (!buf) {
			dev_err(dev, "Failed to allocate memory\n");
			return -ENOMEM;
		}

		len = kmsg_get_line(msg, text, false, true, buf, msg_len);
		if ((written + len + 1) > kmsg_size) {
			dev_info(dev, "debug buffer is full exiting!!\n");
			kfree(buf);
			break;
		}

		memcpy_toio(buffer->data + written, buf, len);
		written += len;
		kfree(buf);
		idx = kmsg_next_idx(idx, log_buf);
	}

	writel_relaxed(KMSGLOG_SIG, &buffer->sig);
	writel_relaxed(written, &buffer->size);
	kmsg_data_size = written;
	free_pages((unsigned long)log_buf, get_order(log_buf_len));
	return 0;
}

#define NR_LOG_INFO 4

static int lastlogs_extract_kmsg(void)
{
	unsigned long __iomem *plog_buf_len;
	unsigned long __iomem *plog_first_idx;
	unsigned long __iomem *plog_next_idx;
	u32 log_first_idx, log_next_idx, log_buf_len;
	unsigned long tags_addr[NR_LOG_INFO];
	char __iomem *log_buf;
	int i, ret;
	char *rdtag_list[] = {
			"log_buf_len",
			"log_first_idx",
			"log_next_idx",
			"__log_buf"
	};

	for (i = 0; i < NR_LOG_INFO; i++) {
		tags_addr[i] = read_rdtags(rdtag_list[i]);
		if (!tags_addr[i])
			return -EINVAL;
	}

	plog_buf_len = (unsigned long __iomem *)ioremap(tags_addr[0],
			sizeof(u32));
	if (!plog_buf_len) {
		dev_err(dev, "log_buf_len: Ioremap Failed !!\n");
		goto exit1;
	}

	plog_first_idx = (unsigned long __iomem *)ioremap(tags_addr[1],
			sizeof(u32));
	if (!plog_first_idx) {
		dev_err(dev, "log_first_idx: Ioremap Failed!!\n");
		goto exit2;
	}

	plog_next_idx = (unsigned long __iomem *)ioremap(tags_addr[2],
			sizeof(u32));
	if (!plog_next_idx) {
		dev_err(dev, "log_next_idx: Ioremap Failed!!\n");
		goto exit3;
	}

	log_next_idx = readl_relaxed(plog_next_idx);
	log_buf_len = readl_relaxed(plog_buf_len);
	log_first_idx = readl_relaxed(plog_first_idx);

	if (log_buf_len > (1 << CONFIG_LOG_BUF_SHIFT))
		log_buf_len = (1 << CONFIG_LOG_BUF_SHIFT);

	if ((log_first_idx > log_buf_len) || (log_next_idx > log_buf_len)) {
		dev_err(dev, "Invalid log_first_idx/log_next_idx!!\n");
		return -EINVAL;
	}

	log_buf = (char __iomem *)ioremap(tags_addr[3], log_buf_len);
	if (!log_buf) {
		dev_err(dev, "log_buf: Ioremap Failed!!\n");
		goto exit4;
	}

	memset_io(kmsg_base, 0x0, kmsg_size);
	ret = process_records_to_plaintext(log_buf, log_buf_len,
			log_first_idx, log_next_idx);
	if (ret < 0) {
		dev_err(dev, "Failed to convert records to plain text\n");
		dev_err(dev, "Cleaning last_kmsg debug area\n");
		memset_io(kmsg_base, 0x0, kmsg_size);
		goto exit5;
	}

	iounmap(plog_buf_len);
	iounmap(plog_first_idx);
	iounmap(plog_next_idx);
	iounmap(log_buf);

	return 0;

exit5:
	if (log_buf)
		iounmap(log_buf);
exit4:
	if (plog_next_idx)
		iounmap(plog_next_idx);

exit3:
	if (plog_first_idx)
		iounmap(plog_first_idx);

exit2:
	if (plog_buf_len)
		iounmap(plog_buf_len);

exit1:
	return -ENOMEM;

}

static int lastlogs_kmsg_dumps(char *buf, const char *kmsg,
		unsigned long len)
{
	const char *kmsg_idx = kmsg;
	char *line_buf;
	struct log_record *log_msg;
	u32 msg_len, line_len, kmsg_dump_len = 0;

	while (kmsg_idx < kmsg + len) {
		log_msg = (struct log_record *)kmsg_idx;
		msg_len = log_msg->len + DISP_FORMAT_SIZE;
		if (msg_len > LOG_LINE_MAX) {
			dev_err(dev, "Invalid kmsg length %d\n", msg_len);
			return kmsg_dump_len;
		}

		line_buf = kzalloc(msg_len, GFP_KERNEL);
		if (!line_buf) {
			dev_err(dev, "Failed to allocate memory\n");
			return kmsg_dump_len;
		}

		line_len = kmsg_get_line(log_msg,
				kmsg_idx + sizeof(struct log_record),
				false, true, line_buf, msg_len);
		if ((buf + kmsg_dump_len + line_len + 1) > kmsg_base +
				kmsg_size) {
			dev_info(dev, "kmsg buffer is full exiting!!\n");
			kfree(line_buf);
			return kmsg_dump_len;
		}

		memcpy_toio(buf + kmsg_dump_len, line_buf, line_len);
		kmsg_dump_len += line_len;
		kfree(line_buf);
		kmsg_idx += log_msg->len;
	}
	return kmsg_dump_len;
}

static void lastlogs_dump(struct kmsg_dumper *dumper,
		enum kmsg_dump_reason reason, const char *s1, unsigned long l1,
		const char *s2, unsigned long l2)
{
	struct last_logs __iomem *kbuffer =
			(struct last_logs __iomem *)kmsg_base;
	int written_len = 0;

	if (reason != KMSG_DUMP_PANIC)
		return;

	written_len = lastlogs_kmsg_dumps(kbuffer->data, s1, l1);
	written_len += lastlogs_kmsg_dumps(kbuffer->data + written_len,
			s2, l2);
	writel_relaxed(KMSGLOG_SIG, &kbuffer->sig);
	writel_relaxed(written_len, &kbuffer->size);
}

static struct kmsg_dumper lastlogs_dumper = {
	.dump = lastlogs_dump,
};

static int lastlogs_driver_probe(struct platform_device *pdev)
{
	struct resource *kmsg_res, *amss_res;
	struct last_logs __iomem *kbuffer, *abuffer;
	int ret = 0;

	dev = &pdev->dev;
	kmsg_res = platform_get_resource_byname(pdev,
			IORESOURCE_MEM, "last_kmsg");
	if (!kmsg_res || !kmsg_res->start) {
		dev_err(dev, "last_kmsg resource invalid/absent\n");
		ret = -ENODEV;
		goto amss_log;
	}

	kmsg_size = kmsg_res->end - kmsg_res->start + 1;
	kmsg_base = (char __iomem *)ioremap(kmsg_res->start, kmsg_size);
	if (kmsg_base == NULL) {
		dev_err(dev, "failed to map last_kmsg memory\n");
		return -ENOMEM;
	}

	kbuffer = (struct last_logs __iomem *)kmsg_base;

	if (ramdump_mode && !lastlogs_extract_kmsg()) {
		dev_info(dev, "kmsg logs extracted\n");
		if (kmsg_export_logs())
			dev_err(dev, "Failed to export last_kmsg\n");
	} else if (readl_relaxed(&kbuffer->sig) == KMSGLOG_SIG) {
		dev_info(dev, "kmsg logs found\n");
		if (kmsg_export_logs())
			dev_err(dev, "Failed to export last_kmsg\n");
		kmsg_data_size = min(readl_relaxed(&kbuffer->size), kmsg_size);
		memset_io(kmsg_base, 0x0, kmsg_size);
	}

amss_log:
	amss_res = platform_get_resource_byname(pdev,
				IORESOURCE_MEM, "last_amsslog");
	if (!amss_res || !amss_res->start) {
		dev_err(dev, "last_amsslog resource invalid/absent\n");
		return -ENODEV;
	}

	amss_size = amss_res->end - amss_res->start + 1;
	amss_base = (char __iomem *)ioremap(amss_res->start, amss_size);
	if (!amss_base) {
		dev_err(dev, "failed to map last_amsslog\n");
		return -ENOMEM;
	}

	abuffer = (struct last_logs __iomem *)amss_base;

	if (ramdump_mode) {
		if (!extract_amss_logs()) {
			dev_info(dev, "Amss logs extracted\n");
			export_amss_logs();
		}
	} else if (abuffer->sig == AMSSLOG_SIG) {
		dev_info(dev, "Amss logs Found\n");
		export_amss_logs();
		memset(amss_base, 0x0, amss_size);
	}
	iounmap(amss_base);
	kmsg_dump_register(&lastlogs_dumper);
	dev_info(dev, "Last logs driver probe done !!\n");
	return ret;
}

static struct platform_driver lastlogs_driver = {
	.probe = lastlogs_driver_probe,
	.driver = {
		.name   = "last_logs",
	},
};

static int __init lastlogs_module_init(void)
{
	int err;
	err = platform_driver_register(&lastlogs_driver);
	return err;
}

MODULE_AUTHOR("Anirudh Madnurkar <anirudh.x.madnurkar@sonymobile.com>");
MODULE_DESCRIPTION("last crash logs");
MODULE_LICENSE("GPL V2");

module_init(lastlogs_module_init)
