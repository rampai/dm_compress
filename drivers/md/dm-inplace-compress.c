/*
 *  device mapper compression block device.
 *
 *  Released under GPL v2.
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/crypto.h>
#include <linux/lzo.h>
#include <linux/lz4.h>
#include <linux/kthread.h>
#include <linux/page-flags.h>
#include <linux/completion.h>
#include <linux/vmalloc.h>
#include <linux/parser.h>
#include "dm-inplace-compress.h"

#define DM_MSG_PREFIX "dm-inplace-compress"


static const struct kernel_param_ops dm_icomp_alloc_param_ops = {
	.set    = param_set_ulong,
	.get    = param_get_ulong,
};

static atomic64_t dm_icomp_total_alloc_size;
#define DMICP_ALLOC(s) atomic64_add(s, &dm_icomp_total_alloc_size)
#define DMICP_FREE_ALLOC(s) atomic64_sub(s, &dm_icomp_total_alloc_size)
module_param_cb(dm_icomp_total_alloc_size, &dm_icomp_alloc_param_ops,
				&dm_icomp_total_alloc_size, 0644);

static atomic64_t dm_icomp_total_bio_save;
#define DMICP_ALLOC_SAVE(s) {atomic64_add(s, &dm_icomp_total_bio_save); }
module_param_cb(dm_icomp_total_bio_save, &dm_icomp_alloc_param_ops,
				&dm_icomp_total_bio_save, 0644);


static struct kmem_cache *dm_icomp_req_cachep;
static struct kmem_cache *dm_icomp_io_range_cachep;
static struct kmem_cache *dm_icomp_meta_io_cachep;

static struct dm_icomp_io_worker dm_icomp_io_workers[NR_CPUS];
static struct workqueue_struct *dm_icomp_wq;

/*
 *****************************************************
 * compressor selection logic
 *****************************************************
 */
static struct dm_icomp_compressor_data compressors[] = {
	[DMICP_COMP_ALG_LZ4] = {
		.name = "lz4",
		.can_handle_overflow = true,
		.comp_len = lz4_comp_len,
		.max_comp_len = lz4_max_comp_len,
	},
	[DMICP_COMP_ALG_LZO] = {
		.name = "lzo",
		.can_handle_overflow = false,
		.comp_len = lzo_comp_len,
		.max_comp_len = lzo_max_comp_len,
	},
	[DMICP_COMP_ALG_842] = {
		.name = "842",
		.can_handle_overflow = true,
		.comp_len = nx842_comp_len,
		.max_comp_len = nx842_max_comp_len,
	},
};

static int default_compressor = DMICP_COMP_ALG_LZO;
#define DMICP_ALGO_LENGTH 9
static char dm_icomp_algorithm[DMICP_ALGO_LENGTH] = "lzo";
static struct kparam_string dm_icomp_compressor_kparam = {
	.string =	dm_icomp_algorithm,
	.maxlen =	sizeof(dm_icomp_algorithm),
};
static int dm_icomp_compressor_param_set(const char *,
		const struct kernel_param *);
static struct kernel_param_ops dm_icomp_compressor_param_ops = {
	.set =	dm_icomp_compressor_param_set,
	.get =	param_get_string,
};
module_param_cb(compress_algorithm, &dm_icomp_compressor_param_ops,
		&dm_icomp_compressor_kparam, 0644);



static int get_comp_id(const char *s)
{
	int r, val_len;

	if (!crypto_has_comp(s, 0, 0))
		return -1;

	for (r = 0; r < ARRAY_SIZE(compressors); r++) {
		val_len = strlen(compressors[r].name);
		if (!strncmp(s, compressors[r].name, val_len))
			return r;
	}
	return -1;
}

static const char *get_comp_name(int id)
{
	if (id < 0 || id > ARRAY_SIZE(compressors))
		return NULL;
	return compressors[id].name;
}

static void set_default_compressor(int index)
{
	default_compressor = index;
	strlcpy(dm_icomp_algorithm, compressors[index].name,
			sizeof(dm_icomp_algorithm));
	DMINFO("compressor  is %s", dm_icomp_algorithm);
}

static inline int get_default_compressor(void)
{
	return default_compressor;
}

static int select_default_compressor(void)
{
	int r;
	int arr_size = ARRAY_SIZE(compressors);

	for (r = 0; r < arr_size; r++)
		if (crypto_has_comp(compressors[r].name, 0, 0))
			break;
	if (r >= arr_size) {
		DMWARN("No crypto compressors are supported");
		return -EINVAL;
	}
	set_default_compressor(r);
	return 0;
}

static int dm_icomp_compressor_param_set(const char *val,
		const struct kernel_param *kp)
{
	int ret;
	char str[kp->str->maxlen], *s;
	int val_len = strlen(val)+1;

	strlcpy(str, val, val_len);
	s = strim(str);
	ret = get_comp_id(s);
	if (ret < 0) {
		DMWARN("Compressor %s not supported", s);
		return -1;
	}
	set_default_compressor(ret);
	return 0;
}

static void free_compressor(struct dm_icomp_info *info)
{
	int i;

	for_each_possible_cpu(i) {
		if (info->tfm[i]) {
			crypto_free_comp(info->tfm[i]);
			info->tfm[i] = NULL;
		}
	}
}

static int alloc_compressor(struct dm_icomp_info *info)
{
	int i;
	const char *alg_name = get_comp_name(info->comp_alg);

	for_each_possible_cpu(i) {
		info->tfm[i] = crypto_alloc_comp(
			alg_name, 0, 0);
		if (IS_ERR(info->tfm[i]))
			goto err;
	}
	return 0;

err:
	free_compressor(info);
	return -ENOMEM;
}

/**** END compressor select logic ****/


/*****  metadata logic ***************/
/*
 * return the meta data bits corresponding to a block
 * @block_index : the index of the block
 */
static u8 dm_icomp_get_meta(struct dm_icomp_info *info, u64 block_index)
{
	u64 first_bit = block_index * DMICP_META_BITS;
	int bits, offset;
	u32 data;
	u8  ret = 0;

	offset = first_bit & (DMICP_BITS_PER_ENTRY-1);
	bits = min_t(u32, DMICP_META_BITS, DMICP_BITS_PER_ENTRY - offset);

	data = (u32)info->meta_bitmap[first_bit >> DMICP_META_BITS];
	ret = (data >> offset) & ((1 << bits) - 1);

	if (bits < DMICP_META_BITS) {
		data = info->meta_bitmap[(first_bit >> DMICP_META_BITS) + 1];
		bits = DMICP_META_BITS - bits;
		ret |= (data & ((1 << bits) - 1)) << (DMICP_META_BITS - bits);
	}
	return ret;
}


static void dm_icomp_mark_page(struct dm_icomp_info *info, u32 *addr,
				bool dirty_meta)
{
	struct page *page;

	page = vmalloc_to_page(addr);
	if (!page)
		return;
	if (dirty_meta)
		SetPageDirty(page);
	else
		ClearPageDirty(page);
}

/*
 * set the meta data bits corresponding to a block
 * @block_index : the index of the block
 * @meta        : the meta data bits.
 */
static void dm_icomp_set_meta(struct dm_icomp_info *info, u64 block_index,
		u8 meta, bool dirty_meta)
{
	u64 first_bit = block_index * DMICP_META_BITS;
	int bits, offset;
	u32 data;

	offset = first_bit & (DMICP_BITS_PER_ENTRY-1);
	bits = min_t(u32, DMICP_META_BITS, DMICP_BITS_PER_ENTRY - offset);


	data = (u32)info->meta_bitmap[first_bit >> DMICP_META_BITS];
	data &= ~(((1 << bits) - 1) << offset);
	data |= (meta & ((1 << bits) - 1)) << offset;
	info->meta_bitmap[first_bit >> DMICP_META_BITS] = (u32)data;

	if (info->write_mode == DMICP_WRITE_BACK)
		dm_icomp_mark_page(info,
			&info->meta_bitmap[first_bit >> DMICP_META_BITS],
			dirty_meta);

	if (bits < DMICP_META_BITS) {
		meta >>= bits;
		data = (u32)
			info->meta_bitmap[(first_bit >> DMICP_META_BITS) + 1];
		bits = DMICP_META_BITS - bits;
		data = (data >> bits) << bits;
		data |= meta & ((1 << bits) - 1);
		info->meta_bitmap[(first_bit >> DMICP_META_BITS) + 1] =
				(u32)data;

		if (info->write_mode == DMICP_WRITE_BACK)
			dm_icomp_mark_page(info,
			&info->meta_bitmap[(first_bit >> DMICP_META_BITS) + 1],
			dirty_meta);
	}
}


/*
 * set the meta data bits corresponding to an extent
 * @block : the index of the block
 * @logical_blocks: the number of blocks in the extent
 * @sectors: the number of sectors holding the compressed
 *		data
 */
static void dm_icomp_set_extent(struct dm_icomp_req *req, u64 block,
	u16 logical_blocks, sector_t data_sectors)
{
	int i;
	u8 data;

	for (i = 0; i < logical_blocks; i++) {
		data = min_t(sector_t, data_sectors, 8);
		data_sectors -= data;
		if (i != 0)
			data |= DMICP_TAIL_MASK;
		/* For FUA, we write out meta data directly */
		dm_icomp_set_meta(req->info, block + i, data,
					!(req->bio->bi_opf & REQ_FUA));
	}
}

/*
 * get the meta data bits corresponding to an extent
 * @block_index : the index of the block
 * @logical_blocks: return the number of blocks in the extent
 * @sectors: return the number of sectors holding the compressed
 *		data
 */
static void dm_icomp_get_extent(struct dm_icomp_info *info, u64 block_index,
	u64 *first_block_index, u16 *logical_sectors, u16 *data_sectors)
{
	u8 data;

	data = dm_icomp_get_meta(info, block_index);
	while (data & DMICP_TAIL_MASK) {
		block_index--;
		data = dm_icomp_get_meta(info, block_index);
	}
	*first_block_index = block_index;
	*logical_sectors = DMICP_BYTES_TO_SECTOR(DMICP_BLOCK_SIZE);
	*data_sectors = data & DMICP_LENGTH_MASK;
	block_index++;
	while (block_index < info->data_blocks) {
		data = dm_icomp_get_meta(info, block_index);
		if (!(data & DMICP_TAIL_MASK))
			break;
		*logical_sectors += DMICP_BYTES_TO_SECTOR(DMICP_BLOCK_SIZE);
		*data_sectors += data & DMICP_LENGTH_MASK;
		block_index++;
	}
}

/*
 * return the super block
 */
static int dm_icomp_access_super(struct dm_icomp_info *info, void *addr,
		int op, int flag)
{
	struct dm_io_region region;
	struct dm_io_request req;
	unsigned long io_error = 0;
	int ret;

	region.bdev = info->dev->bdev;
	region.sector = 0;
	region.count = DMICP_BYTES_TO_SECTOR(DMICP_BLOCK_SIZE);

	req.bi_op = op;
	req.bi_op_flags = flag;
	req.mem.type = DM_IO_KMEM;
	req.mem.offset = 0;
	req.mem.ptr.addr = addr;
	req.notify.fn = NULL;
	req.client = info->io_client;

	ret = dm_io(&req, 1, &region, &io_error);
	if (ret || io_error)
		return -EIO;
	return 0;
}

static void dm_icomp_meta_io_done(unsigned long error, void *context)
{
	struct dm_icomp_meta_io *meta_io = context;

	meta_io->fn(meta_io->data, error);
	kmem_cache_free(dm_icomp_meta_io_cachep, meta_io);
}

static inline int get_alloc_flag(struct dm_icomp_info *info)
{
	/*
	 * Use GFP_ATOMIC allocations if the device
	 * is used on the critical path
	 */
	return info->critical ? GFP_ATOMIC : GFP_NOIO;
}

/*
 * write meta data to the meta blocks in the backing store.
 */
static int dm_icomp_write_meta(struct dm_icomp_info *info, u64 start_page,
	u64 end_page, void *data,
	void (*fn)(void *data, unsigned long error), int rw, int flags)
{
	struct dm_icomp_meta_io *meta_io;
	sector_t sector, last_sector, last_meta_sector = info->data_start-1;

	WARN_ON(end_page > info->meta_bitmap_pages);

	sector = DMICP_META_START_SECTOR + (start_page <<
				(PAGE_SHIFT - SECTOR_SHIFT));
	WARN_ON(sector > last_meta_sector);
	if (sector > last_meta_sector) {
		fn(data, -EINVAL);
		return -EINVAL;
	}
	last_sector = sector + ((end_page - start_page) <<
				(PAGE_SHIFT - SECTOR_SHIFT));
	if (last_sector > last_meta_sector)
		last_sector = last_meta_sector;


	meta_io = kmem_cache_alloc(dm_icomp_meta_io_cachep,
					get_alloc_flag(info));
	if (!meta_io) {
		fn(data, -ENOMEM);
		return -ENOMEM;
	}
	meta_io->data = data;
	meta_io->fn = fn;

	meta_io->io_region.bdev = info->dev->bdev;


	meta_io->io_region.sector = sector;
	meta_io->io_region.count = last_sector - sector + 1;
	atomic64_add(DMICP_SECTOR_TO_BYTES(meta_io->io_region.count),
				&info->meta_write_size);

	meta_io->io_req.bi_op = rw;
	meta_io->io_req.bi_op_flags = flags;
	meta_io->io_req.mem.type = DM_IO_VMA;
	meta_io->io_req.mem.offset = 0;
	meta_io->io_req.mem.ptr.addr = ((char *)(info->meta_bitmap)) +
						(start_page << PAGE_SHIFT);
	meta_io->io_req.notify.fn = dm_icomp_meta_io_done;
	meta_io->io_req.notify.context = meta_io;
	meta_io->io_req.client = info->io_client;

	dm_io(&meta_io->io_req, 1, &meta_io->io_region, NULL);
	return 0;
}

struct writeback_flush_data {
	struct completion complete;
	atomic_t cnt;
};

static void writeback_flush_io_done(void *data, unsigned long error)
{
	struct writeback_flush_data *wb = data;

	if (atomic_dec_return(&wb->cnt))
		return;
	complete(&wb->complete);
}

static void dm_icomp_flush_dirty_meta(struct dm_icomp_info *info,
			struct writeback_flush_data *data)
{
	struct page *page;
	u64 start = 0, index;
	u32 pending = 0, cnt = 0;
	bool dirty;
	struct blk_plug plug;

	blk_start_plug(&plug);
	for (index = 0; index < info->meta_bitmap_pages; index++, cnt++) {
		if (cnt == 256) {
			cnt = 0;
			cond_resched();
		}

		page = vmalloc_to_page((char *)(info->meta_bitmap) +
					(index << PAGE_SHIFT));
		if (!page)
			DMWARN("Uable to find page for block=%llu", index);
		dirty = TestClearPageDirty(page);

		if (pending == 0 && dirty) {
			start = index;
			pending++;
			continue;
		} else if (pending == 0)
			continue;
		else if (pending > 0 && dirty) {
			pending++;
			continue;
		}

		/* pending > 0 && !dirty */
		atomic_inc(&data->cnt);
		dm_icomp_write_meta(info, start, start + pending, data,
			writeback_flush_io_done, REQ_OP_WRITE, WRITE);
		pending = 0;
	}

	if (pending > 0) {
		atomic_inc(&data->cnt);
		dm_icomp_write_meta(info, start, start + pending, data,
			writeback_flush_io_done, REQ_OP_WRITE, WRITE);
	}
	blkdev_issue_flush(info->dev->bdev, get_alloc_flag(info), NULL);
	blk_finish_plug(&plug);
}

static int dm_icomp_meta_writeback_thread(void *data)
{
	struct dm_icomp_info *info = data;
	struct writeback_flush_data wb;

	atomic_set(&wb.cnt, 1);
	init_completion(&wb.complete);

	while (!kthread_should_stop()) {
		schedule_timeout_interruptible(
			msecs_to_jiffies(info->writeback_delay * 1000));
		dm_icomp_flush_dirty_meta(info, &wb);
	}

	dm_icomp_flush_dirty_meta(info, &wb);

	writeback_flush_io_done(&wb, 0);
	wait_for_completion(&wb.complete);
	return 0;
}

static int dm_icomp_init_meta(struct dm_icomp_info *info, bool new)
{
	struct dm_io_region region;
	struct dm_io_request req;
	unsigned long io_error = 0;
	struct blk_plug plug;
	int ret;
	ssize_t len = DIV_ROUND_UP_ULL(info->meta_bitmap_bits,
			DMICP_BITS_PER_ENTRY);

	len *= (DMICP_BITS_PER_ENTRY >> 3);

	region.bdev = info->dev->bdev;
	region.sector = DMICP_META_START_SECTOR;
	region.count = DMICP_BYTES_TO_SECTOR(round_up(len,
				DMICP_SECTOR_SIZE));

	req.mem.type = DM_IO_VMA;
	req.mem.offset = 0;
	req.mem.ptr.addr = info->meta_bitmap;
	req.notify.fn = NULL;
	req.client = info->io_client;

	blk_start_plug(&plug);
	if (new) {
		memset(info->meta_bitmap, 0, len);
		req.bi_op = REQ_OP_WRITE;
		req.bi_op_flags = REQ_FUA;
		ret = dm_io(&req, 1, &region, &io_error);
	} else {
		req.bi_op = REQ_OP_READ;
		req.bi_op_flags = READ;
		ret = dm_io(&req, 1, &region, &io_error);
	}
	blk_finish_plug(&plug);

	if (ret || io_error) {
		info->ti->error = "Access metadata error";
		return -EIO;
	}

	if (info->write_mode == DMICP_WRITE_BACK) {
		info->writeback_tsk = kthread_run(
			dm_icomp_meta_writeback_thread,
			info, "dm_icomp_writeback");
		if (!info->writeback_tsk) {
			info->ti->error = "Create writeback thread error";
			return -EINVAL;
		}
	}

	return 0;
}

/***** END metadata logic *****/


#define SET_REQ_STAGE(req, value) (req->stage = value)
#define GET_REQ_STAGE(req) req->stage


static void print_max_sectors_possible(struct dm_icomp_info *info)
{
	u64 total_blocks, data_blocks, meta_blocks, no_pairs;
	u32 pair_blocks, rem;

	/* superblock takes away one block */
	total_blocks = DMICP_BYTES_TO_BLOCK(i_size_read(
				info->dev->bdev->bd_inode)) - 1;

	/* number of datablocks representable by one metadata block. */
	data_blocks  = div64_long((DMICP_BLOCK_SIZE * 8),
			 DMICP_META_BITS);
	meta_blocks  = 1; /* we need this one meta data block for sure. */


	/* how many such pairing can we make ? */
	pair_blocks  = data_blocks + meta_blocks;
	no_pairs     = div64_long(total_blocks, pair_blocks);

	/*
	 * these many datablocks and these many ..
	 * metadatablocks will support each other.
	 */
	data_blocks  *= no_pairs;
	meta_blocks  *= no_pairs;

	div_u64_rem(total_blocks, pair_blocks, &rem);
	if (rem) {
		/* we have some remaining blocks.
		 * give one to meta and remaining to data.
		 */
		meta_blocks++;
		data_blocks += (rem - 1);
	}

	DMINFO(" This device can accommodate at most %llu sector ",
		DMICP_BLOCK_TO_SECTOR(data_blocks));
}


/*
 * create a new super block and initialize its contents.
 */
static int dm_icomp_read_or_create_super(struct dm_icomp_info *info)
{
	void *addr, *bitmap_addr;
	struct dm_icomp_super_block *super;
	u64 total_blocks, data_blocks, meta_blocks;
	bool new_super = false;
	int ret;
	ssize_t len;

	info->total_sector = DMICP_BYTES_TO_SECTOR(
			i_size_read(info->dev->bdev->bd_inode));
	total_blocks = DMICP_SECTOR_TO_BLOCK(info->total_sector) - 1;

	data_blocks =  DMICP_SECTOR_TO_BLOCK(info->ti->len);
	meta_blocks =  div64_long(((data_blocks * DMICP_META_BITS) +
			((DMICP_BLOCK_SIZE * 8) - 1)), (DMICP_BLOCK_SIZE * 8));


	info->data_blocks = data_blocks;
	info->data_start = DMICP_BLOCK_TO_SECTOR(1 + meta_blocks);

	DMINFO(
	"data_start=%u data_blocks=%llu metablocks=%llu total_blocks=%llu",
		(unsigned int)info->data_start, info->data_blocks,
		meta_blocks, total_blocks);

	if (DMICP_BLOCK_TO_SECTOR(data_blocks + meta_blocks + 1)
			> info->total_sector) {
		print_max_sectors_possible(info);
		info->ti->error =
			"Insufficient sectors to satisfy requested size";
		return -ENOMEM;
	}

	addr = kzalloc(DMICP_BLOCK_SIZE+DMICP_SECTOR_SIZE, GFP_KERNEL);
	if (!addr) {
		info->ti->error = "Cannot allocate super";
		return -ENOMEM;
	}

	super = PTR_ALIGN(addr, DMICP_SECTOR_SIZE);
	ret = dm_icomp_access_super(info, super, REQ_OP_READ, REQ_FUA);
	if (ret)
		goto out;

	if (le64_to_cpu(super->magic) == DMICP_SUPER_MAGIC) {

		const char *alg_name;

		if (le64_to_cpu(super->meta_blocks) != meta_blocks ||
		    le64_to_cpu(super->data_blocks) != data_blocks) {
			info->ti->error = "Super is invalid";
			ret = -EINVAL;
			goto out;
		}

		alg_name = get_comp_name(super->comp_alg);
		if (!crypto_has_comp(alg_name, 0, 0)) {
			info->ti->error =
				"Compressor algorithm doesn't support";
			ret = -EINVAL;
			goto out;
		}
		info->comp_alg = super->comp_alg;

	} else {
		super->magic = cpu_to_le64(DMICP_SUPER_MAGIC);
		super->meta_blocks = cpu_to_le64(meta_blocks);
		super->data_blocks = cpu_to_le64(data_blocks);
		super->comp_alg = info->comp_alg;
		ret = dm_icomp_access_super(info, super, REQ_OP_WRITE,
				REQ_FUA);
		if (ret) {
			info->ti->error = "Access super fails";
			goto out;
		}
		new_super = true;
	}

	if (alloc_compressor(info)) {
		info->ti->error = "Cannot allocate compressor";
		ret = -ENOMEM;
		goto out;
	}

	info->meta_bitmap_bits = data_blocks * DMICP_META_BITS;
	len = DIV_ROUND_UP_ULL(info->meta_bitmap_bits, DMICP_BITS_PER_ENTRY);
	len *= (DMICP_BITS_PER_ENTRY >> 3);
	info->meta_bitmap_pages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	bitmap_addr = vzalloc((info->meta_bitmap_pages * PAGE_SIZE) +
				DMICP_SECTOR_SIZE);
	if (!bitmap_addr) {
		info->ti->error = "Cannot allocate bitmap";
		ret = -ENOMEM;
		goto bitmap_err;
	}
	info->meta_bitmap = PTR_ALIGN(bitmap_addr, DMICP_SECTOR_SIZE);

	ret = dm_icomp_init_meta(info, new_super);
	if (ret)
		goto meta_err;

	return 0;
meta_err:
	vfree(bitmap_addr);
bitmap_err:
	free_compressor(info);
out:
	kfree(addr);
	return ret;
}

enum {
	Opt_wb, Opt_wt, Opt_dev, Opt_critical, Opt_compressor, Opt_err
};

static const match_table_t dm_icomp_tokens = {
	{Opt_wb, "writeback=%u"},
	{Opt_wb, "writeback:%u"},
	{Opt_dev, "device:%s"},
	{Opt_dev, "device=%s"},
	{Opt_wt, "writethrough"},
	{Opt_critical, "critical"},
	{Opt_compressor, "compressor=%s"},
	{Opt_compressor, "compressor:%s"},
	{Opt_err, NULL}
};

static char *generate_cmdline(unsigned int argc, char **argv)
{
	int i, len = 0;
	char *cmdline;

	for (i = 0 ; i < argc; i++)
		len += strlen(argv[i]);
	cmdline = kmalloc(len+1, GFP_KERNEL);
	if (!cmdline)
		return NULL;

	cmdline[0] = '\0';
	for (i = 0 ; i < argc; i++)
		strcat(cmdline, argv[i]);

	return cmdline;
}


/*
 *	<device>:<path to device> ||  <device>=<path to device>,
 *	[ <writeback>=<meta_commit_delay> ],
 *	[ <writeback>:<meta_commit_delay> ],
 *	[ <writethrough> ],
 *	[ <compressor>=<type> ],
 *	[ <compressor>:<type> ],
 *	[ <critical> ]
 */
static int dm_icomp_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dm_icomp_info *info;
	substring_t args[MAX_OPT_ARGS];
	char *cmdline = NULL, *mode, *device = NULL;
	int ret, i;
	char *p;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ti->error = "dm-inplace-compress: Cannot allocate context";
		return -ENOMEM;
	}

	cmdline = generate_cmdline(argc, argv);
	if (!cmdline) {
		ti->error = "dm-inplace-compress: Cannot allocate memory";
		goto err_para;
	}

	info->ti = ti;
	info->comp_alg = get_default_compressor();
	info->critical = false;

	while ((p = strsep(&cmdline, ",")) != NULL) {

		int token;

		if (!*p)
			continue;

		token = match_token(p, dm_icomp_tokens, args);

		switch (token) {
		case Opt_wb:
			if (match_int(&args[0], &info->writeback_delay)) {
				ti->error = "Invalid argument";
				ret = -EINVAL;
				goto err_para;
			}
			info->write_mode = DMICP_WRITE_BACK;
			break;

		case Opt_wt:
			info->write_mode = DMICP_WRITE_THROUGH;
			break;

		case Opt_dev:
			device = match_strdup(&args[0]);
			break;

		case Opt_critical:
			info->critical = true;
			break;

		case Opt_compressor:
			mode = match_strdup(&args[0]);
			if (!mode) {
				ti->error = "Invalid argument for compressor";
				ret = -EINVAL;
				goto err_para;
			}
			DMINFO("compressor  is %s", mode);
			ret = get_comp_id(mode);
			kfree(mode);
			if (ret < 0) {
				ti->error = "Unsupported compressor";
				ret = -EINVAL;
				goto err_para;
			}
			info->comp_alg = ret;
			break;
		}
	}

	if (!device ||
		dm_get_device(ti, device, dm_table_get_mode(ti->table),
			&info->dev)) {
		ti->error = "Can't get device";
		ret = -EINVAL;
		goto err_para;
	}
	kfree(device);

	info->io_client = dm_io_client_create();
	if (!info->io_client) {
		ti->error = "Can't create io client";
		ret = -EINVAL;
		goto err_ioclient;
	}

	if (bdev_logical_block_size(info->dev->bdev) != DMICP_SECTOR_SIZE) {
		ti->error = "Can't logical block size too big";
		ret = -EINVAL;
		goto err_blocksize;
	}

	if (dm_set_target_max_io_len(ti, DMICP_MAX_SECTORS)) {
		ti->error = "Failed to configure device ";
		ret = -EINVAL;
		goto err_blocksize;
	}

	if (dm_icomp_read_or_create_super(info)) {
		ret = -EINVAL;
		goto err_blocksize;
	}

	for (i = 0; i < BITMAP_HASH_LEN; i++) {
		info->bitmap_locks[i].io_running = 0;
		spin_lock_init(&info->bitmap_locks[i].wait_lock);
		INIT_LIST_HEAD(&info->bitmap_locks[i].wait_list);
	}

	kfree(cmdline);
	atomic64_set(&info->compressed_write_size, 0);
	atomic64_set(&info->uncompressed_write_size, 0);
	atomic64_set(&info->meta_write_size, 0);
	atomic64_set(&dm_icomp_total_alloc_size, 0);
	atomic64_set(&dm_icomp_total_bio_save, 0);

	ti->num_flush_bios = 1;
	ti->private = info;
	return 0;

err_blocksize:
	dm_io_client_destroy(info->io_client);
err_ioclient:
	dm_put_device(ti, info->dev);
err_para:
	kfree(cmdline);
	kfree(info);
	return ret;
}

static void dm_icomp_dtr(struct dm_target *ti)
{
	struct dm_icomp_info *info = ti->private;

	if (info->write_mode == DMICP_WRITE_BACK)
		kthread_stop(info->writeback_tsk);
	free_compressor(info);
	vfree(info->meta_bitmap);
	dm_io_client_destroy(info->io_client);
	dm_put_device(ti, info->dev);
	kfree(info);
}

/*
 * return the range lock to this block.
 */
static struct dm_icomp_hash_lock *dm_icomp_block_hash_lock(
		struct dm_icomp_info *info, u64 block_index)
{
	return &info->bitmap_locks[(block_index >> BITMAP_HASH_SHIFT) &
			BITMAP_HASH_MASK];
}

/*
 * unlock the io range correspondingg to this block.
 */
static struct dm_icomp_hash_lock *dm_icomp_trylock_block(
		struct dm_icomp_info *info,
		struct dm_icomp_req *req, u64 block_index)
{
	struct dm_icomp_hash_lock *hash_lock;

	hash_lock = dm_icomp_block_hash_lock(req->info, block_index);

	spin_lock_irq(&hash_lock->wait_lock);
	if (!hash_lock->io_running) {
		hash_lock->io_running = 1;
		spin_unlock_irq(&hash_lock->wait_lock);
		return hash_lock;
	}
	list_add_tail(&req->sibling, &hash_lock->wait_list);
	spin_unlock_irq(&hash_lock->wait_lock);
	return NULL;
}

static void dm_icomp_queue_req_list(struct dm_icomp_info *info,
	 struct list_head *list);

static void dm_icomp_unlock_block(struct dm_icomp_info *info,
	struct dm_icomp_req *req, struct dm_icomp_hash_lock *hash_lock)
{
	LIST_HEAD(pending_list);
	unsigned long flags;

	spin_lock_irqsave(&hash_lock->wait_lock, flags);
	/* wakeup all pending reqs to avoid live lock */
	list_splice_init(&hash_lock->wait_list, &pending_list);
	hash_lock->io_running = 0;
	spin_unlock_irqrestore(&hash_lock->wait_lock, flags);

	dm_icomp_queue_req_list(info, &pending_list);
}

/*
 * lock all the range locks corresponding to this io request.
 */
static int dm_icomp_lock_req_range(struct dm_icomp_req *req)
{
	u64 block_index, first_block_index;
	u64 first_lock_block, second_lock_block;
	u16 logical_sectors, data_sectors;

	block_index = DMICP_SECTOR_TO_BLOCK(req->bio->bi_iter.bi_sector);
	req->locks[0] = dm_icomp_trylock_block(req->info, req, block_index);
	if (!req->locks[0])
		return 0;
	dm_icomp_get_extent(req->info, block_index, &first_block_index,
				&logical_sectors, &data_sectors);
	if (dm_icomp_block_hash_lock(req->info, first_block_index) !=
						req->locks[0]) {
		dm_icomp_unlock_block(req->info, req, req->locks[0]);
		first_lock_block = first_block_index;
		second_lock_block = block_index;
		goto two_locks;
	}

	block_index = DMICP_SECTOR_TO_BLOCK(bio_end_sector(req->bio) - 1);
	dm_icomp_get_extent(req->info, block_index, &first_block_index,
				&logical_sectors, &data_sectors);
	first_block_index += DMICP_SECTOR_TO_BLOCK(logical_sectors);
	if (dm_icomp_block_hash_lock(req->info, first_block_index) !=
						req->locks[0]) {
		second_lock_block = first_block_index;
		goto second_lock;
	}
	req->locked_locks = 1;
	return 1;

two_locks:
	req->locks[0] = dm_icomp_trylock_block(req->info, req,
		first_lock_block);
	if (!req->locks[0])
		return 0;
second_lock:
	req->locks[1] = dm_icomp_trylock_block(req->info, req,
				second_lock_block);
	if (!req->locks[1]) {
		dm_icomp_unlock_block(req->info, req, req->locks[0]);
		return 0;
	}
	/* Don't need check if meta is changed */
	req->locked_locks = 2;
	return 1;
}



/*
 * unlock all the range locks corresponding to this io request.
 */
static void dm_icomp_unlock_req_range(struct dm_icomp_req *req)
{
	int i;

	for (i = req->locked_locks - 1; i >= 0; i--)
		dm_icomp_unlock_block(req->info, req, req->locks[i]);
}

static void dm_icomp_queue_req(struct dm_icomp_info *info,
		struct dm_icomp_req *req)
{
	unsigned long flags;
	struct dm_icomp_io_worker *worker = &dm_icomp_io_workers[req->cpu];

	spin_lock_irqsave(&worker->lock, flags);
	list_add_tail(&req->sibling, &worker->pending);
	spin_unlock_irqrestore(&worker->lock, flags);

	queue_work_on(req->cpu, dm_icomp_wq, &worker->work);
}

static void dm_icomp_queue_req_list(struct dm_icomp_info *info,
		struct list_head *list)
{
	struct dm_icomp_req *req;

	while (!list_empty(list)) {
		req = list_first_entry(list, struct dm_icomp_req, sibling);
		list_del_init(&req->sibling);
		dm_icomp_queue_req(info, req);
	}
}

static void dm_icomp_get_req(struct dm_icomp_req *req)
{
	atomic_inc(&req->io_pending);
}

static void *dm_icomp_kmalloc(size_t size, int alloc_flag)
{
	void *addr = kmalloc(size, alloc_flag);

	if (!addr)
		return NULL;
	DMICP_ALLOC(size);
	return addr;
}

static void *dm_icomp_krealloc(void *ptr, size_t size,
		size_t origsize, int alloc_flag)
{
	void *addr = krealloc(ptr, size, alloc_flag);

	if (!addr)
		return NULL;
	DMICP_FREE_ALLOC(origsize);
	DMICP_ALLOC(size);
	return addr;
}

static int dm_icomp_alloc_compbuffer(struct dm_icomp_io_range *io, int size)
{
	int alloc_len = size + DMICP_SECTOR_SIZE;
	void *addr = dm_icomp_kmalloc(alloc_len,
			get_alloc_flag(io->req->info));

	if (!addr)
		return 1;

	io->comp_real_data = addr;
	io->comp_kmap	= false;
	io->comp_len	= size;

	/*
	 * comp_data is used to read and write from storage.
	 * So align it.
	 */
	io->comp_data   = io->io_req.mem.ptr.addr
			= PTR_ALIGN(addr, DMICP_SECTOR_SIZE);

	return 0;
}

static int dm_icomp_realloc_comp_buffer(struct dm_icomp_io_range *io, int size)
{
	void *addr = dm_icomp_krealloc(io->comp_real_data,
			size+DMICP_SECTOR_SIZE, io->comp_len+DMICP_SECTOR_SIZE,
				get_alloc_flag(io->req->info));
	if (!addr)
		return 1;

	io->comp_real_data = addr;
	io->comp_kmap	   = false;
	io->comp_data      = io->io_req.mem.ptr.addr = PTR_ALIGN(addr,
				DMICP_SECTOR_SIZE);
	io->comp_len	   = size;
	return 0;
}

static void dm_icomp_kfree(void *addr, unsigned int size)
{
	kfree(addr);
	DMICP_FREE_ALLOC(size);
}

static void dm_icomp_release_decomp_buffer(struct dm_icomp_io_range *io)
{
	if (!io->decomp_data)
		return;

	if (io->decomp_kmap)
		kunmap(io->decomp_real_data);
	else
		dm_icomp_kfree(io->decomp_real_data, io->decomp_len);

	io->decomp_data = io->decomp_real_data = NULL;
	io->decomp_len  = 0;
	io->decomp_kmap = false;
}

static void dm_icomp_release_comp_buffer(struct dm_icomp_io_range *io)
{
	if (!io->comp_data)
		return;

	if (io->comp_kmap)
		kunmap(io->comp_real_data);
	else
		dm_icomp_kfree(io->comp_real_data,
			io->comp_len+DMICP_SECTOR_SIZE);

	io->comp_real_data = io->comp_data = NULL;
	io->comp_len = 0;
	io->comp_kmap = false;
}

static void dm_icomp_free_io_range(struct dm_icomp_io_range *io)
{
	dm_icomp_release_decomp_buffer(io);
	dm_icomp_release_comp_buffer(io);
	kmem_cache_free(dm_icomp_io_range_cachep, io);
}

static void dm_icomp_put_req(struct dm_icomp_req *req)
{
	struct dm_icomp_io_range *io;

	if (atomic_dec_return(&req->io_pending))
		return;

	if (GET_REQ_STAGE(req) == STAGE_INIT) /* waiting for locking */
		return;

	if (GET_REQ_STAGE(req) == STAGE_READ_DECOMP ||
	    GET_REQ_STAGE(req) == STAGE_WRITE_COMP)
		SET_REQ_STAGE(req, STAGE_DONE);

	if (!!!req->result && GET_REQ_STAGE(req) != STAGE_DONE) {
		dm_icomp_queue_req(req->info, req);
		return;
	}

	while (!list_empty(&req->all_io)) {
		io = list_entry(req->all_io.next,
			struct dm_icomp_io_range, next);
		list_del(&io->next);
		dm_icomp_free_io_range(io);
	}

	dm_icomp_unlock_req_range(req);

	req->bio->bi_status = req->result;

	bio_endio(req->bio);
	kmem_cache_free(dm_icomp_req_cachep, req);
}

static void dm_icomp_bio_copy(struct bio *bio, off_t bio_off, void *buf,
		ssize_t len, bool to_buf)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	off_t buf_off = 0;
	ssize_t size;
	void *addr;

	WARN_ON(bio_off + len > DMICP_SECTOR_TO_BYTES(bio_sectors(bio)));

	bio_for_each_segment(bv, bio, iter) {
		int length = bv.bv_len;

		if (bio_off > length) {
			bio_off -= length;
			continue;
		}
		addr = kmap_atomic(bv.bv_page);
		size = min_t(ssize_t, len, length - bio_off);
		if (!buf)
			memset(addr + bio_off + bv.bv_offset, 0, size);
		else if (to_buf)
			memcpy(buf + buf_off, addr + bio_off + bv.bv_offset,
				size);
		else
			memcpy(addr + bio_off + bv.bv_offset, buf + buf_off,
				size);
		kunmap_atomic(addr);
		bio_off = 0;
		buf_off += size;

		if (len <= size)
			break;

		len -= size;
	}
}

static void dm_icomp_io_range_done(unsigned long error, void *context)
{
	struct dm_icomp_io_range *io = context;

	if (error)
		io->req->result = error;

	dm_icomp_put_req(io->req);
}

static inline int dm_icomp_compressor_len(struct dm_icomp_info *info, int len)
{
	if (compressors[info->comp_alg].comp_len)
		return compressors[info->comp_alg].comp_len(len);
	return len;
}

static inline bool dm_icomp_can_handle_overflow(struct dm_icomp_info *info)
{
	return compressors[info->comp_alg].can_handle_overflow;
}

static inline int dm_icomp_compressor_maxlen(struct dm_icomp_info *info,
		int len)
{
	if (compressors[info->comp_alg].max_comp_len)
		return compressors[info->comp_alg].max_comp_len(len);
	return len;
}

/*
 * caller should set region.sector, region.count. bi_rw. IO always to/from
 * comp_data
 */
static struct dm_icomp_io_range *dm_icomp_create_io_range(
		struct dm_icomp_req *req)
{
	struct dm_icomp_io_range *io;

	io = kmem_cache_alloc(dm_icomp_io_range_cachep,
			get_alloc_flag(req->info));
	if (!io)
		return NULL;

	io->io_req.notify.fn = dm_icomp_io_range_done;
	io->io_req.notify.context = io;
	io->io_req.client = req->info->io_client;
	io->io_req.mem.type = DM_IO_KMEM;
	io->io_req.mem.offset = 0;

	io->io_region.bdev = req->info->dev->bdev;
	io->req = req;

	io->comp_data = io->comp_real_data =
			io->decomp_data = io->decomp_real_data = NULL;

	io->data_bytes = io->comp_len =
			io->decomp_len = io->logical_bytes = 0;

	io->comp_kmap = io->decomp_kmap = false;
	return io;
}


/*
 * return an address, within the bio. The address corresponds to
 * the requested offset 'bio_off' and is contiguous of size 'len'
 */
static void *get_addr(struct bio *bio,  int len, u64 bio_off, u64 *offset)
{
	struct bio_vec bv;
	struct bvec_iter iter;

	bio_for_each_segment(bv, bio, iter) {

		if (bio_off <= bv.bv_len) {
			if ((bio_off + len) > bv.bv_len)
				break;
			*offset = bv.bv_offset + bio_off;
			return kmap(bv.bv_page);
		}
                bio_off -= bv.bv_len;

	}
	return NULL;
}


/*
 * create a io range for tracking  predominantly a read request.
 * @req		: the read request
 * @comp_len	: allocation size of the compress buffer
 * @decomp_len	: allocation size of the decompress buffer
 * @actual_comp_len : real size of the compress data
 * @bio_off	: offset within the bio read buffer this request corresponds to.
 *		try to reuse and read into the bio buffer. -1 means don't reuse.
 */
static struct dm_icomp_io_range *dm_icomp_create_io_read_range(
		struct dm_icomp_req *req, int comp_len, int decomp_len,
		sector_t bio_off, int actual_comp_len)
{
	struct bio *bio = req->bio;
	void *addr = NULL;
	struct dm_icomp_io_range *io = dm_icomp_create_io_range(req);
	u64 offset;

	if (!io)
		return NULL;

	/* try reusing the bio if possible */
	if (bio_off >= 0) {
		addr = get_addr(bio, comp_len,
				(u64)DMICP_SECTOR_TO_BYTES(bio_off), &offset);
		if (addr) {
			io->comp_real_data =  addr;
			io->comp_data = io->io_req.mem.ptr.addr = addr + offset;
			io->comp_kmap = true;
			io->comp_len  = comp_len;
		}
	}

	if (!addr && dm_icomp_alloc_compbuffer(io, comp_len)) {
		kmem_cache_free(dm_icomp_io_range_cachep, io);
		return NULL;
	}

	io->data_bytes	= actual_comp_len;  /* NOTE, this value can change */

	/*
	 * note requested length for decompress buffer. Do not allocate it yet.
	 * Value once set is final.
	 */
	io->logical_bytes = decomp_len;

	return io;
}

/*
 *  ensure that the io range has all its buffers; of the correct size,
 *  allocated.
 */
static int dm_icomp_update_io_read_range(struct dm_icomp_io_range *io)
{
	WARN_ON(!io->comp_data);
	WARN_ON(io->decomp_data || io->decomp_len);
	io->decomp_data = dm_icomp_kmalloc(io->logical_bytes,
				get_alloc_flag(io->req->info));
	if (!io->decomp_data)
		return 1;
	io->decomp_real_data = io->decomp_data;
	io->decomp_len = io->logical_bytes;
	io->decomp_kmap = false;
	return 0;
}

/*
 *  resize the comp buffer to its largest possible size.
 */
static int dm_icomp_mod_to_max_io_range(struct dm_icomp_io_range *io)
{
	unsigned int maxlen = dm_icomp_compressor_maxlen(io->req->info,
				io->logical_bytes);

	if (maxlen <= io->comp_len)
		return 0;

	if (io->comp_kmap) {
		WARN_ON(io->comp_kmap);
		kunmap(io->comp_real_data);
		io->comp_kmap = false;
		io->comp_real_data = io->comp_data = NULL;
	}

	if (dm_icomp_realloc_comp_buffer(io, maxlen)) {
		io->comp_len = 0;
		return -ENOSPC;
	}
	io->comp_len = maxlen;
	return 0;
}

/*
 * create a io range for tracking a write request.
 * @req		: the write request
 * @count	: size of the write in sectors.
 * @offset	: offset within the bio read buffer this request correspond to.
 */
static struct dm_icomp_io_range *dm_icomp_create_io_write_range(
	struct dm_icomp_req *req, sector_t offset, sector_t count)
{
	struct bio *bio = req->bio;
	int size  = DMICP_SECTOR_TO_BYTES(count);
	u64 of;
	int comp_len = dm_icomp_compressor_len(req->info, size);
	void *addr;
	struct dm_icomp_io_range *io = dm_icomp_create_io_range(req);

	if (!io)
		return NULL;

	WARN_ON(io->comp_data);

	if (dm_icomp_alloc_compbuffer(io, comp_len)) {
		kmem_cache_free(dm_icomp_io_range_cachep, io);
		return NULL;
	}

	/* we donot know the size of the compress segment yet. */
	io->data_bytes = 0;


	WARN_ON(io->decomp_data);

	io->decomp_kmap = false;

	/* try reusing the bio buffer for decomp data. */
	addr = get_addr(bio, size, DMICP_SECTOR_TO_BYTES(offset), &of);
	if (addr)
		io->decomp_kmap = true;
	else
		addr  = dm_icomp_kmalloc(size, get_alloc_flag(req->info));

	if (!addr) {
		dm_icomp_kfree(io->comp_data, comp_len);
		kmem_cache_free(dm_icomp_io_range_cachep, io);
		return NULL;
	}

	io->logical_bytes = io->decomp_len = size;

	if (io->decomp_kmap) {
		io->decomp_real_data = addr;
		io->decomp_data = addr + of;
		DMICP_ALLOC_SAVE(size);
	} else {
		io->decomp_data = io->decomp_real_data = addr;
		dm_icomp_bio_copy(req->bio, DMICP_SECTOR_TO_BYTES(offset),
			io->decomp_data, size, true);
	}

	return io;
}

static unsigned int round_to_next_sector(unsigned int val)
{
	unsigned int c = round_up(val, DMICP_SECTOR_SIZE);

	if ((c - val) < 2*sizeof(u32))
		c += DMICP_SECTOR_SIZE;
	return c;
}

/*
 * compress and store the data in compress buffer.
 * return value:
 * < 0 : error
 * == 0 : ok
 * == 1 : ok, but comp/decomp is skipped
 * Compressed data size is roundup of DMICP_SECTOR_SIZE, which makes
 * the payload.
 * We store the actual compressed len in the last u32 of the payload.
 * If there is  no  free  space,  we  add  DMICP_SECTOR_SIZE  to the
 * payload size.
 */
static int dm_icomp_io_range_compress(struct dm_icomp_info *info,
		struct dm_icomp_io_range *io, unsigned int *comp_len)
{
	unsigned int actual_comp_len = io->comp_len;
	u32 *addr;
	struct crypto_comp *tfm =  info->tfm[get_cpu()];
	unsigned int decomp_len = io->logical_bytes;
	int ret;

	actual_comp_len = io->comp_len;
	ret = crypto_comp_compress(tfm, io->decomp_data, decomp_len,
		io->comp_data, &actual_comp_len);

	if (ret || round_to_next_sector(actual_comp_len) > io->comp_len) {
		ret = dm_icomp_mod_to_max_io_range(io);
		if (!ret) {
			actual_comp_len = io->comp_len;
			ret = crypto_comp_compress(tfm, io->decomp_data,
				decomp_len, io->comp_data,
				&actual_comp_len);
		}
	}

	put_cpu();

	if (!ret)
		*comp_len = round_to_next_sector(actual_comp_len);

	if (ret || *comp_len >= decomp_len) {
		WARN_ON(decomp_len > io->comp_len);
		*comp_len = decomp_len;
		memcpy(io->comp_data, io->decomp_data, decomp_len);
		atomic64_add(*comp_len, &info->compressed_write_size);
	} else {
		addr = (u32 *)((char *)io->comp_data + *comp_len);
		addr--;
		*addr = cpu_to_le32(actual_comp_len);
		addr--;
		*addr = cpu_to_le32(DMICP_COMPRESS_MAGIC);
	}
	io->data_bytes = *comp_len;
	atomic64_add(decomp_len, &info->uncompressed_write_size);
	atomic64_add(*comp_len, &info->compressed_write_size);

	return 0;
}

/*
 * decompress and store the data in decompress buffer.
 * return value:
 * < 0 : error
 * == 0 : ok
 */
static int dm_icomp_io_range_decompress(struct dm_icomp_info *info,
		struct dm_icomp_io_range *io, unsigned int *decomp_len)
{
	struct crypto_comp *tfm;
	u32 *addr;
	int ret;
	int comp_len = io->data_bytes;

	WARN_ON(!comp_len);
	WARN_ON(io->comp_data != io->io_req.mem.ptr.addr);

	if (comp_len == io->logical_bytes) {
		memcpy(io->decomp_data, io->comp_data, comp_len);
		*decomp_len = comp_len;
		return 0;
	}

	addr = (u32 *)((char *)(io->comp_data) + comp_len);
	addr--;
	comp_len = le32_to_cpu(*addr);
	addr--;

	if (le32_to_cpu(*addr) != DMICP_COMPRESS_MAGIC) {
		DMWARN("Decompress Error ");
		return -EINVAL;
	}

	tfm = info->tfm[get_cpu()];
	*decomp_len = io->logical_bytes;
	ret = crypto_comp_decompress(tfm, io->comp_data, comp_len,
		io->decomp_data, decomp_len);
	WARN_ON(*decomp_len != io->decomp_len);
	put_cpu();

	return ret;
}

/*
 *  fill the bio with the corresponding decompressed data.
 */
static void dm_icomp_handle_read_decomp(struct dm_icomp_req *req)
{
	struct dm_icomp_io_range *io;
	off_t bio_off = 0;
	int ret;
	sector_t bio_len  = DMICP_SECTOR_TO_BYTES(bio_sectors(req->bio));

	SET_REQ_STAGE(req, STAGE_READ_DECOMP);

	if (req->result)
		return;

	list_for_each_entry(io, &req->all_io, next) {
		ssize_t dst_off = 0, src_off = 0, len;
		unsigned int decomp_len;

		io->io_region.sector -= req->info->data_start;

		if (io->io_region.sector >=
				req->bio->bi_iter.bi_sector)
			dst_off = DMICP_SECTOR_TO_BYTES(
				io->io_region.sector -
				req->bio->bi_iter.bi_sector);
		else
			src_off = DMICP_SECTOR_TO_BYTES(
				req->bio->bi_iter.bi_sector -
				io->io_region.sector);

		if (dm_icomp_update_io_read_range(io)) {
			req->result = -EIO;
			return;
		}

		/* Do decomp here */
		ret = dm_icomp_io_range_decompress(req->info, io, &decomp_len);
		if (ret < 0) {
			req->result = ret;
			goto out;
		}

		len = min_t(ssize_t,
			max_t(ssize_t, decomp_len - src_off, 0),
			max_t(ssize_t, bio_len - dst_off, 0));

		dm_icomp_bio_copy(req->bio, dst_off,
			   io->decomp_data + src_off, len, false);

		dm_icomp_release_decomp_buffer(io);
		dm_icomp_release_comp_buffer(io);

		/* io range in all_io list is ordered for read IO */
		while (bio_off < dst_off) {
			ssize_t size = min_t(ssize_t, PAGE_SIZE,
					dst_off - bio_off);
			dm_icomp_bio_copy(req->bio, bio_off, NULL,
					size, false);
			bio_off += size;
		}

		bio_off = dst_off + len;
	}

	while (bio_off < bio_len) {
		ssize_t size = min_t(ssize_t, PAGE_SIZE, (bio_len - bio_off));

		dm_icomp_bio_copy(req->bio, bio_off, NULL,
			size, false);
		bio_off += size;
	}
	return;

out:
	list_for_each_entry(io, &req->all_io, next) {
		dm_icomp_release_decomp_buffer(io);
		dm_icomp_release_comp_buffer(io);
	}
}


/*
 * read an extent
 * @req        : the read request
 * @block      : the block to be read
 * @logical_sectors   : no of sectors occupied by the decompressed data
 * @data_sectors      : no of sectors occupied by the compressed data
 * @may_resize : the compress data size may change during its life.
 */
static void dm_icomp_read_one_extent(struct dm_icomp_req *req, u64 block,
	u16 logical_sectors, u16 data_sectors, bool may_resize)
{
	struct dm_icomp_io_range *io;
	sector_t offset = 0;
	int comp_len;
	int actual_comp_len = DMICP_SECTOR_TO_BYTES(data_sectors);
	int actual_decomp_len = DMICP_SECTOR_TO_BYTES(logical_sectors);

	comp_len = actual_comp_len;

	offset	 =  (may_resize) ? -1 :
			 DMICP_BLOCK_TO_SECTOR(block) -
				req->bio->bi_iter.bi_sector;

	io = dm_icomp_create_io_read_range(req, comp_len,
		actual_decomp_len,
		offset,
		actual_comp_len);
	if (!io) {
		req->result = -ENOMEM;
		return;
	}

	dm_icomp_get_req(req);
	list_add_tail(&io->next, &req->all_io);

	io->io_region.sector = DMICP_BLOCK_TO_SECTOR(block) +
				req->info->data_start;
	io->io_region.count = data_sectors;
	io->io_req.mem.ptr.addr = io->comp_data;
	io->io_req.mem.type = DM_IO_KMEM;
	io->io_req.mem.offset = 0;
	io->io_req.bi_op = REQ_OP_READ;
	io->io_req.bi_op_flags = (req->bio->bi_opf & REQ_FUA);

	WARN_ON((io->io_region.sector + io->io_region.count)
		>= req->info->total_sector);

	dm_io(&io->io_req, 1, &io->io_region, NULL);
}

static bool is_full_overlap(struct dm_icomp_req *req,
               u64 first_sector, u16 logical_sectors)
{
	u64 bio_first_sector = req->bio->bi_iter.bi_sector;
	u64 bio_last_sector = bio_end_sector(req->bio)-1;
	u64 last_sector = first_sector + logical_sectors -1;

	return ((bio_first_sector <= first_sector) &&
		(bio_last_sector >= last_sector));
}

/*
 * read the data corresponding to this request.
 * @req   : the request.
 * @reuse : the read data may be modified. So plan accordingly.
 */
static void dm_icomp_handle_read_existing(struct dm_icomp_req *req, bool reuse)
{
	u64 block_index, first_block_index;
	u16 logical_sectors, data_sectors;

	SET_REQ_STAGE(req, STAGE_READ_EXISTING);

	block_index = DMICP_SECTOR_TO_BLOCK(req->bio->bi_iter.bi_sector);

	while (!!!req->result &&
		(block_index <= DMICP_SECTOR_TO_BLOCK(
				bio_end_sector(req->bio)-1)) &&
		(block_index < req->info->data_blocks)) {

		dm_icomp_get_extent(req->info, block_index, &first_block_index,
			&logical_sectors, &data_sectors);

		block_index = first_block_index +
				DMICP_SECTOR_TO_BLOCK(logical_sectors);

		if (!data_sectors)
			continue;


		/* no point reading in data that will anyway be overwritten */
		if (reuse && is_full_overlap(req,
			DMICP_BLOCK_TO_SECTOR(first_block_index),
				logical_sectors))
			continue;

		dm_icomp_read_one_extent(req, first_block_index,
				logical_sectors, data_sectors, reuse);

	}
}

/*
 * read existing data
 */
static void dm_icomp_handle_read_read_existing(struct dm_icomp_req *req)
{
	dm_icomp_handle_read_existing(req, false);

	if (req->result)
		return;

	/* A shortcut if all data is in already */
	if (list_empty(&req->all_io))
		dm_icomp_handle_read_decomp(req);
}

static void dm_icomp_handle_read_request(struct dm_icomp_req *req)
{
	dm_icomp_get_req(req);

	if (GET_REQ_STAGE(req) == STAGE_INIT && dm_icomp_lock_req_range(req))
		dm_icomp_handle_read_read_existing(req);
	else if (GET_REQ_STAGE(req) == STAGE_READ_EXISTING)
		dm_icomp_handle_read_decomp(req);

	dm_icomp_put_req(req);
}

static void dm_icomp_write_meta_done(void *context, unsigned long error)
{
	struct dm_icomp_req *req = context;

	dm_icomp_put_req(req);
}

static u64 dm_icomp_block_meta_page_index(u64 block, bool end)
{
	u64 bits = block * DMICP_META_BITS - !!end;
	/*
	 * >> 5; 32 bits per entry
	 * << 2; each entry is 4 bytes
	 * >> PAGE_SHIFT; PAGE_SHIFT pages
	 */
	return bits >> (5 - 2 + PAGE_SHIFT);
}


/*
 * write compressed data to the backing storage.
 * @io : io range
 * @sector_start : the sector on backing storage to which the
 *	compressed data needs to be written.
 * @meta_start: the page index of the bits corresponding to
 * @meta_end  : start and end blocks.
 */
static int dm_icomp_compress_write(struct dm_icomp_io_range *io,
		sector_t sector_start, u64 *meta_start, u64 *meta_end)
{
	struct dm_icomp_req *req = io->req;
	sector_t count = DMICP_BYTES_TO_SECTOR(io->decomp_len);
	unsigned int comp_len;
	int ret;
	u64 page_index;

	/* comp_data must be able to accommadate a larger compress buffer */
	ret = dm_icomp_io_range_compress(req->info, io, &comp_len);
	if (ret < 0) {
		req->result = -EIO;
		return -EIO;
	}
	WARN_ON(comp_len > io->comp_len);

	dm_icomp_get_req(req);

	io->io_req.bi_op = REQ_OP_WRITE;
	io->io_req.bi_op_flags = (req->bio->bi_opf & REQ_FUA);
	io->io_req.mem.ptr.addr = io->comp_data;
	io->io_req.mem.type = DM_IO_KMEM;
	io->io_req.mem.offset = 0;
	io->io_region.count = DMICP_BYTES_TO_SECTOR(comp_len);
	io->io_region.sector = sector_start + req->info->data_start;

	dm_icomp_release_decomp_buffer(io);


	WARN_ON((io->io_region.sector + io->io_region.count)
			>= req->info->total_sector);

	dm_io(&io->io_req, 1, &io->io_region, NULL);

	/* update the meta data bits */
	dm_icomp_set_extent(req, DMICP_SECTOR_TO_BLOCK(sector_start),
		DMICP_SECTOR_TO_BLOCK(count), DMICP_BYTES_TO_SECTOR(comp_len));

	page_index = dm_icomp_block_meta_page_index(
		DMICP_SECTOR_TO_BLOCK(sector_start), false);
	if (*meta_start > page_index)
		*meta_start = page_index;

	page_index = dm_icomp_block_meta_page_index(
			DMICP_SECTOR_TO_BLOCK(sector_start + count), true);
	if (*meta_end < page_index)
		*meta_end = page_index;
	return 0;
}

/*
 * modify and write compressed data to the backing storage.
 * @io : io range
 * @meta_start: the page index of the bits corresponding to
 * @meta_end  : start and end blocks.
 */
static int dm_icomp_handle_write_modify(struct dm_icomp_io_range *io,
	u64 *meta_start, u64 *meta_end)
{
	struct dm_icomp_req *req = io->req;
	sector_t bio_start, bio_end, buf_start, buf_end, overlap;
	off_t bio_off, buf_off;
	int ret;
	unsigned int decomp_len;

	io->io_region.sector -= req->info->data_start;

	if (dm_icomp_update_io_read_range(io)) {
		req->result = -EIO;
		return -EIO;
	}

	/* decompress original data */
	ret = dm_icomp_io_range_decompress(req->info, io, &decomp_len);
	if (ret < 0) {
		req->result = ret;
		return ret;
	}

	bio_start = req->bio->bi_iter.bi_sector;
	bio_end = bio_end_sector(req->bio) - 1;

	buf_start = io->io_region.sector;
	buf_end = buf_start + DMICP_BYTES_TO_SECTOR(decomp_len) - 1;

	/* if no overlap, nothing to do. Just return */
	if (bio_start >= buf_end || bio_end <= buf_start)
		return 0;

	bio_off = (buf_start > bio_start) ?  (buf_start - bio_start) : 0;
	buf_off = (bio_start > buf_start) ?  (bio_start - buf_start) : 0;

	/*
	 * overlap = sizeof(block1) + sizeof(block2) - sizeof(left_side_shift) -
	 *		sizeof(right_side_shift)  / 2  +  1
	 */
	overlap  =  (((bio_end - bio_start) + (buf_end - buf_start) -
		abs(buf_end - bio_end) - abs(buf_start - bio_start)) >> 1) + 1;


	dm_icomp_bio_copy(req->bio, DMICP_SECTOR_TO_BYTES(bio_off),
		   io->decomp_data + DMICP_SECTOR_TO_BYTES(buf_off),
		   DMICP_SECTOR_TO_BYTES(overlap), true);

	if (!dm_icomp_can_handle_overflow(req->info)) {
		/* resize the compress buffer to the max range */
		ret = dm_icomp_mod_to_max_io_range(io);
		if (ret < 0) {
			req->result = ret;
			return ret;
		}
	}

	return dm_icomp_compress_write(io, io->io_region.sector,
			meta_start, meta_end);
}


/*
 * create and write new extents. Each extent is not more than
 * DMICP_MAX_SECTORS sectors.
 * @req : the request
 * @sec_start: the start sector of the request
 * @total  : the total sectors
 * @list  : collect each DMICP_MAX_SECTORS sector size io request in this list
 * @meta_start: the page index of the bits corresponding to
 * @meta_end  : start and end blocks.
 *
 */
static void dm_icomp_handle_write_create(struct dm_icomp_req *req,
	sector_t sec_start, sector_t total,
	struct list_head *list, u64 *meta_start, u64 *meta_end)
{
	struct dm_icomp_io_range *io;
	sector_t count, offset = 0;
	int ret;

	while (total) {

		/* max i/o DMICP_MAX_SECTORS sectors */
		count = min_t(sector_t, total, DMICP_MAX_SECTORS);
		io = dm_icomp_create_io_write_range(req, offset, count);
		if (!io) {
			req->result = -ENOMEM;
			return;
		}

		ret = dm_icomp_compress_write(io, sec_start, meta_start,
			meta_end);
		if (ret) {
			dm_icomp_free_io_range(io);
			return;
		}


		list_add_tail(&io->next, list);
		total -= count;
		sec_start += count;
		offset += count;

	}
}

/*
 *  handle the write request.
 */
static void dm_icomp_handle_write_comp(struct dm_icomp_req *req)
{
	struct dm_icomp_io_range *io;
	sector_t io_start, req_start, req_end;
	u64 meta_start = -1L, meta_end = 0;
	LIST_HEAD(newlist);

	SET_REQ_STAGE(req, STAGE_WRITE_COMP);

	if (req->result)
		return;

	req_start = req->bio->bi_iter.bi_sector;
	list_for_each_entry(io, &req->all_io, next) {

		io_start = io->io_region.sector - req->info->data_start;

		if (req_start < io_start) {
			/* fill the gap */
			dm_icomp_handle_write_create(req, req_start,
				(io_start - req_start), &newlist,
				&meta_start, &meta_end);
		}

		dm_icomp_handle_write_modify(io, &meta_start, &meta_end);

		req_start = io_start + DMICP_BYTES_TO_SECTOR(io->logical_bytes);
	}

	req_end =  bio_end_sector(req->bio);
	if (req_start < req_end) {
		/* fill the gap */
		dm_icomp_handle_write_create(req, req_start,
			 req_end-req_start, &newlist, &meta_start,
			&meta_end);
	}

	list_splice_tail(&newlist, &req->all_io);

	if (req->info->write_mode == DMICP_WRITE_THROUGH ||
				(req->bio->bi_opf & REQ_FUA)) {
		if (meta_start == -1)
			return;
		dm_icomp_get_req(req);
		dm_icomp_write_meta(req->info, meta_start,
			meta_end+1, req,
			dm_icomp_write_meta_done,
			REQ_OP_WRITE, req->bio->bi_opf);
	}
}

/*
 *  read the data, modify and write it back to the backing store.
 */
static void dm_icomp_handle_write_read_existing(struct dm_icomp_req *req)
{
	dm_icomp_handle_read_existing(req, true);
	if (req->result)
		return;

	if (list_empty(&req->all_io))
		dm_icomp_handle_write_comp(req);
}

static void dm_icomp_handle_write_request(struct dm_icomp_req *req)
{
	dm_icomp_get_req(req);

	if (GET_REQ_STAGE(req) == STAGE_INIT && dm_icomp_lock_req_range(req))
		dm_icomp_handle_write_read_existing(req);
	else if (GET_REQ_STAGE(req) == STAGE_READ_EXISTING)
		dm_icomp_handle_write_comp(req);

	dm_icomp_put_req(req);
}

/* For writeback mode */
static void dm_icomp_handle_flush_request(struct dm_icomp_req *req)
{
	struct writeback_flush_data wb;

	atomic_set(&wb.cnt, 1);
	init_completion(&wb.complete);

	dm_icomp_flush_dirty_meta(req->info, &wb);

	writeback_flush_io_done(&wb, 0);
	wait_for_completion(&wb.complete);

	req->bio->bi_status = 0;
	bio_endio(req->bio);
	kmem_cache_free(dm_icomp_req_cachep, req);
}

static void dm_icomp_handle_request(struct dm_icomp_req *req)
{
	if (req->bio->bi_opf & REQ_PREFLUSH)
		dm_icomp_handle_flush_request(req);
	else if (op_is_write(bio_op(req->bio)))
		dm_icomp_handle_write_request(req);
	else
		dm_icomp_handle_read_request(req);
}

static void dm_icomp_do_request_work(struct work_struct *work)
{
	struct dm_icomp_io_worker *worker = container_of(work,
				struct dm_icomp_io_worker, work);
	LIST_HEAD(list);
	struct dm_icomp_req *req;
	struct blk_plug plug;
	bool repeat;

	blk_start_plug(&plug);
again:
	spin_lock_irq(&worker->lock);
	list_splice_init(&worker->pending, &list);
	spin_unlock_irq(&worker->lock);

	repeat = !list_empty(&list);
	while (!list_empty(&list)) {
		req = list_first_entry(&list, struct dm_icomp_req, sibling);
		list_del(&req->sibling);

		schedule();
		dm_icomp_handle_request(req);
	}
	if (repeat)
		goto again;
	blk_finish_plug(&plug);
}

static bool valid_request(struct bio *bio, struct dm_icomp_info *info)
{
	sector_t dev_end	=  info->ti->len;
	sector_t req_end	=  bio_end_sector(bio) - 1;

	return (req_end <= dev_end);
}

static int dm_icomp_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_icomp_info *info = ti->private;
	struct dm_icomp_req *req;

	if ((bio->bi_opf & REQ_PREFLUSH) &&
			info->write_mode == DMICP_WRITE_THROUGH) {
		bio->bi_disk = info->dev->bdev;
		return DM_MAPIO_REMAPPED;
	}


	req = kmem_cache_alloc(dm_icomp_req_cachep, get_alloc_flag(info));
	if (!req)
		return -ENOMEM;

	req->bio = bio;
	if (!(bio->bi_opf & REQ_PREFLUSH) && !valid_request(bio, info)) {
		req->bio = bio;
		req->bio->bi_status = -EINVAL;
		bio_endio(req->bio);
		return DM_MAPIO_SUBMITTED;
	}

	req->info = info;
	atomic_set(&req->io_pending, 0);
	INIT_LIST_HEAD(&req->all_io);
	req->result = 0;
	SET_REQ_STAGE(req, STAGE_INIT);
	req->locked_locks = 0;

	req->cpu = raw_smp_processor_id();
	dm_icomp_queue_req(info, req);

	return DM_MAPIO_SUBMITTED;
}

static void dm_icomp_status(struct dm_target *ti, status_type_t type,
	  unsigned int status_flags, char *result, unsigned int maxlen)
{
	struct dm_icomp_info *info = ti->private;
	unsigned int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%ld %ld %ld",
			(long) atomic64_read(&info->uncompressed_write_size),
			(long) atomic64_read(&info->compressed_write_size),
			(long) atomic64_read(&info->meta_write_size));
		break;
	case STATUSTYPE_TABLE:
		if (info->write_mode == DMICP_WRITE_BACK)
			DMEMIT("%s %s:%d %s:%s %s:%d", info->dev->name,
				"writeback", info->writeback_delay,
				"compressor", compressors[info->comp_alg].name,
				"critical", info->critical);
		else
			DMEMIT("%s %s %s:%s %s:%d", info->dev->name,
				"writethrough",
				"compressor", compressors[info->comp_alg].name,
				"critical", info->critical);
		break;
	}
}

static int dm_icomp_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct dm_icomp_info *info = ti->private;

	return fn(ti, info->dev, info->data_start,
		DMICP_BLOCK_TO_SECTOR(info->data_blocks), data);
}

static void dm_icomp_io_hints(struct dm_target *ti,
			    struct queue_limits *limits)
{
	/* No blk_limits_logical_block_size */
	limits->logical_block_size = limits->physical_block_size =
		limits->io_min = DMICP_BLOCK_SIZE;
	limits->max_sectors = limits->max_hw_sectors =
				DMICP_MAX_SECTORS;
}

static struct target_type dm_icomp_target = {
	.name   = "inplacecompress",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr    = dm_icomp_ctr,
	.dtr    = dm_icomp_dtr,
	.map    = dm_icomp_map,
	.status = dm_icomp_status,
	.iterate_devices = dm_icomp_iterate_devices,
	.io_hints = dm_icomp_io_hints,
};

static int __init dm_icomp_init(void)
{
	int r;

	if (select_default_compressor())
		return -EINVAL;

	r = -ENOMEM;
	dm_icomp_req_cachep = kmem_cache_create("dm_icomp_requests",
		sizeof(struct dm_icomp_req), 0, 0, NULL);
	if (!dm_icomp_req_cachep) {
		DMWARN("Can't create request cache");
		goto err;
	}

	dm_icomp_io_range_cachep = kmem_cache_create("dm_icomp_io_range",
		sizeof(struct dm_icomp_io_range), 0, 0, NULL);
	if (!dm_icomp_io_range_cachep) {
		DMWARN("Can't create io_range cache");
		goto err;
	}

	dm_icomp_meta_io_cachep = kmem_cache_create("dm_icomp_meta_io",
		sizeof(struct dm_icomp_meta_io), 0, 0, NULL);
	if (!dm_icomp_meta_io_cachep) {
		DMWARN("Can't create meta_io cache");
		goto err;
	}

	dm_icomp_wq = alloc_workqueue("dm_icomp_io",
		WQ_UNBOUND|WQ_MEM_RECLAIM|WQ_CPU_INTENSIVE, 0);
	if (!dm_icomp_wq) {
		DMWARN("Can't create io workqueue");
		goto err;
	}

	r = dm_register_target(&dm_icomp_target);
	if (r < 0) {
		DMWARN("target registration failed");
		goto err;
	}

	for_each_possible_cpu(r) {
		INIT_LIST_HEAD(&dm_icomp_io_workers[r].pending);
		spin_lock_init(&dm_icomp_io_workers[r].lock);
		INIT_WORK(&dm_icomp_io_workers[r].work,
				dm_icomp_do_request_work);
	}
	return 0;
err:
	kmem_cache_destroy(dm_icomp_req_cachep);
	kmem_cache_destroy(dm_icomp_io_range_cachep);
	kmem_cache_destroy(dm_icomp_meta_io_cachep);
	if (dm_icomp_wq)
		destroy_workqueue(dm_icomp_wq);

	return r;
}

static void __exit dm_icomp_exit(void)
{
	dm_unregister_target(&dm_icomp_target);
	kmem_cache_destroy(dm_icomp_req_cachep);
	kmem_cache_destroy(dm_icomp_io_range_cachep);
	kmem_cache_destroy(dm_icomp_meta_io_cachep);
	destroy_workqueue(dm_icomp_wq);
}

module_init(dm_icomp_init);
module_exit(dm_icomp_exit);

MODULE_AUTHOR("Shaohua Li <shli@kernel.org>");
MODULE_DESCRIPTION(DM_NAME " target with data inplace-compression");
MODULE_LICENSE("GPL");
