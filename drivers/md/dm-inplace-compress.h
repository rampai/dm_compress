#ifndef __DM_INPLACE_COMPRESS_H__
#define __DM_INPLACE_COMPRESS_H__
#include <linux/types.h>

#define DMICP_SUPER_MAGIC 0x106526c206506c09
#define DMICP_COMPRESS_MAGIC 0xfaceecaf
struct dm_icomp_super_block {
	__le64 magic;
	__le64 meta_blocks;
	__le64 data_blocks;
	u8 comp_alg;
} __packed;

#define DMICP_COMP_ALG_LZ4 2
#define DMICP_COMP_ALG_LZO 1
#define DMICP_COMP_ALG_842 0

#ifdef __KERNEL__
/*
 * A block which represents the logical size of the target is 4096B.
 * Data within a block  is compressed. Compressed data; payload, is
 * round up by 512B. Payload is stored at the beginning  of logical
 * sector of the block on the disk. Last 32bit of the payload holds
 * the payload length. However if payload length is 4096B,store the
 * uncompressed data. If IO size is larger than a block,  store the
 * data as extents.  Each  block is represented  by  5bit  metadata.
 * Bit 0 - 3 captures payload length (0 - 8 sectors)for that extent.
 * Bit 4  indicates  the  head/tail  information  for  that  extent.
 * Maximum    allowed     extent     size    is   DMICP_MAX_SECTORS.
 */
#define DMICP_BLOCK_SHIFT	12
#define DMICP_BLOCK_SIZE	(1 << DMICP_BLOCK_SHIFT)
#define DMICP_SECTOR_SHIFT	SECTOR_SHIFT
#define DMICP_SECTOR_SIZE	(1 << SECTOR_SHIFT)
#define DMICP_BLOCK_SECTOR_SHIFT (DMICP_BLOCK_SHIFT - DMICP_SECTOR_SHIFT)
#define DMICP_BLOCK_TO_SECTOR(b) ((b) << DMICP_BLOCK_SECTOR_SHIFT)
#define DMICP_SECTOR_TO_BLOCK(s) ((s) >> DMICP_BLOCK_SECTOR_SHIFT)
#define DMICP_SECTOR_TO_BYTES(s) ((s) << DMICP_SECTOR_SHIFT)
#define DMICP_BYTES_TO_SECTOR(b) ((b) >> DMICP_SECTOR_SHIFT)
#define DMICP_BYTES_TO_BLOCK(b)	((b) >> DMICP_BLOCK_SHIFT)

#define DMICP_MIN_SIZE	DMICP_BLOCK_SIZE

/*
 * maximum  sectors  is  the  twice the number of sectors a page can
 * hold.
 */
#define DMICP_MAX_SECTORS (DMICP_BYTES_TO_SECTOR(PAGE_SIZE) << 1)
#define DMICP_MAX_SIZE	DMICP_SECTOR_TO_BYTES(DMICP_SECTOR_SIZE)

#define DMICP_BITS_PER_ENTRY	32
#define DMICP_META_BITS		5
#define DMICP_LENGTH_BITS	4
#define DMICP_TAIL_MASK		(1 << DMICP_LENGTH_BITS)
#define DMICP_LENGTH_MASK	(DMICP_TAIL_MASK - 1)

#define DMICP_META_START_SECTOR (DMICP_BLOCK_SIZE >> DMICP_SECTOR_SHIFT)

enum DMICP_WRITE_MODE {
	DMICP_WRITE_BACK,
	DMICP_WRITE_THROUGH,
};

/*
 * A lock spans 128 Blocks i.e 512kbytes. Maximum I/O is much lesser than
 * that. Hence an I/O can span at most two locks.
 */
#define BITMAP_HASH_SHIFT 7
#define BITMAP_HASH_LEN (1<<6)
#define BITMAP_HASH_MASK (BITMAP_HASH_LEN - 1)
struct dm_icomp_hash_lock {
	int io_running;
	spinlock_t wait_lock;
	struct list_head wait_list;
};

struct dm_icomp_info {
	struct dm_target *ti;
	struct dm_dev *dev;

	int comp_alg;
	bool critical;
	struct crypto_comp *tfm[NR_CPUS];

	sector_t total_sector;	/* total sectors in the backing store */
	sector_t data_start;
	u64 data_blocks;
	u64 no_of_sectors;

	u32 *meta_bitmap;
	u64 meta_bitmap_bits;
	u64 meta_bitmap_pages;
	struct dm_icomp_hash_lock bitmap_locks[BITMAP_HASH_LEN];

	enum DMICP_WRITE_MODE write_mode;
	unsigned int writeback_delay; /* seconds */
	struct task_struct *writeback_tsk;
	struct dm_io_client *io_client;

	atomic64_t compressed_write_size;
	atomic64_t uncompressed_write_size;
	atomic64_t meta_write_size;
};

struct dm_icomp_meta_io {
	struct dm_io_request io_req;
	struct dm_io_region io_region;
	void *data;
	void (*fn)(void *data, unsigned long error);
};

struct dm_icomp_io_range {
	struct dm_io_request io_req;
	struct dm_io_region io_region;
	bool decomp_kmap;	     /* Is the decomp_data kmapped'? */
	void *decomp_data;
	void *decomp_real_data;      /* holds the actual start of the buffer */
	unsigned int decomp_len;     /* actual allocated/mapped length */
	unsigned int logical_bytes;  /* decompressed size of the extent */
	bool comp_kmap;		     /* Is the comp_data kmapped'? */
	void *comp_data;
	void *comp_real_data;	     /* holds the actual start of the buffer */
	unsigned int comp_len;	     /* actual allocated/mapped length */
	unsigned int data_bytes;     /* compressed size of the extent */
	struct list_head next;
	struct dm_icomp_req *req;
};

enum DMICP_REQ_STAGE {
	STAGE_INIT,
	STAGE_READ_EXISTING,
	STAGE_READ_DECOMP,
	STAGE_WRITE_COMP,
	STAGE_DONE,
};

struct dm_icomp_req {
	struct bio *bio;
	struct dm_icomp_info *info;
	struct list_head sibling;
	struct list_head all_io;
	atomic_t io_pending;
	enum DMICP_REQ_STAGE stage;
	struct dm_icomp_hash_lock *locks[2];
	int locked_locks;
	int result;
	int cpu;
	struct work_struct work;
};

struct dm_icomp_io_worker {
	struct list_head pending;
	spinlock_t lock;
	struct work_struct work;
};

struct dm_icomp_compressor_data {
	char *name;
	bool can_handle_overflow;
	int (*comp_len)(int comp_len);
	int (*max_comp_len)(int comp_len);
};

static inline int lzo_comp_len(int len)
{
	/* lzo compression overshoots the comp buffer
	 * if the buffer size is insufficient.
	 * Once that bug is fixed we can return half
	 * the length.
	 *
	 * return lzo1x_worst_compress(len) >> 1;
	 *
	 * For now its the full length.
	 */
	return lzo1x_worst_compress(len);
}

static inline int lzo_max_comp_len(int len)
{
	return lzo1x_worst_compress(len);
}

static inline int lz4_comp_len(int len)
{
	return LZ4_COMPRESSBOUND(len) >> 1;
}

static inline int lz4_max_comp_len(int len)
{
	return LZ4_COMPRESSBOUND(len);
}

static inline int nx842_comp_len(int len)
{
	int half = (len >> 1);
	return  (half > DMICP_SECTOR_SIZE) ?
			(half - DMICP_SECTOR_SIZE) :
			half;
}

static inline int nx842_max_comp_len(int len)
{
	return len;
}

#endif /* __KERNEL__ */

#endif /* __DM_INPLACE_COMPRESS_H__ */
