#ifndef __DM_INPLACE_COMPRESS_H__
#define __DM_INPLACE_COMPRESS_H__
#include <linux/types.h>

#define DMCP_SUPER_MAGIC 0x106526c206506c09
#define DMCP_COMPRESS_MAGIC 0xfaceecaf
struct dm_icomp_super_block {
	__le64 magic;
	__le64 meta_blocks;
	__le64 data_blocks;
	u8 comp_alg;
} __packed;

#define DMCP_COMP_ALG_LZO 1
#define DMCP_COMP_ALG_842 0

#ifdef __KERNEL__
/*
 * Minium logical size of this target is 4096 byte, which is a block.
 * Data of a block is compressed. Compressed data is round up to 512B, which is
 * the payload. For each block, we have 5 bits meta data. bit 0 - 3 stands
 * payload length(0 - 8 sectors). If compressed payload length is 8 sectors, we
 * just store uncompressed data. Actual compressed data length is stored at the
 * last 32 bits of payload if data is compressed. In disk, payload is stored at
 * the beginning of logical sector of the block. If IO size is bigger than one
 * block, we store the whole data as an extent. Bit 4 stands tail for an
 * extent. Max allowed extent size is 128k.
 */
#define DMCP_BLOCK_SHIFT	12
#define DMCP_BLOCK_SIZE		(1 << DMCP_BLOCK_SHIFT)
#define DMCP_SECTOR_SHIFT	SECTOR_SHIFT
#define DMCP_SECTOR_SIZE	(1 << SECTOR_SHIFT)
#define DMCP_BLOCK_SECTOR_SHIFT (DMCP_BLOCK_SHIFT - DMCP_SECTOR_SHIFT)
#define DMCP_BLOCK_TO_SECTOR(b) ((b) << DMCP_BLOCK_SECTOR_SHIFT)
#define DMCP_SECTOR_TO_BLOCK(s) ((s) >> DMCP_BLOCK_SECTOR_SHIFT)
#define DMCP_SECTOR_TO_BYTES(s) ((s) << DMCP_SECTOR_SHIFT)
#define DMCP_BYTES_TO_SECTOR(b) ((b) >> DMCP_SECTOR_SHIFT)
#define DMCP_BYTES_TO_BLOCK(b)	((b) >> DMCP_BLOCK_SHIFT)

#define DMCP_MIN_SIZE	DMCP_BLOCK_SIZE
#define DMCP_MAX_SIZE	(128 * 2 * DMCP_SECTOR_SIZE) /* 128k */

#define DMCP_BITS_PER_ENTRY	32
#define DMCP_META_BITS		5
#define DMCP_LENGTH_BITS	4
#define DMCP_TAIL_MASK		(1 << DMCP_LENGTH_BITS)
#define DMCP_LENGTH_MASK	(DMCP_TAIL_MASK - 1)

#define DMCP_META_START_SECTOR (DMCP_BLOCK_SIZE >> DMCP_SECTOR_SHIFT)

enum DMCP_WRITE_MODE {
	DMCP_WRITE_BACK,
	DMCP_WRITE_THROUGH,
};

/*
 * a lock spans 128 blocks i.e 512kbytes.
 * max I/O is 128K, which can at-most span two locks.
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

	enum DMCP_WRITE_MODE write_mode;
	unsigned int writeback_delay; /* second */
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

enum DMCP_REQ_STAGE {
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
	enum DMCP_REQ_STAGE stage;
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

static inline int lzo_comp_len(int comp_len)
{
	/* lzo compression overshoots the comp buffer
	 * if the buffer size is insufficient.
	 * Once that bug is fixed we can return half
	 * the length.
	 *
	 * return lzo1x_worst_compress(comp_len) >> 1;
	 *
	 * For now its the full length.
	 */
	return lzo1x_worst_compress(comp_len);
}

static inline int lzo_max_comp_len(int comp_len)
{
	return lzo1x_worst_compress(comp_len);
}

static inline int nx842_comp_len(int comp_len)
{
	return (comp_len >> 1);
}

static inline int nx842_max_comp_len(int comp_len)
{
	return comp_len;
}

#endif /* __KERNEL__ */

#endif /* __DM_INPLACE_COMPRESS_H__ */
