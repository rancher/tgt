struct scsi_cmnd;
struct scsi_lun;
struct Scsi_Host;
struct task_struct;

/* tmp - will replace with SCSI logging stuff */
#define dprintk(fmt, args...)					\
do {								\
	printk("%s(%d) " fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define eprintk dprintk

struct scsi_tgt_queuedata {
	struct Scsi_Host *shost;
};

extern void scsi_tgt_if_exit(void);
extern int scsi_tgt_if_init(void);

extern int scsi_tgt_uspace_send(struct scsi_cmnd *cmd, struct scsi_lun *lun);
extern int scsi_tgt_uspace_send_status(struct scsi_cmnd *cmd, gfp_t flags);
extern int scsi_tgt_kspace_exec(int host_no, u32 cid, int result, u32 len,
				u64 offset, unsigned long uaddr, u8 rw,
				u8 try_map);