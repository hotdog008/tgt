#ifndef __SPC_H
#define __SPC_H

/*
 * Designator type - SPC-4 Reference
 *
 * 0 - Vendor specific - 7.6.3.3
 * 1 - T10 vendor ID - 7.6.3.4
 * 2 - EUI-64 - 7.6.3.5
 * 3 - NAA - 7.6.3.6
 * 4 - Relative Target port identifier - 7.6.3.7
 * 5 - Target Port group - 7.6.3.8
 * 6 - Logical Unit group - 7.6.3.9
 * 7 - MD5 logical unit identifier - 7.6.3.10
 * 8 - SCSI name string - 7.6.3.11
 */
#define DESG_VENDOR 0
#define DESG_T10 1
#define DESG_EUI64 2
#define DESG_NAA 3
#define DESG_REL_TGT_PORT 4
#define DESG_TGT_PORT_GRP 5
#define DESG_LU_GRP 6
#define DESG_MD5 7
#define DESG_SCSI 8

#define NAA_IEEE_EXTD		0x2
#define NAA_LOCAL		0x3
#define NAA_IEEE_REGD		0x5
#define NAA_IEEE_REGD_EXTD	0x6

#define NAA_DESG_LEN		0x8
#define NAA_DESG_LEN_EXTD	0x10

extern struct service_action maint_in_service_actions[],
	persistent_reserve_in_actions[], persistent_reserve_out_actions[];

extern int spc_service_action(int host_no, struct scsi_cmd *cmd);
extern int spc_inquiry(int host_no, struct scsi_cmd *cmd);
extern int spc_report_luns(int host_no, struct scsi_cmd *cmd);
extern int spc_start_stop(int host_no, struct scsi_cmd *cmd);
extern int spc_test_unit(int host_no, struct scsi_cmd *cmd);
extern int spc_request_sense(int host_no, struct scsi_cmd *cmd);
extern int spc_prevent_allow_media_removal(int host_no, struct scsi_cmd *cmd);
extern int spc_illegal_op(int host_no, struct scsi_cmd *cmd);
extern int spc_lu_init(struct scsi_lu *lu);
extern int spc_send_diagnostics(int host_no, struct scsi_cmd *cmd);

typedef tgtadm_err (match_fn_t)(struct scsi_lu *lu, char *params);
extern tgtadm_err lu_config(struct scsi_lu *lu, char *params, match_fn_t *);
extern tgtadm_err spc_lu_config(struct scsi_lu *lu, char *params);
extern void spc_lu_exit(struct scsi_lu *lu);
extern void dump_cdb(struct scsi_cmd *cmd);
extern int spc_mode_sense(int host_no, struct scsi_cmd *cmd);
extern tgtadm_err add_mode_page(struct scsi_lu *lu, char *params);
extern int set_mode_page_changeable_mask(struct scsi_lu *lu, uint8_t pcode,
					 uint8_t subpcode, uint8_t *mask);
extern struct mode_pg *find_mode_page(struct scsi_lu *lu,
				      uint8_t pcode, uint8_t subpcode);
extern int spc_mode_select(int host_no, struct scsi_cmd *cmd,
			   int (*update)(struct scsi_cmd *, uint8_t *, int *));
extern struct vpd *alloc_vpd(uint16_t size);
extern tgtadm_err spc_lu_online(struct scsi_lu *lu);
extern tgtadm_err spc_lu_offline(struct scsi_lu *lu);

extern int spc_access_check(struct scsi_cmd *cmd);
#endif
