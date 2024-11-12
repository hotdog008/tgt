/*
 * Synchronous rbd image backing store routine
 *
 * modified from bs_rdrw.c:
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#define _XOPEN_SOURCE 600

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/fs.h>
#include <sys/epoll.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "scsi.h"
#include "spc.h"
#include "bs_thread.h"

#include "rados/librados.h"
#include "rbd/librbd.h"

#define XCOPY_DESG_HDR_LEN	            4
#define XCOPY_HDR_LEN                   16
#define XCOPY_TARGET_DESC_LEN           32
#define XCOPY_SEGMENT_DESC_B2B_LEN      28
#define XCOPY_NAA_IEEE_REGEX_LEN        16

/*
 * Receive Copy Results Sevice Actions
 */
#define RCR_SA_COPY_STATUS              0x00
#define RCR_SA_RECEIVE_DATA             0x01
#define RCR_SA_OPERATING_PARAMETERS     0x03
#define RCR_SA_FAILED_SEGMENT_DETAILS   0x04

/*
 * Receive Copy Results Operating Parameters
 */
#define RCR_OP_MAX_TARGET_DESC_COUNT    0x02
#define RCR_OP_MAX_SEGMENT_DESC_COUNT   0x01
#define RCR_OP_MAX_DESC_LIST_LEN        1024
#define RCR_OP_MAX_SEGMENT_LEN          16777216 /* 16M */
#define RCR_OP_TOTAL_CONCURR_COPIES     0x01
#define RCR_OP_MAX_CONCURR_COPIES       0x01
#define RCR_OP_DATA_SEG_GRAN_LOG2       0x09
#define RCR_OP_INLINE_DATA_GRAN_LOG2    0x09
#define RCR_OP_HELD_DATA_GRAN_LOG2      0x09

/*
 * Receive Copy Results descriptor type codes supports
 */
#define RCR_OP_IMPLE_DES_LIST_LENGTH    0x02
#define XCOPY_SEG_DESC_TYPE_CODE_B2B    0x02 /* block --> block */
#define XCOPY_TARGET_DESC_TYPE_CODE_ID  0xe4 /* Identification descriptor */


struct active_rbd {
	char *poolname;
	char *imagename;
	char *snapname;
	rados_t cluster;
	rados_ioctx_t ioctx;
	rbd_image_t rbd_image;
};

/* active_rbd is allocated just after the bs_thread_info */
#define RBDP(lu)	((struct active_rbd *) \
				((char *)lu + \
				sizeof(struct scsi_lu) + \
				sizeof(struct bs_thread_info)) \
			)

static void parse_imagepath(char *path, char **pool, char **image, char **snap)
{
	char *origp = strdup(path);
	char *p, *sep;

	p = origp;
	sep = strchr(p, '/');
	if (sep == NULL) {
		*pool = "rbd";
	} else {
		*sep = '\0';
		*pool = strdup(p);
		p = sep + 1;
	}
	/* p points to image[@snap] */
	sep = strchr(p, '@');
	if (sep == NULL) {
		*snap = "";
	} else {
		*snap = strdup(sep + 1);
		*sep = '\0';
	}
	/* p points to image\0 */
	*image = strdup(p);
	free(origp);
}

static void set_medium_error(int *result, uint8_t *key, uint16_t *asc)
{
	*result = SAM_STAT_CHECK_CONDITION;
	*key = MEDIUM_ERROR;
	*asc = ASC_READ_ERROR;
}

static void bs_sync_sync_range(struct scsi_cmd *cmd, uint32_t length,
			       int *result, uint8_t *key, uint16_t *asc)
{
	int ret;

	ret = rbd_flush(RBDP(cmd->dev)->rbd_image);
	if (ret)
		set_medium_error(result, key, asc);
}

static void handle_recv_copy_result(struct scsi_cmd *cmd)
{
    uint8_t *buf = scsi_get_in_buffer(cmd);

    /*
     * SNLID = 1: the copy manager will support an EXTENDED COPY
     * command parameter list in which the LIST ID USAGE field is
     * set to 11b
     */
	buf[4] = 0x01;

    /*
     * MAXIMUM TARGET COUNT: the max number of target descriptors
     * that the copy manager allows in a single EXTENDED COPY
     * target descriptor list.
     */
    put_unaligned_be16(RCR_OP_MAX_TARGET_DESC_COUNT, &buf[8]);

    /*
     * MAXIMUM SEGMENT COUNT: the max number of segment descriptors
     * that the copy manager allows in a single EXTENDED COPY
     * segment descriptor list.
     */
    put_unaligned_be16(RCR_OP_MAX_SEGMENT_DESC_COUNT, &buf[10]);

    /*
     * MAXIMUM DESCRIPTOR LIST LENGTH: the max length, in bytes,
     * of the target descriptor list and segment descriptor list.
     */
    put_unaligned_be32(RCR_OP_MAX_DESC_LIST_LEN, &buf[12]);

    /*
     * MAXIMUM SEGMENT LENGTH: the length, in bytes, of the largest
     * amount of data that the copy manager supports writing via a
     * single segment.
     */
    put_unaligned_be32(RCR_OP_MAX_SEGMENT_LEN, &buf[16]);

    /*
     * MAXIMUM CONCURRENT COPIES: the max number of EXTENDED COPY
     * commands with the LIST ID USAGE field set to 00b or 10b that
     * are supported for concurrent processing by the copy manager.
     */
    put_unaligned_be16(RCR_OP_TOTAL_CONCURR_COPIES, &buf[34]);

    /*
     * MAXIMUM CONCURRENT COPIES: the max number of EXTENDED COPY
     * commands with the LIST ID USAGE field set to 00b or 10b that
     * are supported for concurrent processing by the copy manager.
     */
    buf[36] = RCR_OP_MAX_CONCURR_COPIES;

    /*
     * DATA SEGMENT GRANULARITY: the length of the smallest data
     * block that copy manager permits in a non-inline segment
     * descriptor. In power of two.
     */
	buf[37] = RCR_OP_DATA_SEG_GRAN_LOG2;

    /*
	 * INLINE DATA GRANULARITY: the length of the of the smallest
	 * block of inline data that the copy manager permits being
	 * written by a segment descriptor containing the 04h descriptor
	 * type code (see 6.4.6.6 spc4r37). In power of two.
	 */
	buf[38] = RCR_OP_INLINE_DATA_GRAN_LOG2;

    /*
     * HELD DATA GRANULARITY: the length of the smallest block of
     * held data that the copy manager shall transfer to the
     * application client in response to a RECEIVE COPY RESULTS
     * command with RECEIVE DATA service action (see 6.21 spc4r37).
     * In power of two.
     */
    buf[39] = RCR_OP_HELD_DATA_GRAN_LOG2;

    /*
     * IMPLEMENTED DESCRIPTOR LIST LENGTH: the length, in bytes, of
     * the list of implemented descriptor type codes.
     */
    buf[43] = RCR_OP_IMPLE_DES_LIST_LENGTH;

    /*
     * The list of implemented descriptor type codes: one byte for
     * each segment or target DESCRIPTOR TYPE CODE value (see 6.4.5)
     * supported by the copy manager,
     */
    buf[44] = XCOPY_SEG_DESC_TYPE_CODE_B2B; /* block --> block */
    buf[45] = XCOPY_TARGET_DESC_TYPE_CODE_ID; /* Identification descriptor */

    /* AVAILABLE DATA (n-3)*/
    put_unaligned_be32(42, &buf[0]);

    return;
}

struct xcopy {
    struct scsi_cmd *cmd;

    struct scsi_lu *src_lu;
    uint8_t src_tid_wwn[XCOPY_NAA_IEEE_REGEX_LEN];
    struct scsi_lu *dst_lu;
    uint8_t dst_tid_wwn[XCOPY_NAA_IEEE_REGEX_LEN];

    uint64_t src_lba;
    uint64_t dst_lba;
    uint32_t stdi;
    uint32_t dtdi;
    uint32_t lba_cnt;
    uint32_t copy_lbas;

    int result;
    uint8_t key;
    uint16_t asc;
};

/* get lun id from wwn(scsi id) */
static struct scsi_lu* xcopy_get_target_dev(struct target *target, uint8_t *wwn)
{
    struct scsi_lu *lu;
    struct vpd *lu_vpd;
    uint8_t wwn_offset = XCOPY_DESG_HDR_LEN * 3 + SCSI_ID_LEN + NAA_DESG_LEN;

    list_for_each_entry(lu, &target->device_list, device_siblings) {
        lu_vpd = lu->attrs.lu_vpd[PCODE_OFFSET(0x83)];
        if (!memcmp(wwn, &lu_vpd->data[wwn_offset], XCOPY_NAA_IEEE_REGEX_LEN)) {
            return lu;
        }
	}

    return NULL;
}

/* Identification descriptor target */
static void xcopy_parse_target_id(struct xcopy *xcopy,
    uint8_t *tgt_desc, int32_t index)
{
    /*
     * CODE SET: for now only binary type code is supported.
     */
    if ((tgt_desc[4] & 0x0f) != 0x1) {
        eprintf("Id target CODE DET only support binary type!\n");
        xcopy->asc = ASC_INVALID_FIELD_IN_PARMS;
        goto illegal_req;
    }

    /*
     * ASSOCIATION: for now only LUN type code is supported.
     */
    if ((tgt_desc[5] & 0x30) != 0x00) {
        eprintf("Id target ASSOCIATION other than LUN not supported!\n");
        xcopy->asc = ASC_INVALID_FIELD_IN_PARMS;
        goto illegal_req;
    }

    /*
     * DESIGNATOR TYPE: for now only NAA type code is supported.
     *
     * The designator type define please see: such as
     * From spc4r31, section 7.8.6.1 Device Identification VPD page
     * overview
     */
    if ((tgt_desc[5] & 0x0f) != 0x3) {
        eprintf("Id target DESIGNATOR TYPE other than NAA not supported!\n");
        xcopy->asc = ASC_INVALID_FIELD_IN_PARMS;
        goto illegal_req;
    }

    /*
     * Check for matching 16 byte length for NAA IEEE Registered Extended
     * Assigned designator
     */
    if (tgt_desc[7] != 16) {
        eprintf("Id target DESIGNATOR LENGTH should be 16, but it's: %d\n",
            tgt_desc[7]);
        xcopy->asc = ASC_INVALID_FIELD_IN_PARMS;
        goto illegal_req;
    }

    /*
     * Check for NAA IEEE Registered Extended Assigned header.
     */
    if ((tgt_desc[8] >> 4) != 0x06) {
        eprintf("Id target NAA designator type: 0x%x\n",
            tgt_desc[8] >> 4);
        xcopy->asc = ASC_INVALID_FIELD_IN_PARMS;
        goto illegal_req;
    }

    /*
     * Source designator matches the local device
     */
    if (index == xcopy->stdi) {
        memcpy(xcopy->src_tid_wwn, &tgt_desc[8],
            XCOPY_NAA_IEEE_REGEX_LEN);

        /*
         * find source lun from wwn
         */
        xcopy->src_lu =
            xcopy_get_target_dev(xcopy->cmd->c_target, &tgt_desc[8]);
        if (!xcopy->src_lu) {
            xcopy->asc = ASC_XCOPY_CP_TGT_DEV_NOTCONN;
            goto copy_aborted;
        }
    }

    /*
     * Destination designator matches the local device.
     */
    if (index == xcopy->dtdi) {
        memcpy(xcopy->dst_tid_wwn, &tgt_desc[8],
            XCOPY_NAA_IEEE_REGEX_LEN);

        /*
         * find destination lun from wwn
         */
        xcopy->dst_lu =
            xcopy_get_target_dev(xcopy->cmd->c_target, &tgt_desc[8]);
        if (!xcopy->dst_lu) {
            xcopy->asc = ASC_XCOPY_CP_TGT_DEV_NOTCONN;
            goto copy_aborted;
        }
    }

    goto exit;

illegal_req:
    xcopy->key = ILLEGAL_REQUEST;
    xcopy->result = SAM_STAT_CHECK_CONDITION;
    goto exit;
copy_aborted:
    xcopy->key = COPY_ABORTED;
    xcopy->result = SAM_STAT_CHECK_CONDITION;
exit:
    return;
}

static void xcopy_parse_target_descs(
    struct xcopy *xcopy, uint8_t *tgt_desc, uint16_t tdll)
{
    int i;

    if (tdll % XCOPY_TARGET_DESC_LEN) {
        eprintf("CSCD descriptor list length %u not a multiple of %u\n",
            (unsigned int)tdll, XCOPY_TARGET_DESC_LEN);
        xcopy->asc = ASC_XCOPY_NOTSUPP_TGT_DESC_TYPE;
        goto illegal_req;
    }

    /* From spc4r36q,section 6.4.3.4 CSCD DESCRIPTOR LIST LENGTH field
     * If the number of CSCD descriptors exceeds the allowed number, the copy
     * manager shall terminate the command with CHECK CONDITION status, with
     * the sense key set to ILLEGAL REQUEST, and the additional sense code
     * set to TOO MANY TARGET DESCRIPTORS.
     */
    if (tdll > RCR_OP_MAX_TARGET_DESC_COUNT * XCOPY_TARGET_DESC_LEN) {
        eprintf("Only %u target descriptor(s) supported, but there are %u\n",
            RCR_OP_MAX_TARGET_DESC_COUNT, tdll / XCOPY_TARGET_DESC_LEN);
        xcopy->asc = ASC_XCOPY_TCMU_STS_TOO_MANY_TGT_DESC;
        goto illegal_req;
    }

    for (i = 0; tdll >= XCOPY_TARGET_DESC_LEN; i++) {
        /*
         * Only Identification Descriptor Target Descriptor support
         * for now.
         */
        if (tgt_desc[0] == XCOPY_TARGET_DESC_TYPE_CODE_ID) {
            xcopy_parse_target_id(xcopy, tgt_desc, i);
            if (xcopy->result != SAM_STAT_GOOD)
                goto exit;

            tgt_desc += XCOPY_TARGET_DESC_LEN;
            tdll -= XCOPY_TARGET_DESC_LEN;
        } else {
            eprintf("Unsupport target descriptor type code 0x%x\n",
                tgt_desc[0]);
            xcopy->asc = ASC_XCOPY_NOTSUPP_TGT_DESC_TYPE;
            goto illegal_req;
        }
    }

    dprintf("Source device NAA IEEE WWN: 0x%16phN\n", xcopy->src_tid_wwn);
    dprintf("Destination device NAA IEEE WWN: 0x%16phN\n", xcopy->dst_tid_wwn);

illegal_req:
    xcopy->key = ILLEGAL_REQUEST;
    xcopy->result = SAM_STAT_CHECK_CONDITION;
exit:
    return;
}

/* For now only supports block -> block type */
static void xcopy_parse_segment_descs(uint8_t *seg_descs,
    struct xcopy *xcopy, uint8_t sdll)
{
    uint8_t *seg_desc = seg_descs;
    uint8_t desc_len;

    /*
     * From spc4r31, section 6.3.7.5 Block device to block device
     * operations
     *
     * The segment descriptor size should be 28 bytes
     */
    if (sdll % XCOPY_SEGMENT_DESC_B2B_LEN != 0) {
        eprintf("Illegal block --> block type segment descriptor length %u\n",
            sdll);
        xcopy->asc = ASC_INVALID_FIELD_IN_PARMS;
        goto illegal_req;
    }

    /* From spc4r36q, section 6.4.3.5 SEGMENT DESCRIPTOR LIST LENGTH field
    * If the number of segment descriptors exceeds the allowed number, the copy
    * manager shall terminate the command with CHECK CONDITION status, with the
    * sense key set to ILLEGAL REQUEST, and the additional sense code set to
    * TOO MANY SEGMENT DESCRIPTORS.
    */
    if (sdll > RCR_OP_MAX_SEGMENT_DESC_COUNT * XCOPY_SEGMENT_DESC_B2B_LEN) {
        eprintf("Only %u segment descriptor(s) supported, but there are %u\n",
            RCR_OP_MAX_SEGMENT_DESC_COUNT, sdll / XCOPY_SEGMENT_DESC_B2B_LEN);
        xcopy->asc = ASC_XCOPY_TOO_MANY_SEG_DESC;
        goto illegal_req;
    }

    /* EXTENDED COPY segment descriptor type codes block --> block */
    if (seg_desc[0] != XCOPY_SEG_DESC_TYPE_CODE_B2B) {
        eprintf("Unsupport segment descriptor type code 0x%x\n", seg_desc[0]);
        xcopy->asc = ASC_XCOPY_NOTSUPP_SEG_DESC_TYPE;
        goto illegal_req;
    }

    /*
    * For block -> block type the length is 4-byte header + 0x18-byte
    * data.
    */
    desc_len = get_unaligned_be16(&seg_desc[2]);
    if (desc_len != 0x18) {
        eprintf("Invalid length for block->block type 0x%x\n", desc_len);
        xcopy->asc = ASC_INVALID_FIELD_IN_PARMS;
        goto illegal_req;
    }

    /*
     * From spc4r31, section 6.3.7.1 Segment descriptors introduction
     *
     * The SOURCE TARGET DESCRIPTOR INDEX field contains an index into
     * the target descriptor list (see 6.3.1) identifying the source
     * copy target device. The DESTINATION TARGET DESCRIPTOR INDEX field
     * contains an index into the target descriptor list (see 6.3.1)
     * identifying the destination copy target device.
     */
    xcopy->stdi = get_unaligned_be16(&seg_desc[4]);
    xcopy->dtdi = get_unaligned_be16(&seg_desc[6]);
    dprintf("Segment descriptor: stdi: %hu dtdi: %hu\n", xcopy->stdi,
        xcopy->dtdi);

    xcopy->lba_cnt = get_unaligned_be16(&seg_desc[10]);
    xcopy->src_lba = get_unaligned_be64(&seg_desc[12]);
    xcopy->dst_lba = get_unaligned_be64(&seg_desc[20]);
    dprintf("Segment descriptor: lba_cnt: %u src_lba: %"PRIu64" dst_lba: %"PRIu64"\n",
            xcopy->lba_cnt, xcopy->src_lba, xcopy->dst_lba);

    goto exit;

illegal_req:
    xcopy->asc = ILLEGAL_REQUEST;
    xcopy->result = SAM_STAT_CHECK_CONDITION;
exit:
    return;
}

static void xcopy_parse_parameter_list(struct xcopy *xcopy)
{
    char *tmpbuf = scsi_get_out_buffer(xcopy->cmd);
    size_t data_length = scsi_get_out_length(xcopy->cmd);
    uint16_t sdll, tdll;
    uint32_t inline_dl;
    uint8_t *seg_desc, *tgt_desc;
    uint64_t num_lbas;

    /*
     * From spc4r31, section 6.18.4 OPERATING PARAMETERS service action
     *
     * A supports no list identifier (SNLID) bit set to one indicates
     * the copy manager supports an EXTENDED COPY (see 6.3) command
     * parameter list in which the LIST ID USAGE field is set to 11b
     * and the LIST IDENTIFIER field is set to zero as described in
     * table 105 (see 6.3.1).
     *
     * From spc4r31, section 6.3.1 EXTENDED COPY command introduction
     *
     * LIST ID USAGE == 11b, then the LIST IDENTIFIER field should be
     * as zero.
     */
     dprintf("LIST ID USAGE: 0x%x, LIST IDENTIFIER: 0x%x\n",
             (tmpbuf[1] & 0x18) >> 3, tmpbuf[0]);
    if ((tmpbuf[1] & 0x18) != 0x18 || tmpbuf[0]) {
        eprintf("LIST ID USAGE: 0x%x, LIST IDENTIFIER: 0x%x\n",
                (tmpbuf[1] & 0x18) >> 3, tmpbuf[0]);
        xcopy->asc = ASC_INVALID_FIELD_IN_PARMS;
        goto illegal_req;
    }

    /*
     * From spc4r31, section 6.3.6.1 Target descriptors introduction
     *
     * All target descriptors (see table 108) are 32 bytes or 64 bytes
     * in length
     * From spc4r36q, section6.4.3.4
     * An EXTENDED COPY command may reference one or more CSCDs.
     */
    tdll = get_unaligned_be16(&tmpbuf[2]);
    if (tdll < 32 || tdll % 32 != 0) {
        eprintf("Illegal target descriptor length %u\n", tdll);
        goto inval_param_list_len;
    }

    /*
     * From spc4r31, section 6.3.7.1 Segment descriptors introduction
     *
     * Segment descriptors (see table 120) begin with an eight byte header.
     */
    sdll = get_unaligned_be32(&tmpbuf[8]);
    if (sdll < 8) {
        eprintf("Illegal segment descriptor length %u\n", sdll);
        goto inval_param_list_len;
    }

    /*
     * The maximum length of the target and segment descriptors permitted
     * within a parameter list is indicated by the MAXIMUM DESCRIPTOR LIST
     * LENGTH field in the copy managers operating parameters.
     */
    if (tdll + sdll > RCR_OP_MAX_DESC_LIST_LEN) {
        eprintf("descriptor list length %u exceeds maximum %u\n",
                    tdll + sdll, RCR_OP_MAX_DESC_LIST_LEN);
        goto inval_param_list_len;
    }

    /*
     * The INLINE DATA LENGTH field contains the number of bytes of inline
     * data, after the last segment descriptor.
     */
    inline_dl = get_unaligned_be32(&tmpbuf[12]);
    if (inline_dl != 0) {
        eprintf("non-zero xcopy inline_dl %u unsupported\n", inline_dl);
        goto inval_param_list_len;
    }

    /* From spc4r31, section 6.3.1 EXTENDED COPY command introduction
     *
     * The EXTENDED COPY parameter list (see table 104) begins with a 16
     * byte header.
     *
     * The data length in CDB should be equal to tdll + sdll + inline_dl
     * + parameter list header length
     */
    if (data_length < (XCOPY_HDR_LEN + tdll + sdll + inline_dl)) {
        eprintf("Illegal list length: length from CDB is %zu,"
                " but here the length is %u\n",
                data_length, tdll + sdll + inline_dl);
        goto inval_param_list_len;
    }

    dprintf("Processing XCOPY with tdll: %hu sdll: %u inline_dl: %u\n",
            tdll, sdll, inline_dl);

    /*
     * Parse the segment descripters and for now we only support block
     * -> block type.
     *
     * The max seg_desc number support is 1(see RCR_OP_MAX_SG_DESC_COUNT)
     */
    seg_desc = (uint8_t *)tmpbuf + XCOPY_HDR_LEN + tdll;
    xcopy_parse_segment_descs(seg_desc, xcopy, sdll);
    if (xcopy->result != SAM_STAT_GOOD) {
        goto exit;
    }

    /*
     * Parse the target descripter
     *
     * The max tgt_desc number support is 2(see RCR_OP_MAX_TARGET_DESC_COUNT)
     */
    tgt_desc = (uint8_t *)tmpbuf + XCOPY_HDR_LEN;
    xcopy_parse_target_descs(xcopy, tgt_desc, tdll);
    if (xcopy->result != SAM_STAT_GOOD) {
        goto exit;
    }

    /*
     * src dev blocksize must be same with dst dev blocksize
     */
    if (xcopy->src_lu->blk_shift != xcopy->dst_lu->blk_shift) {
        /* Invalid copy target device type */
        eprintf("The block size of src dev %u != dst dev %u\n",
			     1 << xcopy->src_lu->blk_shift,
			     1 << xcopy->dst_lu->blk_shift);
        xcopy->asc = ASC_XCOPY_INVALID_CP_TGT_DEV_TYPE;
        goto copy_aborted;
    }

    num_lbas = xcopy->src_lu->size >> xcopy->src_lu->blk_shift;
    if (xcopy->src_lba + xcopy->lba_cnt > num_lbas) {
        eprintf(
            "src target exceeds last lba %"PRIu64" (lba %"PRIu64", copy len %u\n",
            num_lbas, xcopy->src_lba, xcopy->lba_cnt);
        xcopy->asc = ASC_LBA_OUT_OF_RANGE;
        goto illegal_req;
    }

    num_lbas = xcopy->dst_lu->size >> xcopy->dst_lu->blk_shift;
    if (xcopy->dst_lba + xcopy->lba_cnt > num_lbas) {
        eprintf("dst target exceeds last lba %"PRIu64" (lba %"PRIu64", copy len %u)\n",
            num_lbas, xcopy->dst_lba, xcopy->lba_cnt);
        xcopy->asc = ASC_LBA_OUT_OF_RANGE;
        goto illegal_req;
    }

inval_param_list_len:
    xcopy->asc = ASC_PARAMETER_LIST_LENGTH_ERR;
illegal_req:
    xcopy->key = ILLEGAL_REQUEST;
    xcopy->result = SAM_STAT_CHECK_CONDITION;
    goto exit;
copy_aborted:
    xcopy->key = COPY_ABORTED;
    xcopy->result = SAM_STAT_CHECK_CONDITION;
exit:
    return;
}

static void bs_rbd_request(struct scsi_cmd *cmd)
{
	int ret;
	uint32_t length, data_length, alloc_len;
	int result = SAM_STAT_GOOD;
	uint8_t key;
	uint16_t asc;
#if 0
	/*
	 * This should go in the sense data on error for COMPARE_AND_WRITE, but
	 * there doesn't seem to be any attempt to do so...
	 */

	uint32_t info = 0;
#endif
	char *tmpbuf;
	size_t blocksize;
	uint64_t offset = cmd->offset;
	uint32_t tl     = cmd->tl;
	int do_verify = 0;
	int i;
	char *ptr;
	const char *write_buf = NULL;
	ret = length = 0;
	key = asc = 0;
    struct xcopy xcopy_parse;
	struct active_rbd *rbd = RBDP(cmd->dev);

	switch (cmd->scb[0]) {
	case ORWRITE_16:
		length = scsi_get_out_length(cmd);

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			result = SAM_STAT_CHECK_CONDITION;
			key = HARDWARE_ERROR;
			asc = ASC_INTERNAL_TGT_FAILURE;
			break;
		}

		ret = rbd_read(rbd->rbd_image, offset, length, tmpbuf);

		if (ret != length) {
			set_medium_error(&result, &key, &asc);
			free(tmpbuf);
			break;
		}

		ptr = scsi_get_out_buffer(cmd);
		for (i = 0; i < length; i++)
			ptr[i] |= tmpbuf[i];

		free(tmpbuf);

		write_buf = scsi_get_out_buffer(cmd);
		goto write;
	case COMPARE_AND_WRITE:
		/* Blocks are transferred twice, first the set that
		 * we compare to the existing data, and second the set
		 * to write if the compare was successful.
		 */
		length = scsi_get_out_length(cmd) / 2;
		if (length != cmd->tl) {
			result = SAM_STAT_CHECK_CONDITION;
			key = ILLEGAL_REQUEST;
			asc = ASC_INVALID_FIELD_IN_CDB;
			break;
		}

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			result = SAM_STAT_CHECK_CONDITION;
			key = HARDWARE_ERROR;
			asc = ASC_INTERNAL_TGT_FAILURE;
			break;
		}

		ret = rbd_read(rbd->rbd_image, offset, length, tmpbuf);

		if (ret != length) {
			set_medium_error(&result, &key, &asc);
			free(tmpbuf);
			break;
		}

		if (memcmp(scsi_get_out_buffer(cmd), tmpbuf, length)) {
			uint32_t pos = 0;
			char *spos = scsi_get_out_buffer(cmd);
			char *dpos = tmpbuf;

			/*
			 * Data differed, this is assumed to be 'rare'
			 * so use a much more expensive byte-by-byte
			 * comparasion to find out at which offset the
			 * data differs.
			 */
			for (pos = 0; pos < length && *spos++ == *dpos++;
			     pos++)
				;
#if 0
			/* See comment above at declaration */
			info = pos;
#endif
			result = SAM_STAT_CHECK_CONDITION;
			key = MISCOMPARE;
			asc = ASC_MISCOMPARE_DURING_VERIFY_OPERATION;
			free(tmpbuf);
			break;
		}

		/* no DPO bit (cache retention advice) support */
		free(tmpbuf);

		write_buf = scsi_get_out_buffer(cmd) + length;
		goto write;
    case EXTENDED_COPY:
        /* spc4r36q section6.4 and 6.5
         * EXTENDED_COPY(LID4) :service action 0x01;
         * EXTENDED_COPY(LID1) :service action 0x00.
         */
        if ((cmd->scb[1] & 0x1f) != 0x00) {
            eprintf("EXTENDED_COPY(LID4) not supported\n");
            result = SAM_STAT_CHECK_CONDITION;
            key = ILLEGAL_REQUEST;
            asc = ASC_INVALID_OP_CODE;
            break;
        }

        length = scsi_get_out_length(cmd);
        /*
         * A parameter list length of zero specifies that copy manager
         * shall not transfer any data or alter any internal state.
         */
        if (length == 0) {
            result = SAM_STAT_GOOD;
            break;
        }

        /*
         * The EXTENDED COPY parameter list begins with a 16 byte header
         * that contains the LIST IDENTIFIER field.
         */
        if (length < XCOPY_HDR_LEN) {
            eprintf("Illegal parameter list: length %u < hdr_len %u\n",
                     length, XCOPY_HDR_LEN);
            result = SAM_STAT_CHECK_CONDITION;
            key = ILLEGAL_REQUEST;
            asc = ASC_PARAMETER_LIST_LENGTH_ERR;
            break;
        }

        memset(&xcopy_parse, 0, sizeof(xcopy_parse));
        xcopy_parse.cmd = cmd;
        xcopy_parse.result = SAM_STAT_GOOD;
        /* Parse and check the parameter list */
        xcopy_parse_parameter_list(&xcopy_parse);

        result = xcopy_parse.result;
        key = xcopy_parse.key;
        asc = xcopy_parse.asc;

        if (result != SAM_STAT_GOOD)
            break;

        /* Nothing to do with BLOCK DEVICE NUMBER OF BLOCKS set to zero */
        if (!xcopy_parse.lba_cnt) {
            result = SAM_STAT_GOOD;
            break;
        }

        /* read first */
        blocksize = 1 << xcopy_parse.src_lu->blk_shift;
        data_length = xcopy_parse.lba_cnt * blocksize;
        tmpbuf = malloc(data_length);
        if (!tmpbuf) {
            result = SAM_STAT_CHECK_CONDITION;
            key = HARDWARE_ERROR;
            asc = ASC_INTERNAL_TGT_FAILURE;
            break;
        }

        rbd = RBDP(xcopy_parse.src_lu);
        ret = rbd_read(rbd->rbd_image, xcopy_parse.src_lba * blocksize,
            data_length, tmpbuf);
        if (ret != data_length) {
			set_medium_error(&result, &key, &asc);
			free(tmpbuf);
			break;
		}

        /* write */
        ret = rbd_write(rbd->rbd_image, xcopy_parse.dst_lba * blocksize,
            data_length, tmpbuf);
        if (ret != data_length) {
            set_medium_error(&result, &key, &asc);
            free(tmpbuf);
            break;
        }

        free(tmpbuf);
        break;
    case RECEIVE_COPY_RESULTS:
        if ((cmd->scb[1] & 0x1f) != RCR_SA_OPERATING_PARAMETERS) {
            eprintf("only support RECEIVE COPY OPERATING PARAMETERS\n");
            result = SAM_STAT_CHECK_CONDITION;
            key = ILLEGAL_REQUEST;
            asc = ASC_INVALID_OP_CODE;
            break;
        }

        alloc_len = get_unaligned_be32(&cmd->scb[10]);
        if (scsi_get_in_length(cmd) < alloc_len) {
            eprintf("buffer length(%u) < alloc length(%u)\n",
                scsi_get_in_length(cmd), alloc_len);

            scsi_set_in_resid_by_actual(cmd, 0);

            result = SAM_STAT_CHECK_CONDITION;
            key = ILLEGAL_REQUEST;
            asc = ASC_INVALID_FIELD_IN_CDB;

            break;
        }

        handle_recv_copy_result(cmd);
        break;
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		/* TODO */
		length = (cmd->scb[0] == SYNCHRONIZE_CACHE) ? 0 : 0;

		if (cmd->scb[1] & 0x2) {
			result = SAM_STAT_CHECK_CONDITION;
			key = ILLEGAL_REQUEST;
			asc = ASC_INVALID_FIELD_IN_CDB;
		} else
			bs_sync_sync_range(cmd, length, &result, &key, &asc);
		break;
	case WRITE_VERIFY:
	case WRITE_VERIFY_12:
	case WRITE_VERIFY_16:
		do_verify = 1;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		length = scsi_get_out_length(cmd);
		write_buf = scsi_get_out_buffer(cmd);
write:
		ret = rbd_write(rbd->rbd_image, offset, length, write_buf);
		if (ret == length) {
			struct mode_pg *pg;

			/*
			 * it would be better not to access to pg
			 * directy.
			 */
			pg = find_mode_page(cmd->dev, 0x08, 0);
			if (pg == NULL) {
				result = SAM_STAT_CHECK_CONDITION;
				key = ILLEGAL_REQUEST;
				asc = ASC_INVALID_FIELD_IN_CDB;
				break;
			}
			if (((cmd->scb[0] != WRITE_6) && (cmd->scb[1] & 0x8)) ||
			    !(pg->mode_data[0] & 0x04))
				bs_sync_sync_range(cmd, length, &result, &key,
						   &asc);
		} else
			set_medium_error(&result, &key, &asc);

		if (do_verify)
			goto verify;
		break;
	case WRITE_SAME:
	case WRITE_SAME_16:
		/* WRITE_SAME used to punch hole in file */
		if (cmd->scb[1] & 0x08) {
			ret = rbd_discard(rbd->rbd_image, offset, tl);
			if (ret != 0) {
				eprintf("Failed to punch hole for WRITE_SAME"
					" command\n");
				result = SAM_STAT_CHECK_CONDITION;
				key = HARDWARE_ERROR;
				asc = ASC_INTERNAL_TGT_FAILURE;
				break;
			}
			break;
		}
		while (tl > 0) {
			blocksize = 1 << cmd->dev->blk_shift;
			tmpbuf = scsi_get_out_buffer(cmd);

			switch (cmd->scb[1] & 0x06) {
			case 0x02: /* PBDATA==0 LBDATA==1 */
				put_unaligned_be32(offset, tmpbuf);
				break;
			case 0x04: /* PBDATA==1 LBDATA==0 */
				/* physical sector format */
				put_unaligned_be64(offset, tmpbuf);
				break;
			}

			ret = rbd_write(rbd->rbd_image, offset, blocksize,
					tmpbuf);
			if (ret != blocksize)
				set_medium_error(&result, &key, &asc);

			offset += blocksize;
			tl     -= blocksize;
		}
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		length = scsi_get_in_length(cmd);
		ret = rbd_read(rbd->rbd_image, offset, length,
			       scsi_get_in_buffer(cmd));

		if (ret != length)
			set_medium_error(&result, &key, &asc);

		break;
	case PRE_FETCH_10:
	case PRE_FETCH_16:
		break;
	case VERIFY_10:
	case VERIFY_12:
	case VERIFY_16:
verify:
		length = scsi_get_out_length(cmd);

		tmpbuf = malloc(length);
		if (!tmpbuf) {
			result = SAM_STAT_CHECK_CONDITION;
			key = HARDWARE_ERROR;
			asc = ASC_INTERNAL_TGT_FAILURE;
			break;
		}

		ret = rbd_read(rbd->rbd_image, offset, length, tmpbuf);

		if (ret != length)
			set_medium_error(&result, &key, &asc);
		else if (memcmp(scsi_get_out_buffer(cmd), tmpbuf, length)) {
			result = SAM_STAT_CHECK_CONDITION;
			key = MISCOMPARE;
			asc = ASC_MISCOMPARE_DURING_VERIFY_OPERATION;
		}

		free(tmpbuf);
		break;
	case UNMAP:
		if (!cmd->dev->attrs.thinprovisioning) {
			result = SAM_STAT_CHECK_CONDITION;
			key = ILLEGAL_REQUEST;
			asc = ASC_INVALID_FIELD_IN_CDB;
			break;
		}

		length = scsi_get_out_length(cmd);
		tmpbuf = scsi_get_out_buffer(cmd);

		if (length < 8)
			break;

		length -= 8;
		tmpbuf += 8;

		while (length >= 16) {
			offset = get_unaligned_be64(&tmpbuf[0]);
			offset = offset << cmd->dev->blk_shift;

			tl = get_unaligned_be32(&tmpbuf[8]);
			tl = tl << cmd->dev->blk_shift;

			if (offset + tl > cmd->dev->size) {
				eprintf("UNMAP beyond EOF\n");
				result = SAM_STAT_CHECK_CONDITION;
				key = ILLEGAL_REQUEST;
				asc = ASC_LBA_OUT_OF_RANGE;
				break;
			}

			if (tl > 0) {
				if (rbd_discard(rbd->rbd_image, offset, tl)
				    != 0) {
					eprintf("Failed to punch hole for"
						" UNMAP at offset:%" PRIu64
						" length:%d\n",
						offset, tl);
					result = SAM_STAT_CHECK_CONDITION;
					key = HARDWARE_ERROR;
					asc = ASC_INTERNAL_TGT_FAILURE;
					break;
				}
			}

			length -= 16;
			tmpbuf += 16;
		}
		break;
	default:
		break;
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	scsi_set_result(cmd, result);

	if (result != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, offset);
		sense_data_build(cmd, key, asc);
	}
}


static int bs_rbd_open(struct scsi_lu *lu, char *path, int *fd, uint64_t *size)
{
	uint32_t blksize = 0;
	int ret;
	rbd_image_info_t inf;
	char *poolname;
	char *imagename;
	char *snapname;
	struct active_rbd *rbd = RBDP(lu);

	parse_imagepath(path, &poolname, &imagename, &snapname);

	rbd->poolname = poolname;
	rbd->imagename = imagename;
	rbd->snapname = snapname;
	eprintf("bs_rbd_open: pool: %s image: %s snap: %s\n",
		poolname, imagename, snapname);

	ret = rados_ioctx_create(rbd->cluster, poolname, &rbd->ioctx);
	if (ret < 0) {
		eprintf("bs_rbd_open: rados_ioctx_create: %d\n", ret);
		return -EIO;
	}

	ret = rbd_open(rbd->ioctx, imagename, &rbd->rbd_image, snapname);
	if (ret < 0) {
		eprintf("bs_rbd_open: rbd_open: %d\n", ret);
		return ret;
	}
	if (rbd_stat(rbd->rbd_image, &inf, sizeof(inf)) < 0) {
		eprintf("bs_rbd_open: rbd_stat: %d\n", ret);
		return ret;
	}
	*size = inf.size;
	blksize = inf.obj_size;

	if (!lu->attrs.no_auto_lbppbe)
		update_lbppbe(lu, blksize);

	return 0;
}

static void bs_rbd_close(struct scsi_lu *lu)
{
	struct active_rbd *rbd = RBDP(lu);

	if (rbd->rbd_image) {
		rbd_close(rbd->rbd_image);
		rados_ioctx_destroy(rbd->ioctx);
		rbd->rbd_image = rbd->ioctx = NULL;
	}
}

// Slurp up and return a copy of everything to the next ';', and update p
static char *slurp_to_semi(char **p)
{
	char *end = index(*p, ';');
	char *ret;
	int len;

	if (end == NULL)
		end = *p + strlen(*p);
	len = end - *p;
	ret = malloc(len + 1);
	strncpy(ret, *p, len);
	ret[len] = '\0';
	*p = end;
	/* Jump past the semicolon, if we stopped at one */
	if (**p == ';')
		*p = end + 1;
	return ret;
}

static char *slurp_value(char **p)
{
	char *equal = index(*p, '=');
	if (equal) {
		*p = equal + 1;
		return slurp_to_semi(p);
	} else {
		// uh...no?
		return NULL;
	}
}

static int is_opt(const char *opt, char *p)
{
	int ret = 0;
	if ((strncmp(p, opt, strlen(opt)) == 0) &&
	    (p[strlen(opt)] == '=')) {
		ret = 1;
	}
	return ret;
}


static tgtadm_err bs_rbd_init(struct scsi_lu *lu, char *bsopts)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);
	tgtadm_err ret = TGTADM_UNKNOWN_ERR;
	int rados_ret;
	struct active_rbd *rbd = RBDP(lu);
	char *confname = NULL;
	char *clientid = NULL;
	char *virsecretuuid = NULL;
	char *given_cephx_key = NULL;
	char disc_cephx_key[256];
	char *clustername = NULL;
	char clientid_full[128];
	char *ignore = NULL;

	dprintf("bs_rbd_init bsopts: \"%s\"\n", bsopts);

	// look for conf= or id= or cluster=

	while (bsopts && strlen(bsopts)) {
		if (is_opt("conf", bsopts))
			confname = slurp_value(&bsopts);
		else if (is_opt("id", bsopts))
			clientid = slurp_value(&bsopts);
		else if (is_opt("cluster", bsopts))
			clustername = slurp_value(&bsopts);
		else if (is_opt("virsecretuuid", bsopts))
			virsecretuuid = slurp_value(&bsopts);
		else if (is_opt("cephx_key", bsopts))
			given_cephx_key = slurp_value(&bsopts);
		else {
			ignore = slurp_to_semi(&bsopts);
			eprintf("bs_rbd: ignoring unknown option \"%s\"\n",
				ignore);
			free(ignore);
			break;
		}
	}

	if (clientid)
		eprintf("bs_rbd_init: clientid %s\n", clientid);
	if (confname)
		eprintf("bs_rbd_init: confname %s\n", confname);
	if (clustername)
		eprintf("bs_rbd_init: clustername %s\n", clustername);
	if (virsecretuuid)
		eprintf("bs_rbd_init: virsecretuuid %s\n", virsecretuuid);
	if (given_cephx_key)
		eprintf("bs_rbd_init: given_cephx_key %s\n", given_cephx_key);

	/* virsecretuuid && given_cephx_key are conflicting options. */
	if (virsecretuuid && given_cephx_key) {
		eprintf("Conflicting options virsecretuuid=[%s] cephx_key=[%s]",
			virsecretuuid, given_cephx_key);
		goto fail;
	}

	/* Get stored key from secret uuid. */
	if (virsecretuuid) {
		char libvir_uuid_file_path_buf[256] = "/etc/libvirt/secrets/";
		strcat(libvir_uuid_file_path_buf, virsecretuuid);
		strcat(libvir_uuid_file_path_buf, ".base64");

		FILE *fp;
		fp = fopen(libvir_uuid_file_path_buf , "r");
		if (fp == NULL) {
			eprintf("bs_rbd_init: Unable to read %s\n",
				libvir_uuid_file_path_buf);
			goto fail;
		}
		if (fgets(disc_cephx_key, 256, fp) == NULL) {
			eprintf("bs_rbd_init: Unable to read %s\n",
				libvir_uuid_file_path_buf);
			goto fail;
		}
		fclose(fp);
		strtok(disc_cephx_key, "\n");

		eprintf("bs_rbd_init: disc_cephx_key %s\n", disc_cephx_key);
	}

	eprintf("bs_rbd_init bsopts=%s\n", bsopts);
	/*
	 * clientid may be set by -i/--id. If clustername is set, then
	 * we use rados_create2, else rados_create
	 */
	if (clustername) {
		/* rados_create2 wants the full client name */
		if (clientid)
			snprintf(clientid_full, sizeof clientid_full,
				 "client.%s", clientid);
		else /* if not specified, default to client.admin */
			snprintf(clientid_full, sizeof clientid_full,
				 "client.admin");
		rados_ret = rados_create2(&rbd->cluster, clustername,
					  clientid_full, 0);
	} else {
		rados_ret = rados_create(&rbd->cluster, clientid);
	}
	if (rados_ret < 0) {
		eprintf("bs_rbd_init: rados_create: %d\n", rados_ret);
		return ret;
	}

	/*
	 * Read config from environment, then conf file(s) which may
	 * be set by conf=
	 */
	rados_ret = rados_conf_parse_env(rbd->cluster, NULL);
	if (rados_ret < 0) {
		eprintf("bs_rbd_init: rados_conf_parse_env: %d\n", rados_ret);
		goto fail;
	}
	rados_ret = rados_conf_read_file(rbd->cluster, confname);
	if (rados_ret < 0) {
		eprintf("bs_rbd_init: rados_conf_read_file: %d\n", rados_ret);
		goto fail;
	}

	/* Set given key */
	if (virsecretuuid) {
		if (rados_conf_set(rbd->cluster, "key", disc_cephx_key) < 0) {
			eprintf("bs_rbd_init: failed to set cephx_key: %s\n",
				disc_cephx_key);
			goto fail;
		}
	}
	if (given_cephx_key) {
		if (rados_conf_set(rbd->cluster, "key", given_cephx_key) < 0) {
			eprintf("bs_rbd_init: failed to set cephx_key: %s\n",
				given_cephx_key);
			goto fail;
		}
	}

	rados_ret = rados_connect(rbd->cluster);
	if (rados_ret < 0) {
		eprintf("bs_rbd_init: rados_connect: %d\n", rados_ret);
		goto fail;
	}
	ret = bs_thread_open(info, bs_rbd_request, nr_iothreads);
fail:
	if (confname)
		free(confname);
	if (clientid)
		free(clientid);
	if (virsecretuuid)
		free(virsecretuuid);
	if (given_cephx_key)
		free(given_cephx_key);

	return ret;
}

static void bs_rbd_exit(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);
	struct active_rbd *rbd = RBDP(lu);

	/* do this first to try to be sure there's no outstanding I/O */
	bs_thread_close(info);
	rados_shutdown(rbd->cluster);
}

static struct backingstore_template rbd_bst = {
	.bs_name		= "rbd",
	.bs_datasize		= sizeof(struct bs_thread_info) +
				  sizeof(struct active_rbd),
	.bs_open		= bs_rbd_open,
	.bs_close		= bs_rbd_close,
	.bs_init		= bs_rbd_init,
	.bs_exit		= bs_rbd_exit,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_oflags_supported    = O_SYNC | O_DIRECT,
};

void register_bs_module(void)
{
	register_backingstore_template(&rbd_bst);
}
