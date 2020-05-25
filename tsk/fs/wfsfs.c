/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/**
 *\file wfsfs.c
 * Contains the internal TSK WFS0.4/5 file system functions.
 */

/* WFS Decoder
 * LICENSE
 *	This software is distributed under GNU Public License.
 * AUTHOR(S)
 *	Galileu Batista (gbat2k ... gbatmobile)
 *	Brazilian Federal Police & Federal Institute of Technonoly in RN
 *	Natal, RN, BRAZIL
 *
 * Copyright (c) 2020 Galileu Batista.  All rights reserved
 *
 --*/

#include "tsk_fs_i.h"
#include "tsk_wfsfs.h"
#include "tsk/base/crc.h"
#include <stddef.h>
#include <time.h>

#define WFS_DBG 1
#ifdef WFS_DBG

void
wfs_debug_print_buf(const char *msg, const uint8_t *buf, int len)
{
    tsk_fprintf(stderr, msg);
    int i = 0;
    for (i = 0; i < len; i++) {
        if (i % 8 == 0)
        tsk_fprintf(stderr, "%08X:\t", i);
        tsk_fprintf(stderr, "0x%02X ", buf[i]);
        if ((i + 1) % 8 == 0)
            tsk_fprintf(stderr, "\n");
    }
    tsk_fprintf(stderr, "\n");
}
#endif

time_t
wfsfs_mktime(const uint8_t *wfs_time) {
    struct tm tm;
    tm.tm_year = (wfs_time[3] >> 2) + 100;
    tm.tm_mon  = ((wfs_time[3] & 0x03) << 2) + (wfs_time[2] >> 6) - 1;
    tm.tm_mday = (wfs_time[2] >> 1) & 0x1F;
    tm.tm_hour = ((wfs_time[2] << 4) + (wfs_time[1] >> 4)) & 0x1F;
    tm.tm_min  = ((wfs_time[1] << 2) + (wfs_time[0] >> 6)) & 0x3F;
    tm.tm_sec  = wfs_time[0] & 0x3F;
    return mktime(&tm);

    wfs_debug_print_buf("timestamp: \n", wfs_time, 4);
}

static uint64_t
wfsfs_get_file_size (WFSFS_INFO *wfsfs, const WFSFS_INODE * dino_buf)
{
    uint64_t size = 0;

    int   nfrag = tsk_getu32(TSK_LIT_ENDIAN, dino_buf->i_numb_frag);
    int   blk_per_frag = tsk_getu32(TSK_LIT_ENDIAN,
                        wfsfs->sb.s_blocks_per_frag);
    size = nfrag * blk_per_frag;
    size += tsk_getu16(TSK_LIT_ENDIAN, dino_buf->i_blks_in_last);
    size *= wfsfs->fs_info.block_size;
    return size;
}

static uint8_t
wfs_dump_inode(WFSFS_INFO * wfsfs, TSK_INUM_T dino_inum,
        WFSFS_INODE *dino_buf) {

    int to_load = dino_buf == NULL;
    TSK_OFF_T    addr;
    ssize_t      cnt;
    WFSFS_SB    *sb = (WFSFS_SB *) &(wfsfs->sb);
    TSK_FS_INFO *fs = (TSK_FS_INFO *) wfsfs;

    TSK_INUM_T max_inode  = fs->root_inum;
    if (dino_inum >= max_inode) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("wfsfs_dinode_load: address: %" PRIuINUM ".\n",
                dino_inum);
        return 1;
    }

    if (to_load) {
        if ((dino_buf = (WFSFS_INODE *) tsk_malloc(WFSFS_INODE_SIZE)) == NULL)
            return 1;

        addr = tsk_getu32(fs->endian, sb->s_first_index_block)
                   * tsk_getu32(fs->endian, sb->s_block_size)
                + dino_inum * WFSFS_INODE_SIZE;

        cnt = tsk_fs_read(fs, addr, (char *) dino_buf, WFSFS_INODE_SIZE);

        if (cnt != WFSFS_INODE_SIZE) {
            free(dino_buf);
            return 1;
        }
    }

    time_t t_start = wfsfs_mktime(dino_buf->i_time_start);
    char   t_start_buf[128];

    time_t t_end = wfsfs_mktime(dino_buf->i_time_end);
    char   t_end_buf[128];
    int    is_main = dino_buf->i_type_desc[0] == 0x02 ||
                     dino_buf->i_type_desc[1] == 0x03;

     if (! to_load)  // Only shows if inode has been loaded
        tsk_fprintf(stderr,
            "Inode num= %" PRIuINUM "\n",
            dino_inum);

    tsk_fprintf(stderr,
        "\tDescriptor type= %d (2 or 3 for main)\n"
        "\tNext Fragment= %d\n"
        "\tCreation time= %" PRIu64 " (%s)\n"
        "\tModification time= %" PRIu64 " (%s)\n",
        dino_buf->i_type_desc[0],
        tsk_getu32(TSK_LIT_ENDIAN, dino_buf->i_next_frag),
        t_start, tsk_fs_time_to_str(t_start, t_start_buf),
        t_end, tsk_fs_time_to_str(t_end, t_end_buf),
        wfsfs_mktime (dino_buf->i_time_end));

    if (is_main)
        tsk_fprintf(stderr,
            "\t#Fragments= %d (size %ld bytes)\n",
            tsk_getu16(TSK_LIT_ENDIAN, dino_buf->i_numb_frag) +1,
            wfsfs_get_file_size(wfsfs, dino_buf));
    else
        tsk_fprintf(stderr,
            "\tFragment number= %d\n",
            tsk_getu16(TSK_LIT_ENDIAN, dino_buf->i_numb_frag));


    if (to_load)
        free(dino_buf);

    return 0;
}

/* wfsfs_dinode_load - look up disk inode & load into wfsfs_inode structure
 * @param wfsfs A wfsfs file system information structure
 * @param dino_inum Metadata address
 * @param dino_buf The buffer to store the block in (must be size of wfsfs->inode_size or larger)
 *
 * return 1 on error and 0 on success
 * */

static uint8_t
wfsfs_dinode_load(WFSFS_INFO * wfsfs, TSK_INUM_T dino_inum,
    WFSFS_INODE * dino_buf)
{
    TSK_OFF_T addr;
    ssize_t cnt;
    WFSFS_SB *sb = (WFSFS_SB *) &(wfsfs->sb);
    TSK_FS_INFO *fs = (TSK_FS_INFO *) wfsfs;

    TSK_INUM_T min_inode  = tsk_getu32(fs->endian, sb->s_num_reserv_frags);
    TSK_INUM_T max_inode  = fs->root_inum;

    if ((dino_inum < min_inode) ||
        (dino_inum >= max_inode)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("wfsfs_dinode_load: address: %" PRIuINUM
            " (valid: %" PRIuINUM "..%" PRIuINUM ").",
            dino_inum, min_inode, max_inode-1);
        return 1;
    }

    if (dino_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("wfsfs_dinode_load: dino_buf is NULL");
        return TSK_ERR;
    }

    addr = tsk_getu32(fs->endian, sb->s_first_index_block)
               * tsk_getu32(fs->endian, sb->s_block_size)
            + dino_inum * WFSFS_INODE_SIZE;

    cnt = tsk_fs_read(fs, addr, (char *) dino_buf, WFSFS_INODE_SIZE);

    if (cnt != WFSFS_INODE_SIZE) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("wfsfs_dinode_load: Inode %" PRIuINUM
            " from %" PRIdOFF, dino_inum, addr);
        return TSK_ERR;
    }

    if (dino_buf->i_type_desc[0] != 0x02 &&
        dino_buf->i_type_desc[0] != 0x03) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr2("wfsfs_dinode_load: Inode %" PRIuINUM
            " from %" PRIdOFF " is not valid.", dino_inum, addr);

        return TSK_ERR;
    }

    if (tsk_verbose)
        wfs_dump_inode(wfsfs, dino_inum, dino_buf);

    return TSK_OK;
}


/* wfsfs_dinode_copy - copy cached disk inode into generic inode
 *
 * returns 1 on error and 0 on success
 * */
static uint8_t
wfsfs_dinode_copy(WFSFS_INFO * wfsfs, TSK_FS_META * fs_meta,
    TSK_INUM_T inum, const WFSFS_INODE * dino_buf)
{
    if (dino_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("wfsfs_dinode_copy: dino_buf is NULL");
        return 1;
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    fs_meta->type = TSK_FS_META_TYPE_REG;
    fs_meta->mode = 0;
    fs_meta->nlink = 1;
    fs_meta->addr = inum;
    fs_meta->flags = TSK_FS_META_FLAG_ALLOC;

    fs_meta->atime = 0;
    fs_meta->ctime = wfsfs_mktime(dino_buf->i_time_start);
    fs_meta->mtime = wfsfs_mktime(dino_buf->i_time_end);
    fs_meta->size = wfsfs_get_file_size(wfsfs, dino_buf);
    fs_meta->seq = inum;

    if (fs_meta->link) {
        free(fs_meta->link);
        fs_meta->link = NULL;
    }

    fs_meta->flags |= TSK_FS_META_FLAG_USED;

    return 0;
}


/* wfsfs_inode_lookup - lookup inode, external interface
 *
 * Returns 1 on error and 0 on success
 *
 */

static uint8_t
wfsfs_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T inum)
{
    WFSFS_INFO *wfsfs = (WFSFS_INFO *) fs;
    WFSFS_INODE *dino_buf = NULL;
    unsigned int size = 0;
    
    if (inum == fs->root_inum) {
        a_fs_file->meta = wfsfs->root_inode;
        return TSK_OK;
    }

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("wfsfs_inode_lookup: fs_file is NULL");
        return 1;
    }

    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta =
                tsk_fs_meta_alloc(WFSFS_FILE_CONTENT_LEN)) == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    size = WFSFS_INODE_SIZE;
    if ((dino_buf = (WFSFS_INODE *) tsk_malloc(size)) == NULL) {
        return 1;
    }

    if (wfsfs_dinode_load(wfsfs, inum, dino_buf)) {
        free(dino_buf);
        return TSK_ERR;
    }

    if (wfsfs_dinode_copy(wfsfs, a_fs_file->meta, inum, dino_buf)) {
        free(dino_buf);
        return TSK_ERR;
    }

    free(dino_buf);
    return TSK_OK;
}


TSK_FS_ATTR_TYPE_ENUM
wfsfs_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}


/** \internal
 * Add the data runs and extents to the file attributes.
 *
 * @param fs_file File system to analyze
 * @returns 0 on success, 1 otherwise
 */
static uint8_t
wfsfs_load_attrs(TSK_FS_FILE * fs_file)
{
    TSK_FS_ATTR  *fs_attr;
    TSK_FS_META  *fs_meta = fs_file->meta;
    TSK_FS_INFO  *fs = fs_file->fs_info;
    WFSFS_INFO  *wfsfs = (WFSFS_INFO *) fs;
    WFSFS_SB    *sb = &(wfsfs->sb);
    WFSFS_INODE  inode_blk;
    ssize_t       cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "wfsfs_load_attrs: Processing file %" PRIuINUM "\n",
            fs_meta->addr);

    // see if we have already loaded the runs
    if ((fs_meta->attr != NULL)
        && (fs_meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
        return 0;
    }

    if (fs_meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }

    if (TSK_FS_TYPE_ISWFS(fs->ftype) == 0) {
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr
            ("wfsfs_load_attrs: Called with non-WFS0.4/5 file system: %x",
            fs->ftype);
        return 1;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "wfsfs_load_attrs: Processing file %" PRIuINUM
            " in normal mode\n", fs_meta->addr);
    }

    TSK_FS_ATTR_RUN *data_run = NULL;
    TSK_FS_ATTR_RUN *data_run_head = NULL;
    TSK_DADDR_T index_start_blk = tsk_getu32(fs->endian, sb->s_first_index_block);

    int blocks_per_frag = tsk_getu32(fs->endian, sb->s_blocks_per_frag);
    int block_size = tsk_getu32(fs->endian, sb->s_block_size);

    int cur_frag = fs_meta->addr;
    TSK_OFF_T size_remain = fs_meta->size;

    while (size_remain > 0) {
        TSK_DADDR_T cur_block = WFSFS_FRAG_2_BLOCK(sb, cur_frag);

        if (cur_block > fs->last_block) {
            fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
            tsk_error_reset();

            tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
            tsk_error_set_errstr
                ("wfsfs_load_attrs: Invalid block address in WFS: %"
                PRIuDADDR " (block size: %d bytes)", cur_block, block_size);
            return 1;
        }

        // see if we need a new run
        TSK_FS_ATTR_RUN *data_run_tmp = tsk_fs_attr_run_alloc();
        if (data_run_tmp == NULL) {
            tsk_fs_attr_run_free(data_run_head);
            fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
            return 1;
        }

        data_run_tmp->len = (size_remain/block_size) < blocks_per_frag ?
                            (size_remain/block_size) : blocks_per_frag;
        data_run_tmp->addr = cur_block;

        if (data_run_head == NULL) {
            data_run_head = data_run_tmp;
            data_run_tmp->offset = 0;
        }
        else {
            data_run->next = data_run_tmp;
            data_run_tmp->offset = data_run->offset + data_run->len;
        }
        data_run = data_run_tmp;

        if ((int64_t) size_remain > 0) {
            size_remain -= (data_run->len * block_size);

            TSK_DADDR_T inode_addr = index_start_blk * block_size +
                                        cur_frag * WFSFS_INODE_SIZE;
            cnt = tsk_fs_read(fs, inode_addr,
                        (char *) &inode_blk, WFSFS_INODE_SIZE);

            if (cnt != WFSFS_INODE_SIZE) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("wfsfs_load_attrs: Inode %d"
                    " from %" PRIuDADDR, cur_frag, inode_addr);
                return 1;
            }

            cur_frag = tsk_getu32(fs->endian, inode_blk.i_next_frag);
        }
    }

    if ((fs_meta->attr == NULL) &&
        ((fs_meta->attr = tsk_fs_attrlist_alloc()) == NULL)) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    // add the run list to the inode structure
    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_meta->attr,
                TSK_FS_ATTR_RES)) == NULL) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, data_run_head, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            fs_meta->size, fs_meta->size, fs_meta->size, 0, 0)) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;

    return TSK_OK;
}

TSK_FS_BLOCK_FLAG_ENUM
wfsfs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    WFSFS_INFO* wfsfs = (WFSFS_INFO*) a_fs;
    uint32_t s_blocks_per_frag = tsk_getu32(a_fs->endian,
        wfsfs->sb.s_blocks_per_frag);
    TSK_DADDR_T s_first_data_block = 
        tsk_getu32(a_fs->endian, wfsfs->sb.s_first_data_block);
    TSK_DADDR_T s_newest_data_block =
        s_first_data_block +
        s_blocks_per_frag *
        (tsk_getu32(a_fs->endian, wfsfs->sb.s_index_last_frag) + 1) - 1;
    TSK_DADDR_T s_oldest_data_block =
        s_first_data_block +
        s_blocks_per_frag *
        tsk_getu32(a_fs->endian, wfsfs->sb.s_index_first_frag);
    TSK_DADDR_T s_last_reserved_data_block =
        s_first_data_block +
        s_blocks_per_frag *
        (tsk_getu32(a_fs->endian, wfsfs->sb.s_num_reserv_frags) + 1) - 1;

    if (a_addr < s_first_data_block)
        return TSK_FS_BLOCK_FLAG_META | TSK_FS_BLOCK_FLAG_ALLOC;

    if (a_addr <= s_last_reserved_data_block)
        return TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_UNALLOC;

    if (a_addr <= s_newest_data_block)
        return TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC;

    if (a_addr >= s_oldest_data_block)
        return TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC;

    return TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_UNALLOC;
}

/* wfsfs_block_walk - block iterator
 *
 * flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_CONT,
 *  TSK_FS_BLOCK_FLAG_META
 *
 *  Return 1 on error and 0 on success
*/

uint8_t
wfsfs_block_walk(TSK_FS_INFO * a_fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr)
{
    char* myname = "wfsfs_block_walk";
    TSK_FS_BLOCK* fs_block;
    TSK_DADDR_T addr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (a_start_blk < a_fs->first_block || a_start_blk > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: start block: %" PRIuDADDR, myname,
            a_start_blk);
        return TSK_ERR;
    }
    if (a_end_blk < a_fs->first_block || a_end_blk > a_fs->last_block
        || a_end_blk < a_start_blk) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: end block: %" PRIuDADDR, myname,
            a_end_blk);
        return TSK_ERR;
    }

    /* Sanity check on a_flags -- make sure at least one ALLOC is set */
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
                TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }

    if ((fs_block = tsk_fs_block_alloc(a_fs)) == NULL) {
        return TSK_ERR;
    }

    for (addr = a_start_blk; addr <= a_end_blk; addr++) {
        int retval;
        int myflags;

        myflags = wfsfs_block_getflags(a_fs, addr);

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_META)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_META)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_CONT)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;

        if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
            myflags |= TSK_FS_BLOCK_FLAG_AONLY;

        if (tsk_fs_block_get_flag(a_fs, fs_block, addr, myflags) == NULL) {
            tsk_error_set_errstr2("%s: block %" PRIuDADDR,
                myname, addr);
            tsk_fs_block_free(fs_block);
            return 1;
        }

        retval = a_action(fs_block, a_ptr);
        if (retval == TSK_WALK_STOP) {
            break;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_block_free(fs_block);
            return 1;
        }
    }

    tsk_fs_block_free(fs_block);
    return TSK_OK;
}

/* return 1 on error and 0 on success */
uint8_t
wfsfs_inode_walk(TSK_FS_INFO * fs,
        TSK_INUM_T a_start_inum, TSK_INUM_T a_end_inum,
        TSK_FS_META_FLAG_ENUM a_flags, TSK_FS_META_WALK_CB a_action,
        void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("inode_walk not implemented for WFS0.4/5");
    return TSK_ERR;
}

/* return 1 on error and 0 on success */
uint8_t
wfsfs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("WFS0.4/5 does not have a journal");
    return 1;
}

/* return 1 on error and 0 on success */
uint8_t
wfsfs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented for WFS0.4/5 yet");
    return 1;
}

/* return 1 on error and 0 on success */
uint8_t
wfsfs_jentry_walk(TSK_FS_INFO * fs, int a_flags,
    TSK_FS_JENTRY_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("WFS0.4/5 does not have a journal");
    return 1;
}

/* return 1 on error and 0 on success */
uint8_t
wfsfs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    int a_flags, TSK_FS_JBLK_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("WFS0.4/5 does not have a journal");
    return 1;
}


/**
 * Print details about the file system to a file handle.
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
wfsfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    WFSFS_INFO *wfsfs = (WFSFS_INFO *) fs;
    WFSFS_SB *sb = &(wfsfs->sb);
    time_t tmptime;
    char timeBuf[128];
    const char *tmptypename;


    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    switch (fs->ftype) {
    case TSK_FS_TYPE_WFS_04:
        tmptypename = "WFS0.4";
        break;
    case TSK_FS_TYPE_WFS_05:
        tmptypename = "WFS0.5";
        break;
    default:
        tmptypename = "WFS0.4";
    }

    tsk_fprintf(hFile, "File System Type: %s\n", tmptypename);
    tsk_fprintf(hFile, "Block size (in bytes): %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_block_size));
    tsk_fprintf(hFile, "Blocks per fragment: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_blocks_per_frag));
    tsk_fprintf(hFile, "Fragment size (in bytes): %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_block_size) *
        tsk_getu32(fs->endian, sb->s_blocks_per_frag));
    tsk_fprintf(hFile, "Root inode (virtual): %" PRIu64 "\n",
        fs->root_inum);

    tsk_fprintf(hFile, "\nTIMESTAMPS:\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tmptime = wfsfs_mktime(sb->s_time_first_creation);
    tsk_fprintf(hFile, "First fragment creation: %s\n",
        (tmptime > 0) ? tsk_fs_time_to_str(tmptime, timeBuf) : "empty");

    tmptime = wfsfs_mktime(sb->s_time_last_modification);
    tsk_fprintf(hFile, "Last fragment modification: %s\n",
        (tmptime > 0) ? tsk_fs_time_to_str(tmptime, timeBuf) : "empty");

    tmptime = wfsfs_mktime(sb->s_time_oldest_creation);
    tsk_fprintf(hFile, "Oldest fragment creation: %s\n",
        (tmptime > 0) ? tsk_fs_time_to_str(tmptime, timeBuf) : "empty");

    tmptime = wfsfs_mktime(sb->s_time_newest_modification);
    tsk_fprintf(hFile, "Newest Fragment modification: %s\n",
        (tmptime > 0) ? tsk_fs_time_to_str(tmptime, timeBuf) : "empty");

    tsk_fprintf(hFile, "\nDISK FRAGMENTS:\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Number of fragments: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_total_indexes));

    tsk_fprintf(hFile, "First fragment number (after reserveds): %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_num_reserv_frags));
    wfs_dump_inode(wfsfs, tsk_getu32(fs->endian, sb->s_num_reserv_frags),
                        NULL);
    tsk_fprintf(hFile, "Last fragment number: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_last_index_valid));
    wfs_dump_inode(wfsfs, tsk_getu32(fs->endian, sb->s_last_index_valid),
                        NULL);

    tsk_fprintf(hFile, "Newest fragment number: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_index_last_frag));
    wfs_dump_inode(wfsfs, tsk_getu32(fs->endian, sb->s_index_last_frag),
                        NULL);

    tsk_fprintf(hFile, "Oldest fragment number: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_index_first_frag));
    wfs_dump_inode(wfsfs, tsk_getu32(fs->endian, sb->s_index_first_frag),
                        NULL);

    tsk_fprintf(hFile, "\nDISK AREAS:\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Block size (in bytes): %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->s_block_size));
    tsk_fprintf(hFile, "Superblock block: %" PRIu32 " (%" PRIu32 ")\n",
        WFSFS_SBOFF / tsk_getu32(fs->endian, sb->s_block_size),
        WFSFS_SBOFF);
    tsk_fprintf(hFile, "Index area start block: %" PRIu32 " (%" PRIu32 ")\n",
        tsk_getu32(fs->endian, sb->s_first_index_block),
        tsk_getu32(fs->endian, sb->s_first_index_block) * 
        tsk_getu32(fs->endian, sb->s_block_size));
    tsk_fprintf(hFile, "Data area start block: %" PRIu32 " (%" PRIu32 ")\n",
        tsk_getu32(fs->endian, sb->s_first_data_block),
        tsk_getu32(fs->endian, sb->s_first_data_block) * 
        tsk_getu32(fs->endian, sb->s_block_size));

    return 0;
}

/**
 * Print details on a specific file to a file handle.
 *
 * @param fs File system file is located in
 * @param hFile File handle to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
wfsfs_istat(TSK_FS_INFO * fs, TSK_FS_ISTAT_FLAG_ENUM istat_flags, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    TSK_FS_META *fs_meta;
    TSK_FS_FILE *fs_file;
    WFSFS_INFO* wfsfs = (WFSFS_INFO *) fs;

    WFSFS_INODE *dino_buf = NULL;
    char timeBuf[128];

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (inum == fs->root_inum)
        fs_meta = wfsfs->root_inode;
    else if (inum < fs->root_inum) {
        // Call wfsfs_inode_lookup. All errors checked there.
        if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
            return TSK_ERR;
        }
        fs_meta = fs_file->meta;
    }
         
    if (inum != fs->root_inum) {
        tsk_fprintf(hFile, "Video : %" PRIuINUM "\n", inum);
        tsk_fprintf(hFile, "size: %" PRIdOFF "\n", fs_meta->size);
        tsk_fprintf(hFile, "#frags: %" PRIdOFF "\n", (fs_meta->size - 1) /
            (tsk_getu32(fs->endian, wfsfs->sb.s_blocks_per_frag) *
                tsk_getu32(fs->endian, wfsfs->sb.s_block_size)) + 1);
        tsk_fprintf(hFile, "num of links: %d\n", fs_meta->nlink);

        tsk_fprintf(hFile, "File Created:\t%s\n",
            tsk_fs_time_to_str(fs_meta->ctime, timeBuf));
        tsk_fprintf(hFile, "File Modified:\t%s\n",
            tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
        if (istat_flags & TSK_FS_ISTAT_RUNLIST) {
            tsk_fprintf(hFile, "\nFragments (values in blocks of %" 
                PRIu32 " bytes):\n",
                        tsk_getu32(fs->endian, wfsfs->sb.s_block_size));
            const TSK_FS_ATTR* fs_attr_default =
                tsk_fs_file_attr_get_type(fs_file,
                    TSK_FS_ATTR_TYPE_DEFAULT, 0, 0);
            if (tsk_fs_attr_print(fs_attr_default, hFile)) {
                tsk_fprintf(hFile, "\nError creating run lists\n");
                tsk_error_print(hFile);
                tsk_error_reset();
            }
        }
    }
    else {
        tsk_fprintf(hFile, "This is the virtual root inode.\n");
    }

    tsk_fs_file_close(fs_file);
    return TSK_OK;
}


/* wfsfs_close - close an wfsfs file system */
static void
wfsfs_close(TSK_FS_INFO * fs)
{
    fs->tag = 0;
    tsk_fs_meta_close(((WFSFS_INFO*)fs)->root_inode);
    tsk_fs_free(fs);
}


/**
 * \internal
 * Open part of a disk image as a WFS0.4/5 file system.
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset where file system starts
 * @param ftype Specific type of file system
 * @param test NOT USED
 * @returns NULL on error or if data is not an WFS0.4/5 file system
 */
TSK_FS_INFO *
wfsfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM ftype, uint8_t test)
{
    unsigned int len;
    WFSFS_INFO  *wfsfs;
    TSK_FS_INFO  *fs;
    WFSFS_SB     *sb;
    wfsfs_header fs_header;   /* header block */
    ssize_t cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (TSK_FS_TYPE_ISWFS(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS Type in wfsfs_open");
        return NULL;
    }

    if (img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("wfsfs_open: sector size is 0");
        return NULL;
    }

    if ((wfsfs = (WFSFS_INFO *) tsk_fs_malloc(sizeof(*wfsfs))) == NULL)
        return NULL;

    fs = &(wfsfs->fs_info);
    sb = &(wfsfs->sb);

    fs->ftype = ftype;
    fs->flags = TSK_FS_INFO_FLAG_NONE;
    fs->img_info = img_info;
    fs->offset = offset;
    fs->tag = TSK_FS_INFO_TAG;

    /*
     * Read the header.
     */
    len = sizeof(fs_header);
    cnt = tsk_fs_read(fs, WFSFS_HEADOFS, (char *) &fs_header, len);
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("wfsfs_open: header");
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO *)wfsfs);
        return NULL;
    }

    /*
     * Verify we are looking at an WFS image
     */
    if (strncmp((char *) &fs_header, WFSFS_MAGIC_WFS04,
                strlen(WFSFS_MAGIC_WFS04)) != 0 &&
        strncmp((char *) &fs_header, WFSFS_MAGIC_WFS05,
                strlen(WFSFS_MAGIC_WFS05)) != 0) {
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO *)wfsfs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not an WFS0.4/5 file system (magic)");
        if (tsk_verbose)
            fprintf(stderr, "wfsfs_open: invalid magic\n");
        return NULL;
    }

    cnt = tsk_fs_read(fs, WFSFS_SBOFF, (char *) sb, len);
    if (cnt != len) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("wfsfs_open: superblock");
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO *)wfsfs);
        return NULL;
    }

    /*
     * Calculate the meta data info
     */
    fs->endian = TSK_LIT_ENDIAN;
    fs->block_size = tsk_getu32(fs->endian, sb->s_block_size);
    fs->dev_bsize = img_info->sector_size;
    fs->first_block = 0;
    fs->inum_count = tsk_getu32(fs->endian, sb->s_total_indexes); 
    fs->last_inum = fs->inum_count;
    fs->root_inum = fs->inum_count;
    fs->first_inum = tsk_getu32(fs->endian, sb->s_num_reserv_frags);
    fs->block_count = tsk_getu32(fs->endian, sb->s_first_data_block) +
                      tsk_getu32(fs->endian, sb->s_total_indexes) *
                      tsk_getu32(fs->endian, sb->s_blocks_per_frag);
    fs->last_block_act = fs->last_block = fs->block_count - 1;

    // sanity check
    if (fs->block_size % 512) {
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO *)wfsfs);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not an WFS04/5 file system (block size)");
        if (tsk_verbose)
            fprintf(stderr, "wfsfs_open: invalid block size\n");
        return NULL;
    }

    // determine the last block we have in this image
    if ((TSK_DADDR_T) ((img_info->size - offset) / fs->block_size) <
        fs->block_count)
        fs->last_block_act =
            (img_info->size - offset) / fs->block_size - 1;

    /* Set the generic function pointers */
    fs->inode_walk = wfsfs_inode_walk;
    fs->block_walk = wfsfs_block_walk;
    fs->block_getflags = wfsfs_block_getflags;

    fs->get_default_attr_type = wfsfs_get_default_attr_type;
    fs->load_attrs = wfsfs_load_attrs;

    fs->file_add_meta = wfsfs_inode_lookup;
    fs->dir_open_meta = wfsfs_dir_open_meta;
    fs->fsstat = wfsfs_fsstat;
    fs->istat = wfsfs_istat;

    fs->fscheck = wfsfs_fscheck;
    fs->name_cmp = tsk_fs_unix_name_cmp;
    fs->close = wfsfs_close;

    /* Journal */
    fs->jblk_walk = wfsfs_jblk_walk;
    fs->jentry_walk = wfsfs_jentry_walk;
    fs->jopen = wfsfs_jopen;

    wfsfs->root_inode = NULL;
    if (wfsfs_gen_root(wfsfs, fs->root_inum)) {
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO*)wfsfs);
        tsk_error_reset();
        tsk_error_set_errstr("wfsfs_open: error in generation of root inode.");
        if (tsk_verbose)
            fprintf(stderr, "wfsfs_open: wfsfs_open: error in generation root inode.\n");
        return NULL;
    }

    /*
     * Print some stats.
     */
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "Image / File system details:"
            "\n\t#blocks/last block: %" PRIu64 "/%" PRIu64
            "\n\t#First index/data block: %" PRIu64 "/%" PRIu64
            "\n\tFragments %" PRIu32 " blocks/fragment %" PRIu32
            "\n",
            fs->last_block, fs->block_count,
            tsk_getu32(fs->endian, sb->s_first_index_block),
            tsk_getu32(fs->endian, sb->s_first_data_block),
            tsk_getu32(fs->endian, sb->s_total_indexes),
            tsk_getu32(fs->endian, sb->s_blocks_per_frag));

    return (TSK_FS_INFO*) wfsfs;
}
