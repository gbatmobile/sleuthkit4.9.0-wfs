/*
** wfsfs_dent
** The Sleuth Kit
**
** File name layer support for an WFS 0.4/0.5
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2006 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILS
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file wfsfs_dent.c
 * Contains the internal TSK file name processing code for WFS0.4/0.5
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

#include <ctype.h>
#include "tsk_fs_i.h"
#include "tsk_wfsfs.h"


static void
wfsfs_gen_dentry (TSK_INUM_T i_num,
    char *wfs_inode,  TSK_FS_NAME * fs_name)
{
    WFSFS_INODE *dir = (WFSFS_INODE *) wfs_inode;

    if (tsk_verbose)
        tsk_fprintf(stderr, "wfsfs_gen_dentry: Processing dir_entry %"
                PRIu64 ": camera %d\n",i_num,
                WFSFS_CAM_NUM(dir->i_camera[0]));

    time_t stime = wfsfs_mktime(dir->i_time_start);
    struct tm *stmTime = localtime(&stime);
    /* localtime is not reentrant. So we need save values
       before call again. */
    int year   = stmTime->tm_year + 1900;
    int month  = stmTime->tm_mon + 1;
    int day    = stmTime->tm_mday;
    int s_hour = stmTime->tm_hour;
    int s_min  = stmTime->tm_min;
    int s_sec  = stmTime->tm_sec;

    time_t etime = wfsfs_mktime(dir->i_time_end);
    struct tm *etmTime = localtime(&etime);

    sprintf(fs_name->name,
            "Vid-%04d%02d%02d-%02d%02d%02d-%02d%02d%02d.%03d.h264",
            year, month, day, s_hour, s_min, s_sec,
            etmTime->tm_hour, etmTime->tm_min, etmTime->tm_sec,
            WFSFS_CAM_NUM(dir->i_camera[0]));


    fs_name->meta_addr = i_num;
    fs_name->name_size = strlen(fs_name->name);
    fs_name->type = TSK_FS_NAME_TYPE_REG;
    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
}

static void
wfsfs_gen_dir_name (TSK_INUM_T i_num,
        const char *name,  TSK_FS_NAME * fs_name)
{
    strcpy(fs_name->name, name);
    fs_name->meta_addr = i_num;
    fs_name->name_size = strlen(fs_name->name);
    fs_name->par_addr = i_num;
    fs_name->type = TSK_FS_NAME_TYPE_DIR;
    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
}

TSK_RETVAL_ENUM
wfsfs_gen_root (WFSFS_INFO * wfsfs, TSK_INUM_T i_num)
{
    TSK_FS_META* fs_meta = wfsfs->root_inode;
    if ((fs_meta == NULL) && (fs_meta = tsk_fs_meta_alloc(0)) == NULL)
        return TSK_ERR;

    wfsfs->root_inode = fs_meta;
    fs_meta->tag = TSK_FS_DIR_TAG;
    fs_meta->type = TSK_FS_META_TYPE_DIR;
    // set the mode
    fs_meta->mode = 0;
    fs_meta->nlink = 3;
    fs_meta->addr = i_num;
    fs_meta->flags = TSK_FS_META_FLAG_ALLOC;
    fs_meta->atime = 0;
    fs_meta->ctime = wfsfs_mktime(wfsfs->sb.s_time_oldest_creation);
    fs_meta->mtime = wfsfs_mktime(wfsfs->sb.s_time_newest_modification);
    fs_meta->size = 0;
    fs_meta->seq = i_num;
    fs_meta->nlink = 1;
    fs_meta->flags |= TSK_FS_META_FLAG_USED;

    return TSK_OK;
}

/** \internal
* Process a directory and load up FS_DIR with the entries. If a pointer to
* an already allocated FS_DIR structure is given, it will be cleared.  If no existing
* FS_DIR structure is passed (i.e. NULL), then a new one will be created. If the return
* value is error or corruption, then the FS_DIR structure could
* have entries (depending on when the error occurred).
*
* @param a_fs File system to analyze
* @param a_fs_dir Pointer to FS_DIR pointer. Can contain an already allocated
* structure or a new structure.
* @param a_addr Address of directory to process.
* @returns error, corruption, ok etc.
*/

TSK_RETVAL_ENUM
wfsfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir, TSK_INUM_T i_num)
{
    WFSFS_INFO *wfsfs = (WFSFS_INFO *) a_fs;
    TSK_FS_DIR *fs_dir;
    ssize_t     cnt;
    uint32_t    inode_blk_ind, inode_ind, inode_ofs;
    uint8_t     *inode_blk;
    TSK_DADDR_T addr;
    TSK_INUM_T  max_inode;

    if (i_num != a_fs->root_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("wfsfs_dir_open_meta: inode value: %"
            PRIuINUM "\n", i_num);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("wfsfs_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "wfsfs_dir_open_meta: Processing directory %" PRIuINUM
            "\n", i_num);
    }

    fs_dir = *a_fs_dir;
    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
        fs_dir->addr = i_num;
    }
    else {
        if ((*a_fs_dir = fs_dir =
                tsk_fs_dir_alloc(a_fs, i_num, 512)) == NULL) {
            return TSK_ERR;
        }
    }

    TSK_FS_NAME *fs_name = tsk_fs_name_alloc(WFSFS_MAXNAMLEN, 0);
    if (fs_name == NULL) {
        tsk_fs_dir_close(fs_dir);
        return TSK_ERR;
    }

    if ((fs_dir->fs_file = tsk_fs_file_alloc(a_fs)) == NULL) {
        tsk_fs_name_free(fs_name);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
        tsk_error_set_errstr
            ("wfsfs_dir_open_meta: Error in memory allocation for dir.");
        return TSK_ERR;
    }
    fs_dir->addr = i_num;

    wfsfs_gen_dir_name(a_fs->root_inum, ".", fs_name);
    if (tsk_fs_dir_add(fs_dir, fs_name)) {
        tsk_fs_name_free(fs_name);
        return TSK_ERR;
    }

    wfsfs_gen_dir_name(a_fs->root_inum, "..", fs_name);
    if (tsk_fs_dir_add(fs_dir, fs_name)) {
        tsk_fs_name_free(fs_name);
        return TSK_ERR;
    }

    if ((inode_blk = (uint8_t *) tsk_malloc(a_fs->block_size)) == NULL) {
        tsk_fs_name_free(fs_name);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUX_MALLOC);
        tsk_error_set_errstr
        ("wfsfs_dir_open_meta: Error in memory allocation for disk block.");
        return TSK_ERR;
    }

    addr = tsk_getu32(a_fs->endian, wfsfs->sb.s_first_index_block);
    inode_ind = 0;
    max_inode = tsk_getu32(a_fs->endian, wfsfs->sb.s_last_index_valid);

    for (inode_blk_ind = 0; inode_blk_ind < WFSFS_INODE_TABLE_SIZE(wfsfs); inode_blk_ind++) {
        if (addr > a_fs->last_block) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_BLK_NUM);
            tsk_error_set_errstr
                ("wfsfs_dir_open_meta: Block too large for image: %" PRIu64, addr);
            return 1;
        }

        cnt = tsk_fs_read(a_fs, addr * a_fs->block_size,
                    (char *) inode_blk, a_fs->block_size);

        if (cnt != a_fs->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("wfsfs_dir_open_meta: Inode block %"
                PRIu32 " at %" PRIu64, inode_blk_ind, addr);
            return 1;
        }

        for (inode_ofs = 0; (inode_ofs < a_fs->block_size); 
                   inode_ofs += WFSFS_INODE_SIZE) {
            if ((inode_ind < a_fs->root_inum) &&
                (inode_blk[inode_ofs+1] == 0x02 ||
                inode_blk[inode_ofs+1] == 0x03)) {                    
                    wfsfs_gen_dentry (inode_ind,
                            (char *) &inode_blk[inode_ofs], fs_name);
                    if (tsk_fs_dir_add(fs_dir, fs_name)) {
                        tsk_fs_name_free(fs_name);
                        return TSK_ERR;
                    }
            }

            inode_ind += 1;
        }
        addr += 1;
    }

    /*
    wfsfs_gen_dir_name(a_fs->root_inum, "/", fs_name);
    fs_dir->fs_file->name = fs_name;
    */

    free(inode_blk);
    tsk_fs_name_free(fs_name);
    return TSK_OK;
}
