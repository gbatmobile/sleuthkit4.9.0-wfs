/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
*/

/*
 * Contains the structures and function APIs for WFS0.4/5 file system support.
 */

#ifndef _TSK_WFSFS_H
#define _TSK_WFSFS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
** Constants
*/
#define WFSFS_HEADER_BLK   0     /* Block 0  contais the Header */
#define WFSFS_SEC_SIZE     512   /* Sector size */
#define WFSFS_HEADOFS      (WFSFS_HEADER_BLK * WFSFS_SEC_SIZE)

#define WFSFS_SB_SECTOR     24    /* Block 24 contains the superblock (24 * 512 = 0x3000) */
#define WFSFS_SBOFF        (WFSFS_SB_SECTOR * WFSFS_SEC_SIZE)

#define SET_BIT(buf, bit_pos) buf[(bit_pos) / 8] |= 1 << ((bit_pos) % 8)
#define UNSET_BIT(buf, bit_pos) buf[(bit_pos) / 8] &= ~(1 << ((bit_pos) % 8))

#define WFSFS_MAGIC_WFS04       "WFS0.4"
#define WFSFS_MAGIC_WFS05       "WFS0.5"
#define WFSFS_HEADER_FOOT       "XM"

#define WFSFS_MAXNAMLEN         35  /* strlen("Vid-YYYYMMDD-HHMMSS-HHMMSS.CCC.h264") */
#define WFSFS_INODE_SIZE        32

#define WFSFS_FILE_CONTENT_LEN sizeof(TSK_DADDR_T)      // we will store the starting cluster

#define WFSFS_FRAG_2_BLOCK(sb, f)	\
	(TSK_DADDR_T)(tsk_getu32(TSK_LIT_ENDIAN,  sb->s_first_data_block) + \
                       f * tsk_getu32(TSK_LIT_ENDIAN, sb->s_blocks_per_frag))

#define WFSFS_INODE_TABLE_SIZE(wfsfs) \
    ((tsk_getu32(wfsfs->fs_info.endian, wfsfs->sb.s_total_indexes) * WFSFS_INODE_SIZE - 1) \
           / wfsfs->fs_info.block_size + 1)

#define WFSFS_CAM_NUM(cam_id) ((cam_id + 2) / 4)

    time_t wfsfs_mktime(const uint8_t* wfs_time);

    typedef struct {
        char h_fs_magic[6];
        char h_filler[504];
        char h_footer[2];
    } wfsfs_header;

/*
** Super Block
*/
    typedef struct {
        uint8_t s_filler1[16];

        uint8_t s_time_last_modification[4];
                                            // off:16 - timestamp of the last video stored 
                                            // in disk.
                                            // In general this is one the fragment neaerst
                                            //   format: YYYYYYMMMMDDDDDHHHHHmmmmmmSSSSSS

        uint8_t s_time_newest_modification[4];
                                            // off:20 -timestamp of the first fragment stored 
                                            // in disk.
                                            // In general this fragment is stored just before
                                            // the fragments reserved to be overwritten in
                                            // following operation
                                            //    format: YYYYYYMMMMDDDDDHHHHHmmmmmmSSSSSS

        uint8_t s_index_last_frag[4];       // off:24 - number of the last (newest) fragment 
                                            // in a video.
        uint8_t s_index_first_frag[4];      // off:28 - number of the first fragment (oldest) 
                                            // in a video.

        uint8_t s_last_index_valid[4];      // off:32 - last index/fragment in disk

        uint8_t s_time_oldest_creation[4];  // off:36
                                            // timestamp of the first video (oldest) stored in disk.
                                            // In general, the first video right after ones
                                            // reserved to be overwritten in following operation.
                                            //    format: YYYYYYMMMMDDDDDHHHHHmmmmmmSSSSSS

        uint8_t s_time_first_creation[4];   // off:40
                                            // timestamp of the first fragment in disk
                                            // in general, the first fragment after
                                            // the reserved ones in the start of disk.
                                            //    format: YYYYYYMMMMDDDDDHHHHHmmmmmmSSSSSS

        uint8_t s_block_size[4];            // off:44 - block size in bytes 
                                            //     (tipycally: 512 - one sector)
        uint8_t s_blocks_per_frag[4];       // off:48 - blocks per fragment
        uint8_t s_filler2[4];               // off:52 - Unknown - values identified: 0x00000000
        uint8_t s_num_reserv_frags[4];      // off:56 - Number of indexes/fragments in the 
                                            //      beginning of fs not used
        uint8_t s_filler3[4];               // off:60 - Unknown - values identified: 0x00003100

        uint8_t s_filler4[4];               // off:64 - Unknown - values identified: 0x00000018
        uint8_t s_first_index_block[4];     // off:68 - first disk block in index area
        uint8_t s_first_data_block[4];      // off:72 - first disk block in data area
        uint8_t s_total_indexes[4];         // off:76 - Number of indexes (and fragments) in 
                                            //      file system
        uint8_t s_filler5[432];             // off:80
    } WFSFS_SB;

/*
 * Inode
 */
    typedef struct {
        uint8_t i_filler1[1],        /* off:0   */
                i_type_desc[1],      /* off:1   */
                i_numb_frag[2],      /* off:2 - */
                                     //    Extra fragments in this file - inode (0x02 or 0x03).
                                     //    Fragment number for continuation (0x01).
                i_prev_frag[4],      /* off:4   */
                i_next_frag[4],      /* off:8   */
                i_time_start[4],     /* off:12  */
                i_time_end[4],       /* off:16  */
                i_filler2[2],        /* off:20  */
                i_blks_in_last[2],   /* off:22  */
                i_main_frag[4],      /* off:24  */
                i_filler3[2],        /* off:28  */
                i_frag_order[1],     /* off:30  */
                i_camera[1];         /* off:31  */
    } WFSFS_INODE;

/*
 * directory entries
 */
    typedef struct {
        uint8_t d_type[1];                   /* 1 - datedir;  2 - camdir; 3 - file */
        union {
            uint8_t             d_inode[4];
            struct WFSFS_DENTRY *next_dent;
        };
        uint8_t d_name_len[2];
        char    d_name[WFSFS_MAXNAMLEN];
    } WFSFS_DENTRY;

    /*
     * Structure of an WFS file system handle.
     */
    typedef struct {
        TSK_FS_INFO   fs_info;      /* super class */
        WFSFS_SB      sb;           /* super block */
        TSK_FS_META   *root_inode;  /* root inode (virtual) */
    } WFSFS_INFO;


    TSK_RETVAL_ENUM
        wfsfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
            TSK_INUM_T a_addr);
    void
        wfs_debug_print_buf(const char* msg,
            const uint8_t* buf, int len);

        TSK_RETVAL_ENUM
        wfsfs_gen_root(WFSFS_INFO* wfsfs, TSK_INUM_T i_num);

#ifdef __cplusplus
}
#endif
#endif
