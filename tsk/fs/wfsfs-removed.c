
/* wfsfs_print_map - print a bitmap */

static void
wfsfs_print_map(uint8_t * map, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (i > 0 && i % 10 == 0)
            putc('|', stderr);
        putc(isset(map, i) ? '1' : '.', stderr);
    }
    putc('\n', stderr);
}


/* wfsfs_imap_load - look up inode bitmap & load into cache
 *
 * Note: This routine assumes &wfsfs->lock is locked by the caller.
 *
 * return 0 on success and 1 on error
 * */
static uint8_t
wfsfs_imap_load(WFSFS_INFO * wfsfs)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & wfsfs->fs_info;
    ssize_t  cnt;
    uint32   inode_blk_ind, inode_ind, inode_ofs;
    uint8_t  inode_blk[ext2fs->fs_info.block_size];
    TSK_DADDR_T addr;

    /* Allocate the cache buffer and exit if map is already loaded */
    if (wfsfs->imap_buf == NULL) {
        len = (wfsfs->fs->s_num_frags - 1) / 8 + 1;
        if ((wfsfs->imap_buf = (uint8_t *) tsk_malloc(len)) == NULL) {
                return 1;
        }
    }

    addr = tsk_getu32(fs->endian, wfsfs->fs->s_first_index_block);
    inode_ind = 0;

    for (inode_blk_ind = 0; inode_blk_ind < INODE_TABLE_SIZE(wfsfs); inode_blk_ind++) {
        if (addr > fs->last_block) {
            free(wfsfs->imap_buf);
            wfsfs->imap_buf = NULL;
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_BLK_NUM);
            tsk_error_set_errstr
                ("wfsfs_imap_load: Block too large for image: %" PRIu64, addr);
            return 1;
        }

        cnt = tsk_fs_read(fs, addr * fs->block_size,
                    (char *) inode_blk, wfsfs->fs_info.block_size);

        if (cnt != wfsfs->fs_info.block_size) {
            if (cnt >= 0) {
                free(wfsfs->imap_buf);
                wfsfs->imap_buf = NULL;
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("wfsfs_imap_load: Inode bitmap %"
                PRIu32 " at %" PRIu64, inode_blk_ind, addr);
            return 1;
        }

        for (inode_ofs = 1; inode_ofs < wfsfs->fs_info.block_size;
                            inode_ofs += WFS_INODE_SIZE) {
            if (inode_blk[inode_ofs] == 0x02 ||
                inode_blk[inode_ofs] == 0x03)
                SET_BIT(wfsfs->imap_buf, inode_ind);
            else
                UNSET_BIT(wfsfs->imap_buf, inode_ind);

            inode_ind += 1;
        }
        addr += 1;
    }

    return 0;
}

