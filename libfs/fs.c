#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "disk.h"
#include "fs.h"

// type and struct definition
struct superblock {
    uint64_t signature;
    uint16_t total_block_amount;
    uint16_t root_index;
    uint16_t data_start_index;
    uint16_t data_block_amount;
    uint8_t fat_amount;
    uint8_t padding[4079];
}__attribute__((packed));

struct root_dir {
    uint8_t file_name[16];
    uint32_t file_size;
    uint16_t first_data_index;
    uint16_t padding[5];
}__attribute__((packed));

typedef struct root_dir root_dir;

// define global variables
struct superblock spb;
uint16_t *fat_array;
root_dir root_array[128];
bool mount = false;

int fs_mount(const char *diskname)
{
    if (block_disk_open(diskname)) {
        return -1;
    }
    // Superblock creation
    if (block_read(0, &spb)) {
        return -1;
    };
    if(memcmp(&(spb.signature), "ECS150FS", 8)) {
        return -1;
    }

    if(spb.total_block_amount != block_disk_count()) {
        return -1;
    }

    // FAT creation
    int fat_total_entry = (spb.fat_amount) * 4096;
    fat_array = (uint16_t *)malloc(fat_total_entry * sizeof(uint16_t));
    for (int i = 0; i < spb.fat_amount + 1; i++) {
        // superblock is at 0, fat array starts in the 1st block
        if (block_read(i + 1, fat_array + i * 2048)) {
            return -1;
        }
    }
    // Root directory creation
    if (block_read(spb.root_index, root_array)) {
        return -1;
    }

    mount = true;
    return 0;
}
//./test_fs.x info disk.fs
int fs_umount(void)
{
    if (!mount) {
        return -1;
    }
    if (block_write(0, &spb)) {
        return -1;
    }
    for (int i = 0; i < spb.fat_amount + 1; i++) {
        // superblock is at 0, fat array starts in the 1st block
        if (block_write(i + 1, fat_array + i * 2048)) {
            return -1;
        }
    }
    if (block_write(spb.root_index, root_array)) {
        return -1;
    }
    if (block_disk_close()) {
        return -1;
    }
    // clean

    free(fat_array);
    mount = false;
    return 0;
}

int fs_info(void)
{
    /* TODO: Phase 1 */
    if (!mount) {
        return -1;
    }
    printf("FS Info:\n");
    printf("total_blk_count=%d\n", spb.total_block_amount);
    printf("fat_blk_count=%d\n", spb.fat_amount);
    printf("rdir_blk=%d\n", spb.root_index);
    printf("data_blk=%d\n", spb.data_start_index);
    printf("data_blk_count=%d\n", spb.data_block_amount);
    int fat_count;
    for (int i = 0; i < spb.data_block_amount; i++) {
        if (fat_array[i] == 0) {
            fat_count++;
        }
    }
    printf("fat_free_ratio=%d/%d\n", fat_count, spb.data_block_amount);
    int root_count = 0;
    for (int i = 0; i < 128; i++) {
        if (!root_array[i].file_size) {
            root_count++;
        }
    }
    printf("rdir_free_ratio=%d/%d\n", root_count, 128);

    return 0;

}

int fs_create(const char *filename)
{
    /* TODO: Phase 2 */
    (void) filename;
    return 0;
}

int fs_delete(const char *filename)
{
    /* TODO: Phase 2 */
    (void) filename;
    return 0;
}

int fs_ls(void)
{
    /* TODO: Phase 2 */
    return 0;
}

int fs_open(const char *filename)
{
    /* TODO: Phase 3 */
    (void) filename;
    return 0;
}

int fs_close(int fd)
{
    /* TODO: Phase 3 */
    (void) fd;
    return 0;
}

int fs_stat(int fd)
{
    /* TODO: Phase 3 */
    (void) fd;
    return 0;
}

int fs_lseek(int fd, size_t offset)
{
    /* TODO: Phase 3 */
    (void) fd;
    (void) offset;
    return 0;
}

int fs_write(int fd, void *buf, size_t count)
{
    /* TODO: Phase 4 */
    (void) fd;
    (void) buf;
    (void)count;

    return 0;
}

int fs_read(int fd, void *buf, size_t count)
{
    /* TODO: Phase 4 */
    (void) fd;
    (void) buf;
    (void)count;
    return 0;
}