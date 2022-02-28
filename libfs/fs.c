#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "disk.h"
#include "fs.h"

#define FAT_EOC 65535
#define REACH_MAX_FILE -1
#define FILE_ALREADY_EXIST -2
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
    uint8_t file_name[FS_FILENAME_LEN];
    uint32_t file_size;
    uint16_t first_data_index;
    uint16_t padding[5];
}__attribute__((packed));

struct file_descriptor {
    int root_index;
    uint8_t file_name[FS_FILENAME_LEN];
    uint16_t offset;
};

typedef struct root_dir root_dir;
typedef struct file_descriptor fd_struct;
// define global variables
struct superblock spb;
uint16_t *fat_array;
root_dir root_array[FS_FILE_MAX_COUNT];
fd_struct fd_table[FS_OPEN_MAX_COUNT];
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
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if ((root_array[i].file_name[0] == '\0')) {
            root_count++;
        }
    }
    printf("rdir_free_ratio=%d/%d\n", root_count, FS_FILE_MAX_COUNT);

    return 0;
}
int find_empty(const char *filename, bool return_index, int *index) {
    int empty_entry = REACH_MAX_FILE;
    bool search = true;
    //printf("%s", root_array[0].file_name);
    for (int i = 0; i < 128; i++) {

        if (search && (root_array[i].file_name[0] == '\0')) {
            empty_entry = i;
            search = false;
        }
        if (!memcmp((root_array[i].file_name), filename, FS_FILENAME_LEN)) {
            if (return_index) {
                *index = i;
            }
            return FILE_ALREADY_EXIST;
        }
    }
    return empty_entry;
}

int fs_create(const char *filename)
{
    /* TODO: Phase 2 */

    if ((!mount) || (filename == NULL) || (sizeof(filename) > FS_FILENAME_LEN)){
        return -1;
    }

    int empty_slot = find_empty(filename, false, NULL);
    if ((empty_slot == FILE_ALREADY_EXIST) || (empty_slot == REACH_MAX_FILE)) {
        return -1;
    }
    // creating the file
    root_array[empty_slot].file_size = 0;
    memcpy(root_array[empty_slot].file_name, filename, 16);
    root_array[empty_slot].first_data_index = FAT_EOC;

    return 0;
}

int fs_delete(const char *filename)
{
    if ((!mount) || (filename == NULL) || (sizeof(filename) > FS_FILENAME_LEN)){
        return -1;
    }
    if (root_array[0].file_name[0] != '\0'){
        //printf("cao!\n");
    }
    if (memcmp(filename, root_array[0].file_name, FS_FILENAME_LEN) == 0){
        //printf("fuck!\n");
    }

    int index = 0;
    for (; index < 128; index++){
        if ((root_array[index].file_name[0] != '\0') &&
            !(memcmp(filename, root_array[index].file_name, FS_FILENAME_LEN))){
            break;
        }
    }
    if (index == 127){
        //printf("?\n");
        return -1;
    }
    memset(root_array[index].file_name, '\0', FS_FILENAME_LEN);

    int next_fat_index = root_array[index].first_data_index;
    while (next_fat_index != FAT_EOC){
        memcpy(&next_fat_index, &(fat_array[next_fat_index]), sizeof(fat_array[next_fat_index]));
        fat_array[next_fat_index] = 0;
    }

    root_array[index].first_data_index = FAT_EOC;
    root_array[index].file_size = 0;
    return 0;

}

int fs_ls(void)
{
    /* TODO: Phase 2 */
    printf("FS Ls:\n");
    for (int i = 0; i < 128; i++) {
        if (root_array[i].file_name[0] != '\0'){
            //printf("i is: %d", i);
            printf("file: %s, size: %d, data_blk: %d\n", root_array[i].file_name,
                   root_array[i].file_size, root_array[i].first_data_index);
        }
    }

    return 0;
}

int fs_open(const char *filename)
{
    /* TODO: Phase 3 */
    if ((!mount) || (filename == NULL) || (sizeof(filename) > FS_FILENAME_LEN)){
        return -1;
    }
    int root_index;
    if (find_empty(filename, true, &root_index) != FILE_ALREADY_EXIST) {
        return -1;
    }

    int fd = -1;
    for (int i = 0; i < FOPEN_MAX; i++) {
        if (fd_table[i].file_name[0] == '\0') {
            fd = i;
            break;
        }
    }

    if (fd == -1) {
        return -1;
    }
    //fd_table[fd].fd = fd;
    memcpy(fd_table[fd].file_name, filename, 16);
    fd_table[fd].offset = 0;
    fd_table[fd].root_index = root_index;

    return fd;
}

int fs_close(int fd)
{
    if ((!mount)){
        return -1;
    }
    if (fd_table[fd].file_name[0] == '\0'  || fd > 31 || fd < 0){
        return -1;
    }
    memset(fd_table[fd].file_name,'\0', FS_FILENAME_LEN);
    fd_table[fd].offset = 0;

    return 0;
}

int fs_stat(int fd)
{
    if ((!mount)){
        return -1;
    }
    if (fd_table[fd].file_name[0] == '\0' || fd > 31 || fd < 0){
        return -1;
    }
    char *file_name;
    memcpy(file_name,fd_table[fd].file_name,FS_FILENAME_LEN);
    for (int i = 0; i < 128 ;i++){
        if (!memcmp((root_array[i].file_name), file_name, FS_FILENAME_LEN)){
            return root_array[i].file_size;
        }
    }
    return -1;
}

int fs_lseek(int fd, size_t offset)
{
    if ((!mount)){
        return -1;
    }
    if (fd_table[fd].file_name[0] == '\0'  || fd > 31 || fd < 0){
        return -1;
    }
    int root_index = fd_table[fd].root_index;
    if (offset > root_array[root_index].file_size) {
        return -1;
    }
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


