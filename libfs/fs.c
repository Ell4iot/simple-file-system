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
#define FAT_FULL -3
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
    uint32_t offset;
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
    memset(&spb, 0, 4096);
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

    // FAT creation， initialize
    int fat_total_entry = (spb.fat_amount) * 4096;
    fat_array = (uint16_t *)malloc(fat_total_entry * sizeof(uint16_t));
    memset(fat_array, 0, fat_total_entry);
    for (int i = 0; i < spb.fat_amount + 1; i++) {
        // superblock is at 0, fat array starts in the 1st block
        if (block_read(i + 1, fat_array + i * 2048)) {
            return -1;
        }
    }
    // Root directory creation
    memset(root_array, 0, 4096);
    if (block_read(spb.root_index, root_array)) {
        return -1;
    }

    mount = true;
    return 0;
}

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
    if (!mount) {
        return -1;
    }
    printf("FS Info:\n");
    printf("total_blk_count=%d\n", spb.total_block_amount);
    printf("fat_blk_count=%d\n", spb.fat_amount);
    printf("rdir_blk=%d\n", spb.root_index);
    printf("data_blk=%d\n", spb.data_start_index);
    printf("data_blk_count=%d\n", spb.data_block_amount);
    int fat_count = 0;
    for (int i = 0; i < spb.data_block_amount; i++) {
        if (fat_array[i] == 0) {
            fat_count++;
        }
    }
    printf("fat_free_ratio=%d/%d\n", fat_count, spb.data_block_amount);
    int root_count = 0;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_array[i].file_name[0] == '\0') {
            root_count++;
        }
    }
    printf("rdir_free_ratio=%d/%d\n", root_count, FS_FILE_MAX_COUNT);

    return 0;
}
int find_empty(const char *filename, bool return_index, int *index) {
    int empty_entry = REACH_MAX_FILE;
    bool search = true;
    for (int i = 0; i < 128; i++) {
        if (search && (root_array[i].file_name[0] == '\0')) {
            empty_entry = i;
            search = false;
        }
        if (!memcmp((root_array[i].file_name), filename, strlen(filename))) {
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
    // error checking
    if ((!mount) || (filename == NULL) || (sizeof(filename) > FS_FILENAME_LEN)){
        return -1;
    }

    int empty_slot = find_empty(filename, false, NULL);
    if ((empty_slot == FILE_ALREADY_EXIST) || (empty_slot == REACH_MAX_FILE)) {
        return -1;
    }
    // creating the file
    root_array[empty_slot].file_size = 0;
    memcpy(root_array[empty_slot].file_name, filename, strlen(filename));
    root_array[empty_slot].first_data_index = FAT_EOC;

    return 0;
}

int fs_delete(const char *filename)
{
    if ((!mount) || (filename == NULL) || (sizeof(filename) > FS_FILENAME_LEN)){
        return -1;
    }

    int index;
    for (int i = 0; i < 128; i++){
        if ((root_array[i].file_name[0] != '\0') &&
            !(memcmp(filename, root_array[i].file_name, strlen(filename)))){
            index = i;
            break;
        }
        if (i == 127) {
            return -1;
        }
    }
    memset(root_array[index].file_name, '\0', FS_FILENAME_LEN);

    int next_fat_index;
    int start_fat_index = root_array[index].first_data_index;
    int before_data_block = 1 + spb.fat_amount + 1;
    uint8_t buf[4096];
    memset(buf, '\0', 4096);

    while (true){
        next_fat_index = fat_array[start_fat_index];
        fat_array[start_fat_index] = 0;
        block_write(before_data_block + start_fat_index, buf);
        if (next_fat_index == FAT_EOC) {
            break;
        }
        start_fat_index = next_fat_index;
    }

    root_array[index].first_data_index = FAT_EOC;
    root_array[index].file_size = 0;
    return 0;

}

int fs_ls(void)
{
    printf("FS Ls:\n");
    for (int i = 0; i < 128; i++) {
        if (root_array[i].file_name[0] != '\0'){
            printf("file: %s, size: %d, data_blk: %d\n", root_array[i].file_name,
                   root_array[i].file_size, root_array[i].first_data_index);
        }
    }

    return 0;
}

int fs_open(const char *filename)
{
    // check no FS is mounted, or invalid filename, or can't open filename
    if ((!mount) || (filename == NULL) || (sizeof(filename) > FS_FILENAME_LEN)){\
        return -1;
    }
    int root_index;
    if (find_empty(filename, true, &root_index) != FILE_ALREADY_EXIST) {
        return -1;
    }
    // check if fd table is full
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
    // open the file
    memcpy(fd_table[fd].file_name, filename, strlen(filename));
    fd_table[fd].offset = 0;
    fd_table[fd].root_index = root_index;

    return fd;
}

int fs_close(int fd)
{
    if (!mount){
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
    if (!mount){
        return -1;
    }
    if (fd_table[fd].file_name[0] == '\0' || fd > 31 || fd < 0){
        return -1;
    }
    int root_index;
    memcpy(&root_index, &(fd_table[fd].root_index), sizeof(fd_table[fd].root_index));
    return root_array[root_index].file_size;

}

int fs_lseek(int fd, size_t offset)
{
    // check if not mounted, or fd is invalid, not open
    if ((!mount)){
        return -1;
    }
    if (fd_table[fd].file_name[0] == '\0'  || fd > 31 || fd < 0){
        return -1;
    }
    // check if offset is larger than current file size
    int root_index = fd_table[fd].root_index;
    if (offset > root_array[root_index].file_size) {
        return -1;
    }
    fd_table[fd].offset = offset;
    return 0;
}
void find_block(uint32_t offset, int *block_amount, uint32_t *remain_offset) {
    *remain_offset = offset % 4096;
    *block_amount = offset / 4096;
}

uint16_t data_index(uint16_t current_block, int remaining) {
    uint16_t next = fat_array[current_block];
    remaining--;
    if (!remaining) {
        return next;
    }
    return data_index(next, remaining);
}
int allocate_new_data(void) {
    for (int i = 0; i < spb.data_block_amount; i++) {
        if (fat_array[i] == 0) {
            return i;
        }
    }
    return FAT_FULL;
}
int fs_write(int fd, void *buf, size_t count)
{
    if ((!mount) || (buf == NULL)){
        return -1;
    }
    if (fd_table[fd].file_name[0] == '\0'  || fd > 31 || fd < 0){
        return -1;
    }
    if (!count) {
        return 0;
    }
    uint8_t bounce[4096];
    uint8_t second_bounce[4096];
    int block_amount;        // block_amount = offset / 4096
    uint32_t remain_offset;  // remain_offset = offset - n * 4096 (n = 0, 1, 2, 3,...)
    size_t remaining_to_write = count;    // counting the size of file left to write
    size_t bytes_to_write;        // bytes of file to write in current iteration
    int already_wrote = 0;        // counting the size of file which are already wrote
    uint16_t block_to_start;
    bool extend_or_not = false;    // Whether to change the file size or not
    int root_index = fd_table[fd].root_index;
    uint16_t first_data_index = root_array[root_index].first_data_index;

    if (first_data_index == FAT_EOC) {
        // The file to write is empty, allocate FAT
        int new_data = allocate_new_data();  // new data block
        if (new_data != FAT_FULL) {
            // empty data block found
            extend_or_not = true;
            first_data_index = new_data;
            fat_array[first_data_index] = FAT_EOC;
            root_array[root_index].first_data_index = new_data;
        } else {
            // no empty data block
            return 0;
        }
    }
    // given the offset, find the corresponding data block to start writing
    // block_to_start is the place where we start writing.
    find_block(fd_table[fd].offset, &block_amount, &remain_offset);
    if (block_amount) {
        // need to find the data block where offset is at
        block_to_start = data_index(first_data_index, block_amount);
    } else {
        // offset is at the fisrt data block
        block_to_start = first_data_index;

    }
    int before_data_block = 1 + spb.fat_amount + 1;
    size_t extend_size = 0;
    while (remaining_to_write) {
        // firstly read the entire block where offset is at into bounce
        block_read(before_data_block + block_to_start, bounce);
        // save the content before the offset
        memcpy(second_bounce, bounce, remain_offset);
        if (remaining_to_write >= 4096 - remain_offset) {
            bytes_to_write = 4096 - remain_offset;
        } else {
            bytes_to_write = remaining_to_write;
        }
        fwrite(bounce + already_wrote, 1, 2742, stdout);

        memcpy(second_bounce + remain_offset, buf + already_wrote, bytes_to_write);
        block_write(before_data_block + block_to_start, second_bounce);
        already_wrote = already_wrote + bytes_to_write;
        remaining_to_write = remaining_to_write - bytes_to_write;

        //remain_offset only applies for the first time
        //set it to 0 after first write
        remain_offset = 0;
        if (extend_or_not) {
            // entering here, means that new data block is allocated
            // need to increase the size
            extend_size = bytes_to_write;
        }
        // if the if statement above fails, extend_size will remain 0
        root_array[root_index].file_size = root_array[root_index].file_size + extend_size;

        if (!remaining_to_write) {
            // finish writing
            break;
        }
        // check whether to extend or not
        if (fat_array[block_to_start] == FAT_EOC) {
            int new_data = allocate_new_data();
            if (new_data != FAT_FULL) {
                // find space to extend
                extend_or_not = true;
                fat_array[block_to_start] = new_data;
                fat_array[new_data] = FAT_EOC;
            } else {
                // no space to extend
                break;
            }
            block_to_start = new_data;
        } else {
            block_to_start = fat_array[block_to_start];
        }

    }
    fd_table[fd].offset = fd_table[fd].offset + already_wrote;
    return already_wrote;
}

int fs_read(int fd, void *buf, size_t count)
{
    if ((!mount) || (buf == NULL)){
        return -1;
    }
    if (fd_table[fd].file_name[0] == '\0'  || fd > 31 || fd < 0){
        return -1;
    }
    uint8_t bounce[4096];
    int block_amount;
    uint32_t remain_offset;
    size_t remaining_to_read = count;
    size_t bytes_to_read;
    int already_read = 0;
    uint16_t block_to_start;
    // given the offset, find the corresponding data block to start reading
    // block_to_start is the place where we start reading.
    find_block(fd_table[fd].offset, &block_amount, &remain_offset);
    uint16_t first_data_index = root_array[fd_table[fd].root_index].first_data_index;

    if (block_amount) {
        // need to find the data block where offset is at
        block_to_start = data_index(first_data_index, block_amount);
    } else {
        // offset is at the fisrt data block
        block_to_start = first_data_index;
    }
    //test_fs.x cat disk.fs bunnygirl.txt
    int before_data_block = 1 + spb.fat_amount + 1;
    while (remaining_to_read) {

        block_read(before_data_block + block_to_start, bounce);
        if (remaining_to_read >= 4096 - remain_offset) {
            bytes_to_read = 4096 - remain_offset;
        } else {
            bytes_to_read = remaining_to_read;
        }
        memcpy(buf + already_read, bounce + remain_offset, bytes_to_read);
        already_read = already_read + bytes_to_read;
        remaining_to_read = remaining_to_read - bytes_to_read;

        remain_offset = 0;
        block_to_start = fat_array[block_to_start];
        // stop reading if reach the end of the file
        if (block_to_start == FAT_EOC) {
            break;
        }
    }
    fd_table[fd].offset = fd_table[fd].offset + already_read;
    return already_read;
}
