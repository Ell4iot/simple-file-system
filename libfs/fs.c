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
        //printf("i: %d, name: %s\n", i, root_array[i].file_name);
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
    printf("%d", start_fat_index);
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
    // check no FS is mounted, or invalid filename, or can't open filename
    if ((!mount) || (filename == NULL) || (sizeof(filename) > FS_FILENAME_LEN)){
        //printf("232\n");
        return -1;
    }
    int root_index;
    //printf("236: %s\n", filename);
    if (find_empty(filename, true, &root_index) != FILE_ALREADY_EXIST) {
        //printf("237\n");
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
        //printf("249\n");
        return -1;
    }
    // open the file
    memcpy(fd_table[fd].file_name, filename, 16);
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
//find current offset location 
void find_block(uint32_t offset, int *block_amount, uint32_t *remain_offset) {
    *remain_offset = offset % BLOCK_SIZE;
    *block_amount = offset /BLOCK_SIZE;
}
//find current blocfk index
uint16_t data_index(uint16_t current_block, int remaining) {
    uint16_t next = fat_array[current_block];
    remaining--;
    if (!remaining) {
        return next;
    }
    return data_index(next, remaining);
}
//计算要写几个block 返回（要写几个block，最后一个block要写多少bit）
void cal_codeblocks_needed(uint32_t *remain_offset,size_t count,int* rc){ 
    int cur_block_remain = BLOCK_SIZE - *remain_offset;
    int new_count;
    if((int)count > cur_block_remain) {
        new_count = count - cur_block_remain;
    }
    else{
        new_count = cur_block_remain;
    }
    int block_needed = new_count/BLOCK_SIZE;
    int last_block_offset = new_count %BLOCK_SIZE;
    if (last_block_offset != 0){
        block_needed++;
    }
    block_needed ++;
    rc[0] = block_needed;
    rc[1] = last_block_offset;
}
//计算从现在的block算起 fat里面有几个block可以写
int remaining_block_count(uint16_t data_index){
    int fat_index = data_index;
    int count = 0;
    while(fat_array[fat_index] != FAT_EOC){
        fat_index = fat_array[fat_index];
        count++;
    }
    return count;
}
//给fat加block
void fat_modify(int* needed_info,int remain_block_count,uint16_t data_index){
    int added_block_amount = needed_info[0] - remain_block_count;
    int fat_index = data_index;
    while(fat_array[fat_index] != FAT_EOC){
        fat_index = fat_array[fat_index];
    }
    int added_fat = 0;
    for(int i = 0; added_fat < added_block_amount; i++){
        if (fat_array[i] == 0){
            fat_array[fat_index] = i;
            fat_index = i;
            added_fat++; 
        }
    }
    fat_array[fat_index] =FAT_EOC;
}
//把要写的fat的block的index放到一个array里 比如{3，6，7，8}
void generate_fat_array_mod(uint16_t data_index, int* rc){
    int fat_index = data_index;
    int index = 0;
    while(fat_array[fat_index] != FAT_EOC){
        rc[index] = fat_index;
        fat_index = fat_array[fat_index];
        index++;
    }
}
int fs_write(int fd, void *buf, size_t count)
{
    /* TODO: Phase 4 */
    int block_amount;
    uint32_t remain_offset;
    find_block(fd_table[fd].offset, &block_amount, &remain_offset);
    uint16_t first_data_index = root_array[fd_table[fd].root_index].first_data_index;
    uint16_t block_to_start;
    if (buf == NULL){
        return -1;
    }
    if ((!mount)){
        return -1;
    }
    if (fd_table[fd].file_name[0] == '\0'  || fd > 31 || fd < 0){
        return -1;
    }
    if (block_amount) {
        // need to find the data block where offset is at
        block_to_start = data_index(first_data_index, block_amount - 1);
    } else {
        // offset is at the fisrt data block
        block_to_start = first_data_index;
    }
    int block_needed_info[2] ;
    cal_codeblocks_needed(&remain_offset,count,block_needed_info);
    int remain_block_count = remaining_block_count(block_amount);
    //改fat 加新的block
    if(block_needed_info[0]>remain_block_count){
        fat_modify(block_needed_info,remain_block_count,block_to_start);
    }
    int fat_array_modify[block_needed_info[0]];
    generate_fat_array_mod(block_to_start,fat_array_modify);
    int bits_done = 0;
    void *temp = 0;
    int remaining_written_blocks = block_needed_info[1];
    int fat_array_index = 0;
    //如果第一个array要写部分 在这个if中执行
    //先read出来原有的block 然后memcpy后半段
    if(remain_offset != 0){
        block_read(first_data_index,temp);
        memcpy(temp+remain_offset,buf+bits_done,block_needed_info[1]);
        bits_done = block_needed_info[1];
        block_write(first_data_index,temp);
        remaining_written_blocks = remaining_written_blocks - 1;
        fat_array_index++;
    }
    //写所有的完整block写入 除了最后一个
    while(remain_block_count > 1 ){
        memcpy(temp,buf+bits_done,BLOCK_SIZE);
        bits_done += BLOCK_SIZE;
        block_write(fat_array_modify[fat_array_index],temp);
        fat_array_index++;
    }
    //写最后一个 写入 count-bits_done 位数据 避免memcpy segamentation
    memcpy(temp,buf+bits_done,count-bits_done);
    block_write(fat_array_modify[fat_array_index],temp);
    return 0;
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

    // file is empty, don't read at all
    if (first_data_index == FAT_EOC) {
        return 0;
    }
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
    // remember the case when file is 0
    return already_read;
}
