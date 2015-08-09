/*
 * diary-mkindex
 * Copyright (C) 2011-2015 Tsukasa Hamano <code@cuspy.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#include "mkdio.h"
#include "ClearSilver.h"

const char *diary_dir = NULL;

static int diary_mkindex_filter(const struct dirent *ent)
{
    const char *ext;
    char testpath[PATH_MAX];
    struct stat st;

    if(!strncmp(ent->d_name, ".", 1)){
        return 0;
    }

    if(!strncmp(ent->d_name, "draft-", 6)){
        return 0;
    }

    if(ent->d_type == DT_DIR){
        snprintf(testpath, PATH_MAX, "%s/%s/index.md", diary_dir, ent->d_name);
        if(stat(testpath, &st)){
            return 0;
        }else{
            return 1;
        }
    }
    
    ext = strrchr(ent->d_name, '.');
    if (!ext){
        return 0;
    }

    if(strcasecmp(ext, ".md")){
        return 0;
    }

    return 1;
}

static int diary_mkindex_sort(const struct dirent **a, const struct dirent **b)
{
    return alphasort(b, a);
}

int diary_mkindex(const char *diary_dir, const char *diary_uri)
{
    struct dirent **namelist;
    struct dirent *ent;
    int num;
    int i;
    char path[PATH_MAX];
    FILE *fp;
    MMIOT *doc;
    char name[PATH_MAX];
    size_t name_len;
    char *title;
    char *author;
    char *date;
    HDF *hdf;

    num = scandir(diary_dir, &namelist,
                  diary_mkindex_filter,
                  diary_mkindex_sort);
    if(num < 0){
        fprintf(stderr, "no such file or directory: %s\n", diary_dir);
        return -1;
    }

    hdf_init(&hdf);

    for (i = 0; i < num; i++) {
        ent = namelist[i];
        if(ent->d_type == DT_DIR){
            snprintf(path, PATH_MAX, "%s/%s/index.md", diary_dir, ent->d_name);
            name_len = snprintf(name, PATH_MAX, "%s/", ent->d_name);
        }else{
            snprintf(path, PATH_MAX, "%s/%s", diary_dir, ent->d_name);
            name_len = snprintf(name, PATH_MAX, "%s", ent->d_name);
            // chop extension of name
            if(name_len >= 3){
                name[name_len - 3] = '\0';
            }
        }
        free(ent);
        fp = fopen(path, "r");
        if(fp == NULL){
            perror("file open error");
            return -1;
        }
        doc = mkd_in(fp, 0);
        fclose(fp);
        if (doc == NULL) {
            perror("mkd_in");
            return -1;
        }
        title = mkd_doc_title(doc);
        author = mkd_doc_author(doc);
        date = mkd_doc_date(doc);

        hdf_set_valuef(hdf, "index.%d.name=%s", i, name);
        hdf_set_valuef(hdf, "index.%d.title=%s", i, title);
        hdf_set_valuef(hdf, "index.%d.date=%s", i, date);
        mkd_cleanup(doc);
    }
    free(namelist);
    hdf_dump_format(hdf, 0, stdout);
    hdf_destroy(&hdf);
    return 0;
}

int main(int argc, char *argv[]){
    int ret;
    int opt;
    char *diary_uri = "";

    while((opt = getopt(argc, argv, "u:")) != -1){
        switch(opt){
        case 'u':
            diary_uri = optarg;
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    if(argc < optind + 1){
        diary_dir = ".";
    }else{
        diary_dir = argv[optind];
    }
    ret = diary_mkindex(diary_dir, diary_uri);
    if(ret){
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
