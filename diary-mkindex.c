/*
 * diary-mkindex
 * Copyright (C) 2012 Tsukasa Hamano <code@cuspy.org>
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

#include "mkdio.h"
#include "ClearSilver.h"

static int diary_mkindex_filter(const struct dirent *ent)
{
    const char *ext;

    ext = strrchr(ent->d_name, '.');
    if (!ext){
        return 0;
    }

    if(!strcasecmp(ext, ".md")){
        return 1;
    }
    return 0;
}

static int diary_mkindex_sort(const struct dirent **a, const struct dirent **b)
{
    return alphasort(b, a);
}

int diary_mkindex(const char *diary_dir)
{
    struct dirent **namelist;
    struct dirent *ent;
    int num;
    int i;
    char path[PATH_MAX];
    FILE *fp;
    MMIOT *doc;
    char uri[PATH_MAX];
    char *title;
    char *author;
    char *date;
    HDF *hdf;
    size_t uri_len;

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
        snprintf(path, PATH_MAX, "%s/%s", diary_dir, ent->d_name);
        snprintf(uri, PATH_MAX, "%s", ent->d_name);
        uri_len = strlen(uri);
        if(uri_len >= 3){
            uri[uri_len - 3] = '\0';
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

        hdf_set_valuef(hdf, "index.%d.uri=%s", i, uri);
        hdf_set_valuef(hdf, "index.%d.title=%s", i, title);
        mkd_cleanup(doc);
    }
    free(namelist);
    hdf_dump_format(hdf, 0, stdout);
    hdf_destroy(&hdf);
    return 0;
}

int main(int argc, char *argv[]){
    const char *diary_dir = NULL;
    int ret;

    if(argc < 2){
        diary_dir = ".";
    }else{
        diary_dir = argv[1];
    }
    ret = diary_mkindex(diary_dir);
    if(ret){
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
