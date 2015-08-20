/*
**  mod_diary.c -- Apache sample diary module
**
**  Copyright (C) 2011-2015 Tsukasa Hamano <code@cuspy.org>
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory
**  by running:
**
**    % ./autogen.sh
**    % ./configure --with-apache=<APACHE_DIR>  \
**        --with-discount=<DISCOUNT_DIR>  \
**        --with-clearsilver=<CLEARSILVER_DIR>
**    % make
**    # make install
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /diary in as follows:
**
**    #   httpd.conf
**    LoadModule diary_module modules/mod_diary.so
**    <Location /diary>
**      SetHandler diary
**      DiaryPath /path/to/diary
**      DiaryTitle Sample Diary
**      DiaryURI http://www.example.com/diray/
**      # Optional Settings
**      DiaryTheme default
**      DiaryCalendar On
**      DiaryGithubFlavouredMarkdown On
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
**  you immediately can request the URL /diary and watch for the
**  output of this module. This can be achieved for instance via:
**
**    $ lynx -mime_header http://localhost/diary/
**
**  The output should be similar to the following one:
**
**    HTTP/1.1 200 OK
**    Date: Tue, 31 Mar 1998 14:42:22 GMT
**    Server: Apache/1.3.4 (Unix)
**    Connection: close
**    Content-Type: text/html
**
**    The sample page from mod_diary.c
*/

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "http_core.h"
#include "apr_hooks.h"

#include "ap_config.h"
#include "apr_strings.h"
#include "apr_uri.h"

#include "mkdio.h"
#include "ClearSilver.h"

#include "diary.h"
#include <time.h>

#define INDEX_HDF "index.hdf"
#define CALENDAR_QUERYSTR_PREFIX "calyear="

module AP_MODULE_DECLARE_DATA diary_module;

typedef struct {
    apr_pool_t *pool;
    const char *path;
    const char *uri;
    const char *title;
    const char *theme;
    int autolink;
    int github_flavoured;
    int calendar;
} diary_conf;

typedef struct {
   int year;
   char month[3];
   char day[3];   
   char today[11];
   int dayofweek_1stdayofmonth;
   int lastdayofmonth;
} calendar_info;

static NEOERR *diary_cs_render_cb(void *ctx, char *s)
{
    ap_rputs(s, (request_rec *)ctx);
    return NULL;
}

static int dayofweek(int y, int m, int d) 
{
   return (y + y/4 - y/100 + y/400 + (13 * ++m + 8) / 5 + 1) % 7; 
}

static int validate_year_and_month(int y, int m)
{
   return (y >= 1970 && y < 3000 && m >= 1 && m <= 12) ? 0 : -1;
}

static void diary_set_calendar_info(calendar_info *cal, const char *querystr)
{
    time_t t;
    struct tm *tm, tm_cal = {0};
    char buf[12];
    const int dayofmonthes[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    char calyear[5]  = {'\0'};
    char calmonth[3] = {'\0'};
    int year, month;

    t = time(NULL);
    if (querystr != NULL) {
      strncpy(calyear,  querystr +  8, 4);
      strncpy(calmonth, querystr + 12, 2);
      year = atoi(calyear);
      month = atoi(calmonth);
      if (validate_year_and_month(year, month) >= 0) {
	 tm_cal.tm_year = year - 1900;
	 tm_cal.tm_mon = month;
	 t = mktime(&tm_cal);
      }
    }
   
    /* Setup the calendar data */
    tm = localtime(&t);
    cal->year = tm->tm_year + 1900;
    strcpy(cal->month, calmonth);
    cal->lastdayofmonth = dayofmonthes[tm->tm_mon];   
    if(tm->tm_mon == 1 /* feb */ && cal->year%4 == 0 && (cal->year%100 != 0 || cal->year%400 == 0))
        ++cal->lastdayofmonth;
    sprintf(cal->month, "%02d", tm->tm_mon + 1);
    sprintf(cal->day, "%02d", tm->tm_mday);
    strftime(buf, 11, "%Y-%m-%d", tm);
    strcpy(cal->today, buf);
    /* Get the day of week of the 1st day of this month */
    cal->dayofweek_1stdayofmonth = dayofweek(cal->year, tm->tm_mon, 1);
}

static int diary_handle_index(request_rec *r, diary_conf *conf)
{
    HDF *hdf;
    CSPARSE *cs;
    NEOERR *cs_err;
    STRING cs_err_str;
    calendar_info cal;
    char *theme_path;
    char *theme_file;

    theme_path = apr_pstrcat(r->pool, conf->path, "/themes/", conf->theme, NULL);
    theme_file = apr_pstrcat(r->pool, theme_path, "/index.cst", NULL);

    hdf_init(&hdf);
    hdf_set_int_value(hdf, "index", 1);
    hdf_set_value(hdf, "hdf.loadpaths.1", conf->path);
    hdf_set_value(hdf, "hdf.loadpaths.2", theme_path);
    hdf_set_value(hdf, "diary.title", conf->title);
    hdf_set_value(hdf, "diary.uri", conf->uri);
    hdf_set_value(hdf, "diary.theme", conf->theme);

    if (conf->calendar) {
        diary_set_calendar_info(&cal, r->args);
        hdf_set_int_value(hdf, "cal.year", cal.year);
        hdf_set_value(hdf, "cal.month", cal.month);
        hdf_set_value(hdf, "cal.day", cal.day);   
        hdf_set_value(hdf, "cal.today", cal.today);
        hdf_set_int_value(hdf, "cal.lastdayofmonth", cal.lastdayofmonth);
        hdf_set_int_value(hdf, "cal.dayofweek_1stdayofmonth", cal.dayofweek_1stdayofmonth);
    }

    cs_err = hdf_read_file(hdf, INDEX_HDF);
    if(cs_err){
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "cannot read index.hdf.");
        // TODO: no need to free cs_err and cs_err_str?
        hdf_destroy(&hdf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    //hdf_dump(hdf, NULL);

    cs_err = cs_init(&cs, hdf);
    if(cs_err){
        string_init(&cs_err_str);
        nerr_error_string(cs_err, &cs_err_str);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error at cs_init(): %s", cs_err_str.buf);
        // TODO: no need to free cs_err and cs_err_str?
        cs_destroy(&cs);
        hdf_destroy(&hdf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    cgi_register_strfuncs(cs);

    cs_err = cs_parse_file(cs, theme_file);
    if(cs_err){
        string_init(&cs_err_str);
        nerr_error_string(cs_err, &cs_err_str);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "hoge error in cs_parse_file(): %s", cs_err_str.buf);
        // TODO: no need to free cs_err and cs_err_str?
        cs_destroy(&cs);
        hdf_destroy(&hdf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    r->content_type = "text/html";
    cs_render(cs, r, diary_cs_render_cb);

    cs_destroy(&cs);
    hdf_destroy(&hdf);
    return OK;
}

static int diary_handle_feed_rss(request_rec *r, diary_conf *conf)
{
    HDF *hdf;
    CSPARSE *cs;
    NEOERR *cs_err;
    STRING cs_err_str;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "diary_handle_feed_rss()");

    hdf_init(&hdf);
    hdf_set_value(hdf, "hdf.loadpaths.1", conf->path);
    hdf_set_value(hdf, "diary.title", conf->title);
    hdf_set_value(hdf, "diary.uri", conf->uri);

    cs_err = hdf_read_file(hdf, INDEX_HDF);
    if(cs_err){
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "cannot read index.hdf.");
        hdf_destroy(&hdf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    //hdf_dump(hdf, NULL);

    cs_err = cs_init(&cs, hdf);
    if(cs_err){
        string_init(&cs_err_str);
        nerr_error_string(cs_err, &cs_err_str);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error at cs_init(): %s", cs_err_str.buf);
        cs_destroy(&cs);
        hdf_destroy(&hdf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    cgi_register_strfuncs(cs);

    cs_err = cs_parse_string(cs, strdup(RSS_TMPL), RSS_TMPL_LEN);
    if(cs_err){
        string_init(&cs_err_str);
        nerr_error_string(cs_err, &cs_err_str);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "error in cs_parse_string(): %s", cs_err_str.buf);
        cs_destroy(&cs);
        hdf_destroy(&hdf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    r->content_type = "application/rss+xml";
    cs_render(cs, r, diary_cs_render_cb);

    cs_destroy(&cs);
    hdf_destroy(&hdf);
    return OK;
}

static int diary_handle_feed(request_rec *r, diary_conf *conf)
{
    if (!strcmp(r->path_info, "/feed/")) {
        return diary_handle_feed_rss(r, conf);
    }else if(!strncmp(r->path_info, "/feed/rss", 9)){
        return diary_handle_feed_rss(r, conf);
    }
    return HTTP_NOT_FOUND;
}

static int diary_handle_entry(request_rec *r,
                              diary_conf *conf,
                              const char *filename)
{
    FILE *fp;
    CSPARSE *cs;
    NEOERR *cs_err;
    HDF *hdf;
    MMIOT *doc;
    char *title;
    char *author;
    char *date;
    int size;
    char *p;
    int flag = 0;
    int github_flavoured = conf->github_flavoured;
    calendar_info cal;
    char *theme_path;
    char *theme_file;

    theme_path = apr_pstrcat(r->pool, conf->path, "/themes/", conf->theme, NULL);
    theme_file = apr_pstrcat(r->pool, theme_path, "/index.cst", NULL);

    fp = fopen(filename, "r");
    if(fp == NULL){
        switch (errno) {
        case ENOENT:
            return HTTP_NOT_FOUND;
        case EACCES:
            return HTTP_FORBIDDEN;
        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "diary_parse_entry error: errno=%d\n", errno);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    doc = github_flavoured ? gfm_in(fp, 0) : mkd_in(fp, 0);
    fclose(fp);
    if (doc == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    title = mkd_doc_title(doc);
    if(title == NULL){
        title = "notitle";
    }
    date = mkd_doc_date(doc);
    author = mkd_doc_author(doc);

    if(conf->autolink){
        flag = MKD_AUTOLINK;
    }
    mkd_compile(doc, flag);
    if ((size = mkd_document(doc, &p)) == EOF) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    hdf_init(&hdf);

    hdf_set_value(hdf, "hdf.loadpaths.1", conf->path);
    hdf_set_value(hdf, "hdf.loadpaths.2", theme_path);

    cs_err = hdf_read_file(hdf, INDEX_HDF);
    if(cs_err){
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "cannot read index.hdf.");
        // TODO: no need to free cs_err and cs_err_str?
        hdf_destroy(&hdf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    hdf_set_value(hdf, "diary.title", conf->title);
    hdf_set_value(hdf, "diary.uri", conf->uri);
    hdf_set_value(hdf, "diary.theme", conf->theme);

    hdf_set_value(hdf, "entry.uri", r->uri);
    hdf_set_value(hdf, "entry.title", title);
    hdf_set_value(hdf, "entry.author", author);
    hdf_set_value(hdf, "entry.date", date);
    hdf_set_value(hdf, "entry.desc", p);
    //hdf_dump(hdf, NULL);

    if (conf->calendar) {
        diary_set_calendar_info(&cal, r->args);
        hdf_set_int_value(hdf, "cal.year", cal.year);
        hdf_set_value(hdf, "cal.month", cal.month);
        hdf_set_value(hdf, "cal.day", cal.day);   
        hdf_set_value(hdf, "cal.today", cal.today);
        hdf_set_int_value(hdf, "cal.lastdayofmonth", cal.lastdayofmonth);
        hdf_set_int_value(hdf, "cal.dayofweek_1stdayofmonth", cal.dayofweek_1stdayofmonth);
    }
   
    cs_err = cs_init(&cs, hdf);
    if(cs_err){
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    cgi_register_strfuncs(cs);
    mkd_cleanup(doc);
    cs_parse_file(cs, theme_file);

    r->content_type = "text/html";
    cs_render(cs, r, diary_cs_render_cb);

    hdf_destroy(&hdf);
    cs_destroy(&cs);
    return 0;
}

/* The diary handler */
static int diary_handler(request_rec *r)
{
    diary_conf *conf;
    int ret;
    char *filename;

    if (strcmp(r->handler, "diary")) {
        return DECLINED;
    }

    if (r->header_only) {
        return OK;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "diary_handler: %s", r->path_info);

    conf = (diary_conf *) ap_get_module_config(r->per_dir_config,
                                               &diary_module);
    if (!strcmp(r->path_info, "/")) {
        return diary_handle_index(r, conf);
    }else if(!strncmp(r->path_info, "/feed/", 6)){
        return diary_handle_feed(r, conf);
    }

    r->path_info = NULL;
    ret = apr_stat(&r->finfo, r->filename, APR_FINFO_MIN, r->pool);
    /* see apr_file_info.h:apr_filetype_e */
    if(ret == 0 && r->finfo.filetype == APR_REG){
        return DECLINED;
    }

    /* request to directory */
    if(ret == 0 && r->finfo.filetype == APR_DIR){
        filename = apr_pstrcat(r->pool, r->filename, "/index.md", NULL);
        ret = apr_stat(&r->finfo, filename, APR_FINFO_MIN, r->pool);
        if(!ret){
            ret = diary_handle_entry(r, conf, filename);
            return OK;
        }
    }

    filename = apr_pstrcat(r->pool, r->filename, ".md", NULL);
    ret = apr_stat(&r->finfo, filename, APR_FINFO_MIN, r->pool);
    if(!ret){
        ret = diary_handle_entry(r, conf, filename);
        return OK;
    }

    return DECLINED;
}

static int diary_fixups(request_rec *r)
{
    diary_conf *conf;
    conf = (diary_conf *)ap_get_module_config(r->per_dir_config,
                                              &diary_module);
    if(conf->path == NULL) {
        return DECLINED;
    }
    r->filename = apr_pstrcat(r->pool, conf->path, r->path_info, NULL);
    return DECLINED;
}

static void *diary_config(apr_pool_t *p, char *dummy)
{
    diary_conf *c = (diary_conf *) apr_pcalloc(p, sizeof(diary_conf));
    memset(c, 0, sizeof(diary_conf));
    c->pool = p;

    // default settings
    c->uri = "";
    c->title = "My Diary";
    c->theme = "default";
    c->autolink = 1;
    c->github_flavoured = 1;
    c->calendar = 1;
    return (void *)c;
}

static const char *set_diary_path(cmd_parms * cmd, void *conf,
                                  const char *arg)
{
    diary_conf *c = (diary_conf *)conf;
    c->path = arg;
    return NULL;
}

static const char *set_diary_title(cmd_parms * cmd, void *conf,
                                   const char *arg)
{
    diary_conf *c = (diary_conf *)conf;
    c->title = arg;
    return NULL;
}

static const char *set_diary_uri(cmd_parms * cmd, void *conf,
                                 const char *arg)
{
    diary_conf *c = (diary_conf *)conf;
    c->uri = arg;
    return NULL;
}

static const char *set_diary_theme(cmd_parms *cmd, void *conf,
                                   const char *arg)
{
    diary_conf *c = (diary_conf *)conf;
    c->theme = arg;
    return NULL;
}

static const char *set_diary_autolink(cmd_parms *cmd, void *conf, int flag)
{
    diary_conf *c = (diary_conf *)conf;
    c->autolink = flag;
    return NULL;
}

static const char *set_diary_github_flavoured(cmd_parms *cmd, void *conf, int flag)
{
   diary_conf *c = (diary_conf *)conf;
   c->github_flavoured = flag;
   return NULL;
}

static const char *set_diary_calendar(cmd_parms *cmd, void *conf, int flag)
{
   diary_conf *c = (diary_conf *)conf;
   c->calendar = flag;
   return NULL;
}

static const command_rec diary_cmds[] = {
    AP_INIT_TAKE1("DiaryPath", set_diary_path, NULL, OR_ALL,
                  "set DiaryPath"),
    AP_INIT_TAKE1("DiaryUri", set_diary_uri, NULL, OR_ALL,
                  "set DiaryUri"),
    AP_INIT_TAKE1("DiaryTitle", set_diary_title, NULL, OR_ALL,
                  "set DiaryTitle"),
    AP_INIT_TAKE1("DiaryTheme", set_diary_theme, NULL, OR_ALL,
                  "set DiaryTheme"),
    AP_INIT_FLAG("DiaryAutolink", set_diary_autolink,  NULL, OR_ALL,
                 "set autolink with On(default) or Off"),
    AP_INIT_FLAG("DiaryGithubFlavouredMarkdown", set_diary_github_flavoured,  NULL, OR_ALL,
                 "set use of Github-flavoured Markdown with On(default) or Off)"),
    AP_INIT_FLAG("DiaryCalendar", set_diary_calendar,  NULL, OR_ALL,
                 "show calendar with On(default) or Off"),
    {NULL}
};

/*
static int diary_post_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    return 0;
}
*/

static void diary_register_hooks(apr_pool_t *p)
{
    //ap_hook_post_config(diary_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(diary_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(diary_fixups, NULL, NULL, APR_HOOK_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA diary_module = {
    STANDARD20_MODULE_STUFF,
    diary_config,               /* create per-dir    config structures */
    NULL,                       /* merge  per-dir    config structures */
    NULL,                       /* create per-server config structures */
    NULL,                       /* merge  per-server config structures */
    diary_cmds,                 /* table of config file commands       */
    diary_register_hooks        /* register hooks                      */
};
